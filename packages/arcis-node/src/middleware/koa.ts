/**
 * @module @arcis/node/koa
 *
 * Koa adapter for Arcis. Returns a Koa middleware function suitable for
 * `app.use(...)`. Rate-limit + bot detection run BEFORE `next()` (the
 * handler); security headers are applied AFTER `next()` so they ride on
 * the buffered response that Koa flushes on its own.
 *
 * ```ts
 * import Koa from 'koa';
 * import { arcisKoa } from '@arcis/node/koa';
 *
 * const app = new Koa();
 * app.use(arcisKoa({
 *   rateLimit: { max: 100, windowMs: 60_000 },
 *   bot: true,
 * }));
 * app.use(async (ctx) => { ctx.body = { ok: true }; });
 * app.listen(3000);
 * ```
 *
 * No runtime dependency on `koa` — its types are duck-typed enough to
 * satisfy Koa's actual `Context` shape. Real `Context` is assignable
 * into `KoaContextLike` without imports.
 */

import type { Request as ExpressRequestLike } from 'express';
import { HEADERS, RATE_LIMIT } from '../core/constants';
import type {
  HeaderOptions,
  HstsOptions,
  RateLimitOptions,
} from '../core/types';
import {
  detectBot,
  type BotProtectionOptions,
  type BotDetectionResult,
} from './bot-detection';

// ─── Koa duck-typed contracts ───────────────────────────────────────────────
// Mirrors Koa's `Context` / `Request` / `Response` closely enough that real
// Koa types are assignable, without taking a runtime dep.

export interface KoaRequestLike {
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
  url?: string;
  method?: string;
  socket?: { remoteAddress?: string };
}

export interface KoaResponseLike {
  status: number;
  body: unknown;
  set(name: string, value: string): void;
}

export interface KoaContextLike {
  request: KoaRequestLike;
  response: KoaResponseLike;
  /**
   * Koa attaches IP at `ctx.ip` (delegating to `ctx.request.ip`). We read
   * either; whichever is set wins.
   */
  ip?: string;
  /** `ctx.set` shortcuts to `ctx.response.set` in real Koa. */
  set(name: string, value: string): void;
  /** Setting `ctx.status` shortcuts to `ctx.response.status`. */
  status: number;
  /** Setting `ctx.body` shortcuts to `ctx.response.body`. */
  body: unknown;
}

export type KoaNext = () => Promise<unknown>;
export type KoaMiddleware = (ctx: KoaContextLike, next: KoaNext) => Promise<void>;

// ─── Adapter options ────────────────────────────────────────────────────────

export interface ArcisKoaOptions {
  /** Security headers configuration. Default: enabled. Pass `false` to disable. */
  headers?: boolean | HeaderOptions;
  /** Rate limiter configuration. Default: 100 req/60s in-memory. Pass `false` to disable. */
  rateLimit?: boolean | RateLimitOptions;
  /**
   * Bot protection. Default: disabled (opt-in to avoid surprising behavior on
   * legitimate crawlers). Pass `true` for sensible defaults or an options
   * object for full control.
   */
  bot?: boolean | BotProtectionOptions;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

interface RateLimitEntry {
  count: number;
  resetTime: number;
}

interface RateLimitDecision {
  allowed: boolean;
  count: number;
  max: number;
  remaining: number;
  resetSeconds: number;
}

function buildLimiter(opts: RateLimitOptions): (key: string) => RateLimitDecision {
  const max = opts.max ?? RATE_LIMIT.DEFAULT_MAX_REQUESTS;
  const windowMs = opts.windowMs ?? RATE_LIMIT.DEFAULT_WINDOW_MS;
  // Object.create(null) avoids prototype-pollution risk if a key is "__proto__".
  const store = Object.create(null) as Record<string, RateLimitEntry>;
  return (key: string): RateLimitDecision => {
    const now = Date.now();
    let entry = store[key];
    if (!entry || entry.resetTime < now) {
      entry = { count: 0, resetTime: now + windowMs };
      store[key] = entry;
    }
    entry.count += 1;
    const remaining = Math.max(0, max - entry.count);
    const resetSeconds = Math.ceil((entry.resetTime - now) / 1000);
    return { allowed: entry.count <= max, count: entry.count, max, remaining, resetSeconds };
  };
}

function headerValue(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const v = headers[name];
  if (v === undefined) return undefined;
  if (Array.isArray(v)) return v[0];
  return v;
}

/**
 * Adapt the Koa-style headers object to the shape `detectBot()` reads off
 * an Express request. Only headers `detectBot` consults are forwarded.
 */
function botInputFor(
  headers: Record<string, string | string[] | undefined>,
): ExpressRequestLike {
  const h: Record<string, string | undefined> = {
    'user-agent': headerValue(headers, 'user-agent'),
    accept: headerValue(headers, 'accept'),
    'accept-language': headerValue(headers, 'accept-language'),
    'accept-encoding': headerValue(headers, 'accept-encoding'),
    connection: headerValue(headers, 'connection'),
  };
  return { headers: h } as unknown as ExpressRequestLike;
}

/**
 * Pull a stable client IP. Order: `ctx.ip` / `ctx.request.ip` (Koa
 * pre-resolves these from XFF when `app.proxy = true`) → X-Forwarded-For
 * (leftmost) → X-Real-IP → socket.remoteAddress → "unknown". When the
 * Koa user enables `app.proxy`, Koa already trusted XFF — we honor that.
 */
function clientIpOf(ctx: KoaContextLike): string {
  if (ctx.ip) return ctx.ip;
  if (ctx.request.ip) return ctx.request.ip;
  const headers = ctx.request.headers ?? {};
  const xff = headerValue(headers, 'x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  const xrip = headerValue(headers, 'x-real-ip');
  if (xrip) return xrip.trim();
  if (ctx.request.socket?.remoteAddress) return ctx.request.socket.remoteAddress;
  return 'unknown';
}

function applySecurityHeaders(
  ctx: KoaContextLike,
  options: HeaderOptions,
): void {
  const {
    contentSecurityPolicy = true,
    xssFilter = true,
    noSniff = true,
    frameOptions = HEADERS.FRAME_OPTIONS,
    hsts = true,
    referrerPolicy = HEADERS.REFERRER_POLICY,
    permissionsPolicy = HEADERS.PERMISSIONS_POLICY,
    cacheControl = true,
    crossOriginOpenerPolicy = 'same-origin',
    crossOriginResourcePolicy = 'same-origin',
    crossOriginEmbedderPolicy = 'require-corp',
    originAgentCluster = true,
    dnsPrefetchControl = true,
  } = options;

  if (contentSecurityPolicy) {
    ctx.set(
      'Content-Security-Policy',
      typeof contentSecurityPolicy === 'string' ? contentSecurityPolicy : HEADERS.DEFAULT_CSP,
    );
  }
  if (xssFilter) ctx.set('X-XSS-Protection', '0');
  if (noSniff) ctx.set('X-Content-Type-Options', HEADERS.CONTENT_TYPE_OPTIONS);
  if (frameOptions) ctx.set('X-Frame-Options', frameOptions);

  // HSTS only over HTTPS — sending it over HTTP can brick HTTP-only dev
  // servers. Trust X-Forwarded-Proto only when 'http' or 'https'. Koa's
  // `ctx.request.url` is a path-only string; without a way to read the
  // listening socket's TLS state from a duck-typed contract, fall back
  // to XFP. Production deployments behind a TLS-terminating proxy MUST
  // set X-Forwarded-Proto to receive HSTS — same contract as the Fastify
  // and Express adapters.
  const xfp = headerValue(ctx.request.headers ?? {}, 'x-forwarded-proto')
    ?.split(',')[0]
    ?.trim()
    ?.toLowerCase();
  const trustedXfp = xfp === 'https' || xfp === 'http' ? xfp : undefined;
  const isHttps = trustedXfp === 'https';

  if (hsts && isHttps) {
    const o: HstsOptions = typeof hsts === 'object' ? hsts : {};
    const maxAge = o.maxAge ?? HEADERS.HSTS_MAX_AGE;
    const includeSub = o.includeSubDomains !== false;
    const preload = o.preload === true;
    let v = `max-age=${maxAge}`;
    if (includeSub) v += '; includeSubDomains';
    if (preload) v += '; preload';
    ctx.set('Strict-Transport-Security', v);
  }

  if (referrerPolicy) ctx.set('Referrer-Policy', referrerPolicy);
  if (permissionsPolicy) ctx.set('Permissions-Policy', permissionsPolicy);
  if (crossOriginOpenerPolicy) ctx.set('Cross-Origin-Opener-Policy', crossOriginOpenerPolicy);
  if (crossOriginResourcePolicy) ctx.set('Cross-Origin-Resource-Policy', crossOriginResourcePolicy);
  if (crossOriginEmbedderPolicy) ctx.set('Cross-Origin-Embedder-Policy', crossOriginEmbedderPolicy);
  if (originAgentCluster) ctx.set('Origin-Agent-Cluster', '?1');
  if (dnsPrefetchControl) ctx.set('X-DNS-Prefetch-Control', 'off');
  ctx.set('X-Permitted-Cross-Domain-Policies', 'none');

  if (cacheControl) {
    ctx.set(
      'Cache-Control',
      typeof cacheControl === 'string' ? cacheControl : HEADERS.CACHE_CONTROL,
    );
    ctx.set('Pragma', 'no-cache');
    ctx.set('Expires', '0');
  }
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Build a Koa middleware that applies Arcis protections on each request:
 * rate-limit (returns 429 if exceeded), bot detection (returns
 * `botStatusCode` if denied), then `await next()`, then security headers
 * on the buffered response. Order matches the SvelteKit / Fastify /
 * Next.js adapters so cross-framework behavior is consistent.
 *
 * Setting `ctx.status` and `ctx.body` before returning is Koa's idiomatic
 * way to short-circuit a response — we don't call `next()` on the deny
 * path so downstream middleware doesn't run.
 */
export function arcisKoa(options: ArcisKoaOptions = {}): KoaMiddleware {
  const headersCfg = options.headers ?? true;
  const rateLimitCfg = options.rateLimit ?? true;
  const botCfg = options.bot;

  const limiter = rateLimitCfg
    ? buildLimiter(typeof rateLimitCfg === 'object' ? rateLimitCfg : {})
    : null;

  const botEnabled = !!botCfg;
  const botOpts: BotProtectionOptions =
    typeof botCfg === 'object' ? botCfg : {};
  const botAllow = new Set(botOpts.allow ?? ['SEARCH_ENGINE', 'SOCIAL', 'MONITORING']);
  const botDeny = new Set(botOpts.deny ?? ['AUTOMATED']);
  const botDefault = botOpts.defaultAction ?? 'allow';
  const botStatusCode = botOpts.statusCode ?? 403;
  const botMessage = botOpts.message ?? 'Access denied.';

  return async (ctx, next) => {
    // 1. Rate limit
    if (limiter) {
      const key = clientIpOf(ctx);
      const decision = limiter(key);
      ctx.set('X-RateLimit-Limit', decision.max.toString());
      ctx.set(
        'X-RateLimit-Remaining',
        decision.allowed ? decision.remaining.toString() : '0',
      );
      ctx.set('X-RateLimit-Reset', decision.resetSeconds.toString());
      if (!decision.allowed) {
        ctx.set('Retry-After', decision.resetSeconds.toString());
        ctx.status = 429;
        ctx.body = {
          error: 'Too many requests, please try again later.',
          retryAfter: decision.resetSeconds,
        };
        return; // do NOT call next() — short-circuit
      }
    }

    // 2. Bot detection
    if (botEnabled) {
      const result: BotDetectionResult = detectBot(botInputFor(ctx.request.headers ?? {}));
      if (result.isBot) {
        const denied =
          botDeny.has(result.category) ||
          (!botAllow.has(result.category) && botDefault === 'deny');
        if (denied) {
          ctx.status = botStatusCode;
          ctx.body = { error: botMessage };
          return;
        }
      }
    }

    // 3. Run downstream
    await next();

    // 4. Security headers — on the way back out, before Koa flushes.
    if (headersCfg) {
      applySecurityHeaders(
        ctx,
        typeof headersCfg === 'object' ? headersCfg : {},
      );
    }
  };
}

export default arcisKoa;
