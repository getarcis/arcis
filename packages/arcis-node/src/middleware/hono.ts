/**
 * @module @arcis/node/hono
 *
 * Hono adapter for Arcis. Hono runs on Web Fetch primitives (Request /
 * Response / Headers) so the same Edge-native pipeline that powers the
 * SvelteKit / Astro / Nuxt / Next.js / Bun adapters drives this one.
 * That means it works in any runtime Hono targets: Cloudflare Workers,
 * Deno Deploy, Bun, AWS Lambda, Node, and so on.
 *
 * Quick start:
 *
 * ```ts
 * import { Hono } from 'hono';
 * import { arcisHono } from '@arcis/node/hono';
 *
 * const app = new Hono();
 * app.use('*', arcisHono({ rateLimit: { max: 100 }, bot: true }));
 * app.get('/', (c) => c.text('hello'));
 * ```
 *
 * No runtime dependency on `hono` — its types are imported only at
 * compile time. The adapter ships in every Arcis install regardless of
 * whether the consumer uses Hono.
 *
 * For users running Hono on top of Bun, the dedicated `@arcis/node/bun`
 * adapter ships with a tighter Bun integration; this adapter is for
 * everyone else (Workers, Deno, Lambda, plain Node + Hono).
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

// ─── Hono duck-typed contracts ──────────────────────────────────────────────
// Mirrors Hono's `Context` and `MiddlewareHandler` shapes closely enough
// that real Hono types are assignable, without a runtime dep.

interface HonoContextLike {
  req: { raw: Request };
  res: Response;
  env?: Record<string, unknown>;
}

export type HonoMiddleware = (
  c: HonoContextLike,
  next: () => Promise<void>,
) => Promise<Response | void>;

export interface ArcisHonoOptions {
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

function botInputFor(headers: Headers): ExpressRequestLike {
  const h: Record<string, string | undefined> = {
    'user-agent': headers.get('user-agent') ?? undefined,
    accept: headers.get('accept') ?? undefined,
    'accept-language': headers.get('accept-language') ?? undefined,
    'accept-encoding': headers.get('accept-encoding') ?? undefined,
    connection: headers.get('connection') ?? undefined,
  };
  return { headers: h } as unknown as ExpressRequestLike;
}

/**
 * Extract a client IP from the request. Falls back to "unknown" when
 * none of XFF / CF-Connecting-IP / Forwarded / X-Real-IP are present.
 * The fallback is intentionally NOT a per-request unique value —
 * unknown traffic should share a bucket so a misconfigured edge can't
 * bypass rate limiting by stripping headers.
 */
function clientIpOf(headers: Headers): string {
  const cf = headers.get('cf-connecting-ip');
  if (cf) return cf.trim();
  const xff = headers.get('x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  const real = headers.get('x-real-ip');
  if (real) return real.trim();
  return 'unknown';
}

function applySecurityHeaders(
  response: Response,
  options: HeaderOptions,
  request: Request,
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
  const h = response.headers;

  if (contentSecurityPolicy) {
    h.set(
      'Content-Security-Policy',
      typeof contentSecurityPolicy === 'string' ? contentSecurityPolicy : HEADERS.DEFAULT_CSP,
    );
  }
  if (xssFilter) h.set('X-XSS-Protection', '0');
  if (noSniff) h.set('X-Content-Type-Options', HEADERS.CONTENT_TYPE_OPTIONS);
  if (frameOptions) h.set('X-Frame-Options', frameOptions);

  // HSTS only over HTTPS — sending it over HTTP can brick HTTP-only dev
  // servers. Trust X-Forwarded-Proto only when it's exactly 'http' or
  // 'https' (anything else is suspect proxy garbage).
  const xfp = request.headers
    .get('x-forwarded-proto')
    ?.split(',')[0]
    ?.trim()
    ?.toLowerCase();
  const trustedXfp = xfp === 'https' || xfp === 'http' ? xfp : undefined;
  let isHttps = trustedXfp === 'https';
  try {
    isHttps = isHttps || new URL(request.url).protocol === 'https:';
  } catch {
    // Malformed request.url shouldn't crash the security-header pass.
  }

  if (hsts && isHttps) {
    const o: HstsOptions = typeof hsts === 'object' ? hsts : {};
    const maxAge = o.maxAge ?? HEADERS.HSTS_MAX_AGE;
    const includeSub = o.includeSubDomains !== false;
    const preload = o.preload === true;
    let v = `max-age=${maxAge}`;
    if (includeSub) v += '; includeSubDomains';
    if (preload) v += '; preload';
    h.set('Strict-Transport-Security', v);
  }

  if (referrerPolicy) h.set('Referrer-Policy', referrerPolicy);
  if (permissionsPolicy) h.set('Permissions-Policy', permissionsPolicy);
  if (crossOriginOpenerPolicy) h.set('Cross-Origin-Opener-Policy', crossOriginOpenerPolicy);
  if (crossOriginResourcePolicy) h.set('Cross-Origin-Resource-Policy', crossOriginResourcePolicy);
  if (crossOriginEmbedderPolicy) h.set('Cross-Origin-Embedder-Policy', crossOriginEmbedderPolicy);
  if (originAgentCluster) h.set('Origin-Agent-Cluster', '?1');
  if (dnsPrefetchControl) h.set('X-DNS-Prefetch-Control', 'off');
  h.set('X-Permitted-Cross-Domain-Policies', 'none');

  if (cacheControl) {
    h.set(
      'Cache-Control',
      typeof cacheControl === 'string' ? cacheControl : HEADERS.CACHE_CONTROL,
    );
    h.set('Pragma', 'no-cache');
    h.set('Expires', '0');
  }

  h.delete('X-Powered-By');
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Build a Hono middleware handler that applies Arcis protections in
 * this order: rate limit (returns 429 if exceeded), bot detection
 * (returns 403 if the bot is in the deny list), runs `next()`, then
 * mutates the resulting `c.res` headers with security defaults.
 *
 * Hono's `c.res` is a regular `Response` whose `headers` are mutable
 * mid-request, so the security-header pass is in-place — no
 * Response-rebuild needed.
 */
export function arcisHono(options: ArcisHonoOptions = {}): HonoMiddleware {
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

  return async (c, next) => {
    const request = c.req.raw;

    // 1. Rate limit
    if (limiter) {
      const key = clientIpOf(request.headers);
      const decision = limiter(key);
      if (!decision.allowed) {
        return new Response(
          JSON.stringify({
            error: 'Too many requests, please try again later.',
            retryAfter: decision.resetSeconds,
          }),
          {
            status: 429,
            headers: {
              'Content-Type': 'application/json',
              'X-RateLimit-Limit': decision.max.toString(),
              'X-RateLimit-Remaining': '0',
              'X-RateLimit-Reset': decision.resetSeconds.toString(),
              'Retry-After': decision.resetSeconds.toString(),
            },
          },
        );
      }
    }

    // 2. Bot detection
    if (botEnabled) {
      const result: BotDetectionResult = detectBot(botInputFor(request.headers));
      if (result.isBot) {
        const denied =
          botDeny.has(result.category) ||
          (!botAllow.has(result.category) && botDefault === 'deny');
        if (denied) {
          return new Response(
            JSON.stringify({ error: botMessage }),
            { status: botStatusCode, headers: { 'Content-Type': 'application/json' } },
          );
        }
      }
    }

    // 3. Hand off to downstream
    await next();

    // 4. Apply security headers in-place on c.res. Hono guarantees c.res
    //    is set by the time the chain resumes.
    if (headersCfg && c.res) {
      applySecurityHeaders(c.res, typeof headersCfg === 'object' ? headersCfg : {}, request);
    }
    return undefined;
  };
}

export default arcisHono;
