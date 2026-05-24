/**
 * @module @arcis/node/bun
 *
 * Bun + Hono adapter for Arcis. Two entry points.
 *
 * **Scope:** rate-limit + bot detection + security headers. Bun's
 * Web Fetch runtime cannot easily inspect request bodies inside this
 * adapter (consuming the stream defeats the downstream handler). For
 * XSS/SQL/SSTI/etc. body-payload blocking, call
 * `sanitizeObject(await req.json())` from `@arcis/node/sanitizers`
 * inside your route handler.
 *
 * **1. `Bun.serve` fetch wrapper:**
 *
 * ```ts
 * import { arcisBun } from '@arcis/node/bun';
 *
 * Bun.serve({
 *   fetch: arcisBun({ rateLimit: { max: 100 }, bot: true }, async (req, server) => {
 *     return new Response('Hello');
 *   }),
 * });
 * ```
 *
 * **2. Hono middleware (works on Bun / Workers / Deno / Node):**
 *
 * ```ts
 * import { Hono } from 'hono';
 * import { arcisHono } from '@arcis/node/bun';
 *
 * const app = new Hono();
 * app.use(arcisHono({ rateLimit: { max: 100 } }));
 * app.get('/', (c) => c.text('Hello'));
 * ```
 *
 * No runtime dependency on `bun-types` or `hono` — both shapes are
 * duck-typed.
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

// ─── Bun + Hono duck-typed contracts ────────────────────────────────────────

export interface BunServerLike {
  requestIP(req: Request): { address: string; family?: string; port?: number } | null;
}

export type BunFetchHandler = (
  req: Request,
  server?: BunServerLike,
) => Promise<Response> | Response;

interface HonoRequestLike {
  raw: Request;
  url: string;
  header(name: string): string | undefined;
}

export interface HonoContextLike {
  req: HonoRequestLike;
  res: Response;
  json(object: unknown, status?: number): Response;
}

export type HonoNext = () => Promise<void>;
export type HonoMiddlewareHandler = (
  c: HonoContextLike,
  next: HonoNext,
) => Promise<Response | void>;

// ─── Adapter options ────────────────────────────────────────────────────────

export interface ArcisBunOptions {
  /** Security headers configuration. Default: enabled. Pass `false` to disable. */
  headers?: boolean | HeaderOptions;
  /** Rate limiter configuration. Default: 100 req/60s in-memory. Pass `false` to disable. */
  rateLimit?: boolean | RateLimitOptions;
  /** Bot protection. Default: disabled (opt-in). */
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
  return (key) => {
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

function applySecurityHeaders(
  response: Response,
  options: HeaderOptions,
  url: URL,
  reqHeaders: Headers,
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

  const xfp = reqHeaders
    .get('x-forwarded-proto')
    ?.split(',')[0]
    ?.trim()
    ?.toLowerCase();
  const trustedXfp = xfp === 'https' || xfp === 'http' ? xfp : undefined;
  const isHttps = url.protocol === 'https:' || trustedXfp === 'https';

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

interface BotConfig {
  enabled: boolean;
  allow: Set<string>;
  deny: Set<string>;
  defaultAction: 'allow' | 'deny';
  statusCode: number;
  message: string;
}

function buildBotConfig(botCfg: ArcisBunOptions['bot']): BotConfig {
  const opts: BotProtectionOptions = typeof botCfg === 'object' ? botCfg : {};
  return {
    enabled: !!botCfg,
    allow: new Set(opts.allow ?? ['SEARCH_ENGINE', 'SOCIAL', 'MONITORING']),
    deny: new Set(opts.deny ?? ['AUTOMATED']),
    defaultAction: opts.defaultAction ?? 'allow',
    statusCode: opts.statusCode ?? 403,
    message: opts.message ?? 'Access denied.',
  };
}

function clientIpFromHeaders(headers: Headers, fallback: string): string {
  const xff = headers.get('x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  return fallback;
}

function rateLimitedResponse(decision: RateLimitDecision): Response {
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

function botBlockedResponse(cfg: BotConfig): Response {
  return new Response(JSON.stringify({ error: cfg.message }), {
    status: cfg.statusCode,
    headers: { 'Content-Type': 'application/json' },
  });
}

function botBlocked(result: BotDetectionResult, cfg: BotConfig): boolean {
  if (!result.isBot) return false;
  if (cfg.deny.has(result.category)) return true;
  if (!cfg.allow.has(result.category) && cfg.defaultAction === 'deny') return true;
  return false;
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Wrap a `Bun.serve` fetch handler with Arcis protections. The wrapped handler
 * returns 429/403 directly when rate-limited or bot-blocked; otherwise it
 * delegates to the user handler and applies security headers to the result.
 */
export function arcisBun(
  options: ArcisBunOptions,
  handler: BunFetchHandler,
): BunFetchHandler {
  const headersCfg = options.headers ?? true;
  const rateLimitCfg = options.rateLimit ?? true;
  const limiter = rateLimitCfg
    ? buildLimiter(typeof rateLimitCfg === 'object' ? rateLimitCfg : {})
    : null;
  const botCfg = buildBotConfig(options.bot);

  return async (req, server) => {
    const url = new URL(req.url);
    const fallbackIp = server?.requestIP(req)?.address ?? 'unknown';
    const ip = clientIpFromHeaders(req.headers, fallbackIp);

    if (limiter) {
      const decision = limiter(ip);
      if (!decision.allowed) return rateLimitedResponse(decision);
    }

    if (botCfg.enabled) {
      const result = detectBot(botInputFor(req.headers));
      if (botBlocked(result, botCfg)) return botBlockedResponse(botCfg);
    }

    const response = await handler(req, server);

    if (headersCfg) {
      applySecurityHeaders(
        response,
        typeof headersCfg === 'object' ? headersCfg : {},
        url,
        req.headers,
      );
    }

    return response;
  };
}

/**
 * Hono middleware factory. Apply via `app.use(arcisHono({...}))`. Returns 429
 * or 403 directly when rate-limited or bot-blocked; otherwise calls `next()`
 * and mutates `c.res.headers` with security defaults afterwards.
 */
export function arcisHono(options: ArcisBunOptions = {}): HonoMiddlewareHandler {
  const headersCfg = options.headers ?? true;
  const rateLimitCfg = options.rateLimit ?? true;
  const limiter = rateLimitCfg
    ? buildLimiter(typeof rateLimitCfg === 'object' ? rateLimitCfg : {})
    : null;
  const botCfg = buildBotConfig(options.bot);

  return async (c, next) => {
    const url = new URL(c.req.url);
    const ip = clientIpFromHeaders(c.req.raw.headers, 'unknown');

    if (limiter) {
      const decision = limiter(ip);
      if (!decision.allowed) return rateLimitedResponse(decision);
    }

    if (botCfg.enabled) {
      const result = detectBot(botInputFor(c.req.raw.headers));
      if (botBlocked(result, botCfg)) return botBlockedResponse(botCfg);
    }

    await next();

    if (headersCfg) {
      applySecurityHeaders(
        c.res,
        typeof headersCfg === 'object' ? headersCfg : {},
        url,
        c.req.raw.headers,
      );
    }
    return;
  };
}

export default arcisBun;
