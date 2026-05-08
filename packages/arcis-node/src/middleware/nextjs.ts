/**
 * @module @arcis/node/nextjs
 *
 * Next.js adapter for Arcis. Two entry points covering the modern Next.js
 * stack (Edge Middleware + App Router route handlers):
 *
 * **1. Edge Middleware (`middleware.ts` at the project root):**
 *
 * ```ts
 * import { arcisMiddleware } from '@arcis/node/nextjs';
 * import { NextResponse } from 'next/server';
 *
 * const arcis = arcisMiddleware({
 *   rateLimit: { max: 100, windowMs: 60_000 },
 *   bot: true,
 * });
 *
 * export default async function middleware(request: Request) {
 *   const blocked = await arcis(request);
 *   if (blocked) return blocked;
 *   return NextResponse.next();
 * }
 * ```
 *
 * The returned function inspects the request and returns either:
 *   - a `Response` (rate-limited 429 / bot-blocked 403) to short-circuit, or
 *   - `undefined` to let the request proceed.
 *
 * The caller decides what "proceed" means — `NextResponse.next()` for Edge
 * Middleware, or a re-thrown handler call for custom plumbing. Keeping the
 * allow-path explicit avoids importing `next/server` from the adapter.
 *
 * **2. App Router route handlers (`app/api/.../route.ts`):**
 *
 * ```ts
 * import { arcisProtect } from '@arcis/node/nextjs';
 *
 * export const POST = arcisProtect(
 *   async (request: Request) => Response.json({ ok: true }),
 *   { rateLimit: { max: 100 }, bot: true },
 * );
 * ```
 *
 * The wrapper runs the same allow / deny pipeline as `arcisMiddleware`,
 * then on the allow path calls the handler, mutates the resulting
 * Response's headers with security defaults, and returns it.
 *
 * Pages-router API routes (`pages/api/...`) use Node-style req/res rather
 * than the Web Fetch shape; for those, drop the standard Express adapter
 * (`arcis()` from the package root) into `app.use(...)` of a custom server,
 * or migrate to the App Router for first-party support.
 *
 * No runtime dependency on `next` — the adapter speaks Web Fetch
 * `Request`/`Response` directly. NextRequest extends Request and
 * NextResponse extends Response, so both are assignable into / out of this
 * surface without imports.
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

// ─── Adapter options ────────────────────────────────────────────────────────

export interface ArcisNextOptions {
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

/**
 * Adapt the Headers object to the shape `detectBot()` reads off an
 * Express request. Only headers that `detectBot` consults are forwarded —
 * keeps the surface tiny.
 */
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
 * Pull a stable client IP from a Web Fetch Request. Honors trust order:
 * X-Forwarded-For (leftmost trusted entry) → X-Real-IP → CF-Connecting-IP
 * (Cloudflare on Vercel) → "unknown".
 *
 * Vercel + Cloudflare set `X-Forwarded-For`; Next.js Edge Middleware sees
 * those as request headers but does NOT expose `request.ip` consistently
 * across deployment targets (it's `undefined` on self-hosted Node, set
 * on Vercel Edge). Reading the header set is the portable approach.
 *
 * Falls back to the literal string "unknown" so the rate-limit key is
 * still deterministic; an unknown-IP request still rate-limits against
 * other unknown-IP requests, which is the behavior tests assume.
 */
function clientIpOf(request: Request): string {
  const xff = request.headers.get('x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  const xrip = request.headers.get('x-real-ip');
  if (xrip) return xrip.trim();
  const cf = request.headers.get('cf-connecting-ip');
  if (cf) return cf.trim();
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
  // 'https'; reject malformed values to avoid header-injection trickery.
  const xfp = request.headers
    .get('x-forwarded-proto')
    ?.split(',')[0]
    ?.trim()
    ?.toLowerCase();
  const trustedXfp = xfp === 'https' || xfp === 'http' ? xfp : undefined;
  let isHttps = false;
  try {
    isHttps = new URL(request.url).protocol === 'https:';
  } catch {
    // Malformed request.url — treat as non-https; HSTS won't be set.
  }
  if (!isHttps && trustedXfp === 'https') isHttps = true;

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

// ─── Pipeline ───────────────────────────────────────────────────────────────

/**
 * Resolved option bundle plus the materialised limiter. Built once per
 * factory call so each invocation of the returned function is allocation-
 * light.
 */
interface ResolvedPipeline {
  headersCfg: boolean | HeaderOptions;
  limiter: ((key: string) => RateLimitDecision) | null;
  botEnabled: boolean;
  botAllow: Set<string>;
  botDeny: Set<string>;
  botDefault: 'allow' | 'deny';
  botStatusCode: number;
  botMessage: string;
}

function resolvePipeline(options: ArcisNextOptions): ResolvedPipeline {
  const headersCfg = options.headers ?? true;
  const rateLimitCfg = options.rateLimit ?? true;
  const botCfg = options.bot;

  const limiter = rateLimitCfg
    ? buildLimiter(typeof rateLimitCfg === 'object' ? rateLimitCfg : {})
    : null;

  const botEnabled = !!botCfg;
  const botOpts: BotProtectionOptions = typeof botCfg === 'object' ? botCfg : {};
  return {
    headersCfg,
    limiter,
    botEnabled,
    botAllow: new Set(botOpts.allow ?? ['SEARCH_ENGINE', 'SOCIAL', 'MONITORING']),
    botDeny: new Set(botOpts.deny ?? ['AUTOMATED']),
    botDefault: botOpts.defaultAction ?? 'allow',
    botStatusCode: botOpts.statusCode ?? 403,
    botMessage: botOpts.message ?? 'Access denied.',
  };
}

/**
 * Run the rate-limit + bot pipeline against `request`. Returns a Response
 * to short-circuit (429 / 403) or `null` to let the caller continue.
 *
 * Pulled out of `arcisMiddleware` so `arcisProtect` can reuse the same
 * decision logic without rebuilding the pipeline per invocation.
 */
function checkRequest(request: Request, p: ResolvedPipeline): Response | null {
  if (p.limiter) {
    const key = clientIpOf(request);
    const decision = p.limiter(key);
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

  if (p.botEnabled) {
    const result: BotDetectionResult = detectBot(botInputFor(request.headers));
    if (result.isBot) {
      const denied =
        p.botDeny.has(result.category) ||
        (!p.botAllow.has(result.category) && p.botDefault === 'deny');
      if (denied) {
        return new Response(
          JSON.stringify({ error: p.botMessage }),
          { status: p.botStatusCode, headers: { 'Content-Type': 'application/json' } },
        );
      }
    }
  }

  return null;
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Build a Next.js Edge Middleware factory. The returned function runs the
 * Arcis allow / deny pipeline against the request and returns a `Response`
 * to short-circuit OR `undefined` to indicate "let the request proceed."
 *
 * The caller is responsible for the proceed-path (typically
 * `NextResponse.next()` from `next/server`). This split keeps the adapter
 * dependency-free of `next/server` while preserving clean Edge Middleware
 * ergonomics.
 *
 * Security headers are NOT applied here — Edge Middleware can't easily
 * mutate the response body's headers without consuming the body. For
 * security-headers-on-response, use `arcisProtect` on the route handler.
 */
export function arcisMiddleware(
  options: ArcisNextOptions = {},
): (request: Request) => Promise<Response | undefined> {
  const pipeline = resolvePipeline(options);
  return async (request: Request) => {
    const blocked = checkRequest(request, pipeline);
    return blocked ?? undefined;
  };
}

/**
 * Wrap an App Router route handler with the Arcis pipeline. Runs rate-limit
 * + bot checks BEFORE the handler, then security headers on the response
 * AFTER. The `...args` spread preserves the second-arg shape route handlers
 * receive, e.g. `(request, { params })` for dynamic routes.
 *
 * ```ts
 * export const GET = arcisProtect(
 *   async (request, { params }) => Response.json({ id: params.id }),
 *   { rateLimit: { max: 50 } },
 * );
 * ```
 */
export function arcisProtect<TArgs extends unknown[]>(
  handler: (request: Request, ...args: TArgs) => Promise<Response> | Response,
  options: ArcisNextOptions = {},
): (request: Request, ...args: TArgs) => Promise<Response> {
  const pipeline = resolvePipeline(options);
  return async (request: Request, ...args: TArgs) => {
    const blocked = checkRequest(request, pipeline);
    if (blocked) return blocked;
    const response = await handler(request, ...args);
    if (pipeline.headersCfg) {
      applySecurityHeaders(
        response,
        typeof pipeline.headersCfg === 'object' ? pipeline.headersCfg : {},
        request,
      );
    }
    return response;
  };
}

export default arcisMiddleware;
