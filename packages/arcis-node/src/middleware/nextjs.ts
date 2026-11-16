/**
 * @module @arcis/node/nextjs
 *
 * Next.js adapter for Arcis. Two entry points covering the modern Next.js
 * stack (Edge Middleware + App Router route handlers).
 *
 * **Scope:** rate-limit + bot detection + security headers. The Edge
 * runtime cannot easily inspect request bodies (they are streams that
 * can only be read once, and consuming them in middleware defeats the
 * route handler). For XSS/SQL/SSTI/etc. body-payload blocking, call
 * `sanitizeObject(await request.json())` from `@arcis/node/sanitizers`
 * inside your route handler, or wrap individual handlers with
 * `arcisProtect` (also exported from this module).
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
import type {
  HeaderOptions,
  RateLimitOptions,
} from '../core/types';
import {
  detectBot,
  type BotProtectionOptions,
  type BotDetectionResult,
} from './bot-detection';
import { applyPlanToHeaders, compileSecurityHeaders, parseForwardedProto, type CompiledSecurityHeaders } from './security-headers';
import { createClientIpResolver, toHeaderGetter, type ClientIpResolver } from '../utils/client-ip';
import {
  adapterKey,
  buildAdapterLimiter,
  mergeClientIpOptions,
  userClientIp,
  type AdapterRateLimiter,
  type FetchClientIpOptions,
} from './rate-limit-shared';

// ─── Adapter options ────────────────────────────────────────────────────────

/**
 * Adapter options. Next.js middleware has no peer address, so the client IP
 * comes from `getClientIp` when it returns a valid address; else
 * `clientIpHeader`; else `x-real-ip` (then the right-most X-Forwarded-For
 * entry) on Vercel (`VERCEL=1`) or `cf-connecting-ip` on Cloudflare Workers;
 * else every request shares one `unknown` key. Self-hosted deployments
 * should set `clientIpHeader` to the header their proxy overwrites.
 */
export interface ArcisNextOptions extends FetchClientIpOptions {
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

function applySecurityHeaders(
  response: Response,
  policy: CompiledSecurityHeaders,
  request: Request,
): void {
  let isHttps = parseForwardedProto(request.headers.get('x-forwarded-proto')) === 'https';
  try {
    isHttps = isHttps || new URL(request.url).protocol === 'https:';
  } catch {
    // Malformed request.url: rely on X-Forwarded-Proto alone.
  }
  applyPlanToHeaders(response.headers, policy, policy.plan({ isHttps, request: request, response }));
}

// ─── Pipeline ───────────────────────────────────────────────────────────────

/**
 * Resolved option bundle plus the materialised limiter. Built once per
 * factory call so each invocation of the returned function is allocation-
 * light.
 */
interface ResolvedPipeline {
  headerPolicy: CompiledSecurityHeaders | null;
  limiter: AdapterRateLimiter | null;
  resolver: ClientIpResolver;
  getClientIp: FetchClientIpOptions['getClientIp'];
  botEnabled: boolean;
  botAllow: Set<string>;
  botDeny: Set<string>;
  botDefault: 'allow' | 'deny';
  botStatusCode: number;
  botMessage: string;
}

function resolvePipeline(options: ArcisNextOptions): ResolvedPipeline {
  const headersCfg = options.headers ?? true;
  const headerPolicy = headersCfg
    ? compileSecurityHeaders(typeof headersCfg === 'object' ? headersCfg : {}, {
        nonceUnsupportedBy: 'Next.js',
      })
    : null;
  const rateLimitCfg = options.rateLimit ?? true;
  const botCfg = options.bot;

  const rateLimitOpts = typeof rateLimitCfg === 'object' ? rateLimitCfg : {};
  const limiter = rateLimitCfg ? buildAdapterLimiter(rateLimitOpts, 'arcisNext') : null;
  const resolver = createClientIpResolver(mergeClientIpOptions(options, rateLimitOpts));

  const botEnabled = !!botCfg;
  const botOpts: BotProtectionOptions = typeof botCfg === 'object' ? botCfg : {};
  return {
    headerPolicy,
    limiter,
    resolver,
    getClientIp: options.getClientIp,
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
    const ip =
      userClientIp(p.getClientIp, request) ?? p.resolver.fromEdge(toHeaderGetter(request.headers));
    const decision = p.limiter.check(adapterKey(ip, p.limiter, 'arcisNext'));
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
    if (pipeline.headerPolicy) {
      applySecurityHeaders(
        response,
        pipeline.headerPolicy,
        request,
      );
    }
    return response;
  };
}

export default arcisMiddleware;
