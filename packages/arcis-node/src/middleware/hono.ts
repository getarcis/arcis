/**
 * @module @arcis/node/hono
 *
 * Hono adapter for Arcis. Hono runs on Web Fetch primitives (Request /
 * Response / Headers) so the same Edge-native pipeline that powers the
 * SvelteKit / Astro / Nuxt / Next.js / Bun adapters drives this one.
 * That means it works in any runtime Hono targets: Cloudflare Workers,
 * Deno Deploy, Bun, AWS Lambda, Node, and so on.
 *
 * **Scope:** rate-limit + bot detection + security headers. The
 * Web Fetch shape means consuming the body stream in this adapter
 * would defeat the downstream handler. For XSS/SQL/SSTI/etc. body
 * payload blocking, call `sanitizeObject(await c.req.json())` from
 * `@arcis/node/sanitizers` inside your route handler.
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
import { createClientIpResolver, toHeaderGetter } from '../utils/client-ip';
import {
  adapterKey,
  buildAdapterLimiter,
  honoPeerAddress,
  mergeClientIpOptions,
  userClientIp,
  type FetchClientIpOptions,
} from './rate-limit-shared';

// ─── Hono duck-typed contracts ──────────────────────────────────────────────
// Mirrors Hono's `Context` and `MiddlewareHandler` shapes closely enough
// that real Hono types are assignable, without a runtime dep.

interface HonoContextLike {
  req: { raw: Request };
  res: Response;
  /** Runtime bindings: a Node `incoming`, a Bun server, Deno conn info, or Workers bindings. */
  env?: unknown;
}

export type HonoMiddleware = (
  c: HonoContextLike,
  next: () => Promise<void>,
) => Promise<Response | void>;

/**
 * Adapter options. Client IP resolution: `getClientIp` when it returns a
 * valid address; else the peer address Hono exposes (Node, Bun, Deno) with
 * the `trustedProxies` walk; else, without a peer, `clientIpHeader`, then
 * `cf-connecting-ip` on Cloudflare Workers or `x-real-ip` on Vercel; else
 * one shared `unknown` key.
 */
export interface ArcisHonoOptions extends FetchClientIpOptions {
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
    // Malformed request.url shouldn't crash the security-header pass.
  }
  applyPlanToHeaders(response.headers, policy, policy.plan({ isHttps, request: request, response }));
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
  const headerPolicy = headersCfg
    ? compileSecurityHeaders(typeof headersCfg === 'object' ? headersCfg : {}, {
        nonceUnsupportedBy: 'Hono',
      })
    : null;
  const rateLimitCfg = options.rateLimit ?? true;
  const botCfg = options.bot;

  const rateLimitOpts = typeof rateLimitCfg === 'object' ? rateLimitCfg : {};
  const limiter = rateLimitCfg ? buildAdapterLimiter(rateLimitOpts, 'arcisHono') : null;
  const resolver = createClientIpResolver(mergeClientIpOptions(options, rateLimitOpts));

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
      const ip =
        userClientIp(options.getClientIp, request) ??
        resolver.resolve(honoPeerAddress(c.env, request), toHeaderGetter(request.headers));
      const decision = limiter.check(adapterKey(ip, limiter, 'arcisHono'));
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
    if (headerPolicy && c.res) {
      applySecurityHeaders(c.res, headerPolicy, request);
    }
    return undefined;
  };
}

export default arcisHono;
