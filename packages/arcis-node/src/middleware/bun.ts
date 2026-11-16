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
  honoPeerAddress,
  mergeClientIpOptions,
  userClientIp,
  type AdapterRateLimitDecision,
  type AdapterRateLimiter,
  type FetchClientIpOptions,
} from './rate-limit-shared';

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
  /** Hono on Bun passes the Bun server here; it supplies the peer address. */
  env?: unknown;
  json(object: unknown, status?: number): Response;
}

export type HonoNext = () => Promise<void>;
export type HonoMiddlewareHandler = (
  c: HonoContextLike,
  next: HonoNext,
) => Promise<Response | void>;

// ─── Adapter options ────────────────────────────────────────────────────────

/**
 * Adapter options. Client IP resolution: `getClientIp` when it returns a
 * valid address; else the peer address (`server.requestIP()`) with the
 * `trustedProxies` walk; else, without a peer, `clientIpHeader` or the
 * platform header; else one shared `unknown` key.
 */
export interface ArcisBunOptions extends FetchClientIpOptions {
  /** Security headers configuration. Default: enabled. Pass `false` to disable. */
  headers?: boolean | HeaderOptions;
  /** Rate limiter configuration. Default: 100 req/60s in-memory. Pass `false` to disable. */
  rateLimit?: boolean | RateLimitOptions;
  /** Bot protection. Default: disabled (opt-in). */
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
  url: URL,
  request: Request,
): void {
  const isHttps =
    url.protocol === 'https:' ||
    parseForwardedProto(request.headers.get('x-forwarded-proto')) === 'https';
  applyPlanToHeaders(response.headers, policy, policy.plan({ isHttps, request: request, response }));
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

interface RateLimitSetup {
  limiter: AdapterRateLimiter | null;
  resolver: ClientIpResolver;
}

function buildRateLimit(options: ArcisBunOptions, owner: string): RateLimitSetup {
  const rateLimitCfg = options.rateLimit ?? true;
  const rateLimitOpts = typeof rateLimitCfg === 'object' ? rateLimitCfg : {};
  return {
    limiter: rateLimitCfg ? buildAdapterLimiter(rateLimitOpts, owner) : null,
    resolver: createClientIpResolver(mergeClientIpOptions(options, rateLimitOpts)),
  };
}

function rateLimitedResponse(decision: AdapterRateLimitDecision): Response {
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
  const headerPolicy = headersCfg
    ? compileSecurityHeaders(typeof headersCfg === 'object' ? headersCfg : {}, {
        nonceUnsupportedBy: 'Bun',
      })
    : null;
  const { limiter, resolver } = buildRateLimit(options, 'arcisBun');
  const botCfg = buildBotConfig(options.bot);

  return async (req, server) => {
    const url = new URL(req.url);

    if (limiter) {
      const ip =
        userClientIp(options.getClientIp, req) ??
        resolver.resolve(server?.requestIP(req)?.address, toHeaderGetter(req.headers));
      const decision = limiter.check(adapterKey(ip, limiter, 'arcisBun'));
      if (!decision.allowed) return rateLimitedResponse(decision);
    }

    if (botCfg.enabled) {
      const result = detectBot(botInputFor(req.headers));
      if (botBlocked(result, botCfg)) return botBlockedResponse(botCfg);
    }

    const response = await handler(req, server);

    if (headerPolicy) {
      applySecurityHeaders(
        response,
        headerPolicy,
        url,
        req,
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
  const headerPolicy = headersCfg
    ? compileSecurityHeaders(typeof headersCfg === 'object' ? headersCfg : {}, {
        nonceUnsupportedBy: 'Bun',
      })
    : null;
  const { limiter, resolver } = buildRateLimit(options, 'arcisHono');
  const botCfg = buildBotConfig(options.bot);

  return async (c, next) => {
    const url = new URL(c.req.url);

    if (limiter) {
      const request = c.req.raw;
      const ip =
        userClientIp(options.getClientIp, request) ??
        resolver.resolve(honoPeerAddress(c.env, request), toHeaderGetter(request.headers));
      const decision = limiter.check(adapterKey(ip, limiter, 'arcisHono'));
      if (!decision.allowed) return rateLimitedResponse(decision);
    }

    if (botCfg.enabled) {
      const result = detectBot(botInputFor(c.req.raw.headers));
      if (botBlocked(result, botCfg)) return botBlockedResponse(botCfg);
    }

    await next();

    if (headerPolicy) {
      applySecurityHeaders(
        c.res,
        headerPolicy,
        url,
        c.req.raw,
      );
    }
    return;
  };
}

export default arcisBun;
