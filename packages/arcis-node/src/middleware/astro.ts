/**
 * @module @arcis/node/astro
 *
 * Astro adapter for Arcis. Drop into `src/middleware.ts`.
 *
 * **Scope:** rate-limit + bot detection + security headers. For
 * XSS/SQL/SSTI/etc. body-payload blocking, call `sanitizeObject` from
 * `@arcis/node/sanitizers` inside your endpoint handler. v1 keeps the
 * middleware surface narrow.
 *
 * ```ts
 * import { defineMiddleware } from 'astro:middleware';
 * import { onRequest as arcisOnRequest } from '@arcis/node/astro';
 * export const onRequest = arcisOnRequest({ rateLimit: { max: 100 }, bot: true });
 * ```
 *
 * Or compose with other middleware via `sequence`:
 *
 * ```ts
 * import { sequence } from 'astro:middleware';
 * import { onRequest as arcis } from '@arcis/node/astro';
 * export const onRequest = sequence(arcis(), authMiddleware);
 * ```
 *
 * Astro uses Web Fetch `Request`/`Response`, like SvelteKit, but the request
 * context exposes `clientAddress` as a getter property (not a method) and
 * `next()` takes no arguments. There is no runtime dependency on `astro` —
 * the middleware shape is duck-typed.
 */

import type { Request as ExpressRequestLike } from 'express';
import { RATE_LIMIT } from '../core/constants';
import type {
  HeaderOptions,
  RateLimitOptions,
} from '../core/types';
import {
  detectBot,
  type BotProtectionOptions,
  type BotDetectionResult,
} from './bot-detection';
import { applyPlanToHeaders, parseForwardedProto, planSecurityHeaders } from './security-headers';

// ─── Astro duck-typed contracts ─────────────────────────────────────────────

interface AstroCookies {
  get(name: string): { value: string } | undefined;
  set(name: string, value: string, opts?: { path?: string; [k: string]: unknown }): void;
  delete(name: string, opts?: { path?: string }): void;
}

export interface AstroAPIContext {
  request: Request;
  url: URL;
  cookies: AstroCookies;
  /** Astro exposes the client IP as a getter property, not a method. */
  clientAddress: string;
}

export type AstroMiddlewareNext = () => Promise<Response>;

export type AstroMiddlewareHandler = (
  context: AstroAPIContext,
  next: AstroMiddlewareNext,
) => Promise<Response>;

// ─── Adapter options ────────────────────────────────────────────────────────

export interface ArcisAstroOptions {
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

function applySecurityHeaders(
  response: Response,
  options: HeaderOptions,
  context: AstroAPIContext,
): void {
  const isHttps =
    context.url.protocol === 'https:' ||
    parseForwardedProto(context.request.headers.get('x-forwarded-proto')) === 'https';
  applyPlanToHeaders(response.headers, planSecurityHeaders(options, { isHttps }));
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Build an Astro `MiddlewareHandler` that applies Arcis protections in this
 * order on each request: rate limit (returns 429 if exceeded), bot detection
 * (returns 403 if denied), then runs `next()`, then mutates the resulting
 * response's headers with security defaults.
 */
export function onRequest(options: ArcisAstroOptions = {}): AstroMiddlewareHandler {
  const headersCfg = options.headers ?? true;
  const rateLimitCfg = options.rateLimit ?? true;
  const botCfg = options.bot;

  const limiter = rateLimitCfg
    ? buildLimiter(typeof rateLimitCfg === 'object' ? rateLimitCfg : {})
    : null;

  const botEnabled = !!botCfg;
  const botOpts: BotProtectionOptions = typeof botCfg === 'object' ? botCfg : {};
  const botAllow = new Set(botOpts.allow ?? ['SEARCH_ENGINE', 'SOCIAL', 'MONITORING']);
  const botDeny = new Set(botOpts.deny ?? ['AUTOMATED']);
  const botDefault = botOpts.defaultAction ?? 'allow';
  const botStatusCode = botOpts.statusCode ?? 403;
  const botMessage = botOpts.message ?? 'Access denied.';

  return async (context, next) => {
    if (limiter) {
      const decision = limiter(context.clientAddress);
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

    if (botEnabled) {
      const result: BotDetectionResult = detectBot(botInputFor(context.request.headers));
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

    const response = await next();

    if (headersCfg) {
      applySecurityHeaders(response, typeof headersCfg === 'object' ? headersCfg : {}, context);
    }

    return response;
  };
}

export default onRequest;
