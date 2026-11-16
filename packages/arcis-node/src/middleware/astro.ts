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
import { createClientIpResolver, toHeaderGetter, type ClientIpOptions } from '../utils/client-ip';
import { adapterKey, buildAdapterLimiter, mergeClientIpOptions } from './rate-limit-shared';

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

/**
 * Adapter options. The framework address (`context.clientAddress`) is the peer for
 * the `trustedProxies` walk, so a proxy on a trusted private address can
 * report the client in X-Forwarded-For while a public client cannot choose
 * its own key. When no address is available, `clientIpHeader` or the
 * platform header is used, else one shared `unknown` key.
 */
export interface ArcisAstroOptions extends ClientIpOptions {
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
  context: AstroAPIContext,
): void {
  const isHttps =
    context.url.protocol === 'https:' ||
    parseForwardedProto(context.request.headers.get('x-forwarded-proto')) === 'https';
  applyPlanToHeaders(response.headers, policy, policy.plan({ isHttps, request: context, response }));
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
  const headerPolicy = headersCfg
    ? compileSecurityHeaders(typeof headersCfg === 'object' ? headersCfg : {}, {
        nonceUnsupportedBy: 'Astro',
      })
    : null;
  const rateLimitCfg = options.rateLimit ?? true;
  const botCfg = options.bot;

  const rateLimitOpts = typeof rateLimitCfg === 'object' ? rateLimitCfg : {};
  const limiter = rateLimitCfg ? buildAdapterLimiter(rateLimitOpts, 'onRequest') : null;
  const resolver = createClientIpResolver(mergeClientIpOptions(options, rateLimitOpts));

  const botEnabled = !!botCfg;
  const botOpts: BotProtectionOptions = typeof botCfg === 'object' ? botCfg : {};
  const botAllow = new Set(botOpts.allow ?? ['SEARCH_ENGINE', 'SOCIAL', 'MONITORING']);
  const botDeny = new Set(botOpts.deny ?? ['AUTOMATED']);
  const botDefault = botOpts.defaultAction ?? 'allow';
  const botStatusCode = botOpts.statusCode ?? 403;
  const botMessage = botOpts.message ?? 'Access denied.';

  return async (context, next) => {
    if (limiter) {
      let peer: string | undefined;
      try {
        peer = context.clientAddress;
      } catch {
        // The adapter cannot provide an address (for example a prerendered route).
      }
      const ip = resolver.resolve(peer, toHeaderGetter(context.request.headers));
      const decision = limiter.check(adapterKey(ip, limiter, 'onRequest'));
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

    if (headerPolicy) {
      applySecurityHeaders(response, headerPolicy, context);
    }

    return response;
  };
}

export default onRequest;
