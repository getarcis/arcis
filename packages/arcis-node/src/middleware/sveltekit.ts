/**
 * @module @arcis/node/sveltekit
 *
 * SvelteKit adapter for Arcis. Returns a `Handle` factory you can drop into
 * `src/hooks.server.ts`.
 *
 * **Scope:** rate-limit + bot detection + security headers. For
 * XSS/SQL/SSTI/etc. body-payload blocking, call `sanitizeObject` from
 * `@arcis/node/sanitizers` inside your route handler. v1 keeps the
 * middleware surface narrow.
 *
 * ```ts
 * import { arcisHandle } from '@arcis/node/sveltekit';
 * export const handle = arcisHandle({ rateLimit: { max: 100 }, bot: true });
 * ```
 *
 * Or compose with other handles via SvelteKit's own `sequence` helper:
 *
 * ```ts
 * import { sequence } from '@sveltejs/kit/hooks';
 * import { arcisHandle } from '@arcis/node/sveltekit';
 * export const handle = sequence(arcisHandle(), authHandle, loggingHandle);
 * ```
 *
 * SvelteKit uses Web Fetch `Request`/`Response` objects, not Express
 * `req`/`res`, so this adapter implements the Arcis pipeline natively against
 * the Fetch API rather than wrapping `arcis()`. There is no runtime dependency
 * on `@sveltejs/kit` — its types are imported only for compile-time checks.
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

// ─── SvelteKit duck-typed contracts ─────────────────────────────────────────
// Mirrors `@sveltejs/kit`'s `RequestEvent` / `Handle` shape closely enough
// that real SvelteKit types are assignable, without taking a runtime dep.

interface SvelteKitCookies {
  get(name: string): string | undefined;
  set(name: string, value: string, opts: { path: string; [k: string]: unknown }): void;
  delete(name: string, opts: { path: string }): void;
}

export interface SvelteKitRequestEvent {
  request: Request;
  url: URL;
  cookies: SvelteKitCookies;
  getClientAddress(): string;
}

export type SvelteKitResolve = (
  event: SvelteKitRequestEvent,
  opts?: unknown,
) => Promise<Response> | Response;

export type SvelteKitHandle = (input: {
  event: SvelteKitRequestEvent;
  resolve: SvelteKitResolve;
}) => Promise<Response>;

// ─── Adapter options ────────────────────────────────────────────────────────

/**
 * Adapter options. The framework address (`event.getClientAddress()`) is the peer for
 * the `trustedProxies` walk, so a proxy on a trusted private address can
 * report the client in X-Forwarded-For while a public client cannot choose
 * its own key. When no address is available, `clientIpHeader` or the
 * platform header is used, else one shared `unknown` key.
 */
export interface ArcisHandleOptions extends ClientIpOptions {
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
  event: SvelteKitRequestEvent,
): void {
  const isHttps =
    event.url.protocol === 'https:' ||
    parseForwardedProto(event.request.headers.get('x-forwarded-proto')) === 'https';
  applyPlanToHeaders(response.headers, policy, policy.plan({ isHttps, request: event, response }));
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Build a SvelteKit `Handle` that applies Arcis protections in this order on
 * each request: rate limit (returns 429 if exceeded), bot detection (returns
 * 403 if the bot is in the deny list), then runs downstream `resolve(event)`,
 * then mutates the resulting `Response`'s headers with security defaults.
 */
export function arcisHandle(options: ArcisHandleOptions = {}): SvelteKitHandle {
  const headersCfg = options.headers ?? true;
  const headerPolicy = headersCfg
    ? compileSecurityHeaders(typeof headersCfg === 'object' ? headersCfg : {}, {
        nonceUnsupportedBy: 'SvelteKit',
      })
    : null;
  const rateLimitCfg = options.rateLimit ?? true;
  const botCfg = options.bot;

  const rateLimitOpts = typeof rateLimitCfg === 'object' ? rateLimitCfg : {};
  const limiter = rateLimitCfg ? buildAdapterLimiter(rateLimitOpts, 'arcisHandle') : null;
  const resolver = createClientIpResolver(mergeClientIpOptions(options, rateLimitOpts));

  const botEnabled = !!botCfg;
  const botOpts: BotProtectionOptions =
    typeof botCfg === 'object' ? botCfg : {};
  const botAllow = new Set(botOpts.allow ?? ['SEARCH_ENGINE', 'SOCIAL', 'MONITORING']);
  const botDeny = new Set(botOpts.deny ?? ['AUTOMATED']);
  const botDefault = botOpts.defaultAction ?? 'allow';
  const botStatusCode = botOpts.statusCode ?? 403;
  const botMessage = botOpts.message ?? 'Access denied.';

  return async ({ event, resolve }) => {
    // 1. Rate limit
    if (limiter) {
      let peer: string | undefined;
      try {
        peer = event.getClientAddress();
      } catch {
        // The adapter cannot provide an address (for example a prerendered route).
      }
      const ip = resolver.resolve(peer, toHeaderGetter(event.request.headers));
      const decision = limiter.check(adapterKey(ip, limiter, 'arcisHandle'));
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
      const result: BotDetectionResult = detectBot(botInputFor(event.request.headers));
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

    // 3. Resolve downstream
    const response = await resolve(event);

    // 4. Apply security headers (in-place; SvelteKit's response headers are mutable)
    if (headerPolicy) {
      applySecurityHeaders(response, headerPolicy, event);
    }

    return response;
  };
}

export default arcisHandle;
