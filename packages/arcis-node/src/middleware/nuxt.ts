/**
 * @module @arcis/node/nuxt
 *
 * Nuxt (h3) adapter for Arcis. Drop into a server middleware file.
 *
 * **Scope:** rate-limit + bot detection + security headers. For
 * XSS/SQL/SSTI/etc. body-payload blocking, call `sanitizeObject` from
 * `@arcis/node/sanitizers` inside your route handler. v1 keeps the
 * middleware surface narrow.
 *
 * ```ts
 * // server/middleware/arcis.ts
 * import { defineEventHandler } from 'h3';
 * import { arcisHandler } from '@arcis/node/nuxt';
 * export default defineEventHandler(arcisHandler({ rateLimit: { max: 100 } }));
 * ```
 *
 * Or compose with other handlers — each Nuxt server middleware file runs in
 * the order Nitro discovers them (alphabetical by default).
 *
 * The adapter operates against h3's Node-compat layer (`event.node.req` /
 * `event.node.res`) so it works on the standard Nuxt server. There is no
 * runtime dependency on `h3` — its event shape is duck-typed.
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
import { compileSecurityHeaders, type CompiledSecurityHeaders } from './security-headers';
import { createClientIpResolver, toHeaderGetter, type ClientIpOptions } from '../utils/client-ip';
import { adapterKey, buildAdapterLimiter, mergeClientIpOptions } from './rate-limit-shared';

// ─── h3 / Nuxt duck-typed contracts ─────────────────────────────────────────

interface NodeIncomingMessageLike {
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
  method?: string;
  url?: string;
}

interface NodeServerResponseLike {
  statusCode: number;
  writableEnded?: boolean;
  setHeader(name: string, value: string | number | string[]): void;
  removeHeader(name: string): void;
  end(body?: string): void;
}

export interface H3EventLike {
  node: {
    req: NodeIncomingMessageLike;
    res: NodeServerResponseLike;
  };
}

export type ArcisH3Handler = (event: H3EventLike) => Promise<void> | void;

// ─── Adapter options ────────────────────────────────────────────────────────

/**
 * Adapter options. The client IP is the socket peer address passed through
 * the `trustedProxies` walk; on edge presets without a socket, the
 * configured `clientIpHeader` or the platform header is used, else one
 * shared `unknown` key.
 */
export interface ArcisNuxtOptions extends ClientIpOptions {
  /** Security headers configuration. Default: enabled. Pass `false` to disable. */
  headers?: boolean | HeaderOptions;
  /** Rate limiter configuration. Default: 100 req/60s in-memory. Pass `false` to disable. */
  rateLimit?: boolean | RateLimitOptions;
  /** Bot protection. Default: disabled (opt-in). */
  bot?: boolean | BotProtectionOptions;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function botInputFor(req: NodeIncomingMessageLike): ExpressRequestLike {
  // Node's IncomingMessage already has the headers shape detectBot reads off
  // an Express request — pass it through with a type assertion.
  return { headers: req.headers } as unknown as ExpressRequestLike;
}

function isHttpsRequest(req: NodeIncomingMessageLike): boolean {
  const xfp = req.headers['x-forwarded-proto'];
  const value = (Array.isArray(xfp) ? xfp[0] : xfp)?.split(',')[0]?.trim()?.toLowerCase();
  return value === 'https';
}

function applySecurityHeaders(
  res: NodeServerResponseLike,
  req: NodeIncomingMessageLike,
  policy: CompiledSecurityHeaders,
): void {
  // Applied before the route handler runs, so a header the route sets wins.
  const plan = policy.plan({ isHttps: isHttpsRequest(req), request: req, response: res });
  for (const [name, value] of plan.set) res.setHeader(name, value);
  for (const name of plan.remove) res.removeHeader(name);
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Build an h3 event handler that applies Arcis protections on each request.
 * Wrap it with `defineEventHandler` in your Nuxt server middleware. When a
 * request is rate-limited or denied, the handler writes the 429/403 response
 * directly via `event.node.res` and returns; otherwise it sets security
 * headers and falls through to the next handler.
 */
export function arcisHandler(options: ArcisNuxtOptions = {}): ArcisH3Handler {
  const headersCfg = options.headers ?? true;
  const headerPolicy = headersCfg
    ? compileSecurityHeaders(typeof headersCfg === 'object' ? headersCfg : {}, {
        nonceUnsupportedBy: 'Nuxt',
      })
    : null;
  const rateLimitCfg = options.rateLimit ?? true;
  const botCfg = options.bot;

  const rateLimitOpts = typeof rateLimitCfg === 'object' ? rateLimitCfg : {};
  const limiter = rateLimitCfg ? buildAdapterLimiter(rateLimitOpts, 'arcisHandler') : null;
  const resolver = createClientIpResolver(mergeClientIpOptions(options, rateLimitOpts));

  const botEnabled = !!botCfg;
  const botOpts: BotProtectionOptions = typeof botCfg === 'object' ? botCfg : {};
  const botAllow = new Set(botOpts.allow ?? ['SEARCH_ENGINE', 'SOCIAL', 'MONITORING']);
  const botDeny = new Set(botOpts.deny ?? ['AUTOMATED']);
  const botDefault = botOpts.defaultAction ?? 'allow';
  const botStatusCode = botOpts.statusCode ?? 403;
  const botMessage = botOpts.message ?? 'Access denied.';

  return (event) => {
    const { req, res } = event.node;

    // 1. Rate limit
    if (limiter) {
      const ip = resolver.resolve(req.socket?.remoteAddress, toHeaderGetter(req.headers));
      const decision = limiter.check(adapterKey(ip, limiter, 'arcisHandler'));
      if (!decision.allowed) {
        res.statusCode = 429;
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Retry-After', decision.resetSeconds.toString());
        res.setHeader('X-RateLimit-Limit', decision.max.toString());
        res.setHeader('X-RateLimit-Remaining', '0');
        res.setHeader('X-RateLimit-Reset', decision.resetSeconds.toString());
        res.end(
          JSON.stringify({
            error: 'Too many requests, please try again later.',
            retryAfter: decision.resetSeconds,
          }),
        );
        return;
      }
    }

    // 2. Bot detection
    if (botEnabled) {
      const result: BotDetectionResult = detectBot(botInputFor(req));
      if (result.isBot) {
        const denied =
          botDeny.has(result.category) ||
          (!botAllow.has(result.category) && botDefault === 'deny');
        if (denied) {
          res.statusCode = botStatusCode;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ error: botMessage }));
          return;
        }
      }
    }

    // 3. Security headers — set up-front so they're sent with the eventual
    // response from the downstream Nuxt route handler.
    if (headerPolicy) {
      applySecurityHeaders(res, req, headerPolicy);
    }
  };
}

export default arcisHandler;
