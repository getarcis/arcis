/**
 * @module @arcis/node/nuxt
 *
 * Nuxt (h3) adapter for Arcis. Drop into a server middleware file:
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

export interface ArcisNuxtOptions {
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

function botInputFor(req: NodeIncomingMessageLike): ExpressRequestLike {
  // Node's IncomingMessage already has the headers shape detectBot reads off
  // an Express request — pass it through with a type assertion.
  return { headers: req.headers } as unknown as ExpressRequestLike;
}

function clientIpFromReq(req: NodeIncomingMessageLike): string {
  // Trust X-Forwarded-For only when present and well-formed; fall back to
  // socket.remoteAddress; finally a stable 'unknown' bucket so a missing IP
  // doesn't share a counter with every other unresolvable client.
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  const remote = req.socket?.remoteAddress;
  if (remote) return remote;
  return 'unknown';
}

function isHttpsRequest(req: NodeIncomingMessageLike): boolean {
  const xfp = req.headers['x-forwarded-proto'];
  const value = (Array.isArray(xfp) ? xfp[0] : xfp)?.split(',')[0]?.trim()?.toLowerCase();
  return value === 'https';
}

function applySecurityHeaders(
  res: NodeServerResponseLike,
  req: NodeIncomingMessageLike,
  options: HeaderOptions,
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

  if (contentSecurityPolicy) {
    res.setHeader(
      'Content-Security-Policy',
      typeof contentSecurityPolicy === 'string' ? contentSecurityPolicy : HEADERS.DEFAULT_CSP,
    );
  }
  if (xssFilter) res.setHeader('X-XSS-Protection', '0');
  if (noSniff) res.setHeader('X-Content-Type-Options', HEADERS.CONTENT_TYPE_OPTIONS);
  if (frameOptions) res.setHeader('X-Frame-Options', frameOptions);

  if (hsts && isHttpsRequest(req)) {
    const o: HstsOptions = typeof hsts === 'object' ? hsts : {};
    const maxAge = o.maxAge ?? HEADERS.HSTS_MAX_AGE;
    const includeSub = o.includeSubDomains !== false;
    const preload = o.preload === true;
    let v = `max-age=${maxAge}`;
    if (includeSub) v += '; includeSubDomains';
    if (preload) v += '; preload';
    res.setHeader('Strict-Transport-Security', v);
  }

  if (referrerPolicy) res.setHeader('Referrer-Policy', referrerPolicy);
  if (permissionsPolicy) res.setHeader('Permissions-Policy', permissionsPolicy);
  if (crossOriginOpenerPolicy) res.setHeader('Cross-Origin-Opener-Policy', crossOriginOpenerPolicy);
  if (crossOriginResourcePolicy) res.setHeader('Cross-Origin-Resource-Policy', crossOriginResourcePolicy);
  if (crossOriginEmbedderPolicy) res.setHeader('Cross-Origin-Embedder-Policy', crossOriginEmbedderPolicy);
  if (originAgentCluster) res.setHeader('Origin-Agent-Cluster', '?1');
  if (dnsPrefetchControl) res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');

  if (cacheControl) {
    res.setHeader(
      'Cache-Control',
      typeof cacheControl === 'string' ? cacheControl : HEADERS.CACHE_CONTROL,
    );
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }

  res.removeHeader('X-Powered-By');
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

  return (event) => {
    const { req, res } = event.node;

    // 1. Rate limit
    if (limiter) {
      const decision = limiter(clientIpFromReq(req));
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
    if (headersCfg) {
      applySecurityHeaders(res, req, typeof headersCfg === 'object' ? headersCfg : {});
    }
  };
}

export default arcisHandler;
