/**
 * @module @arcis/node/astro
 *
 * Astro adapter for Arcis. Drop into `src/middleware.ts`:
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

  const xfp = context.request.headers
    .get('x-forwarded-proto')
    ?.split(',')[0]
    ?.trim()
    ?.toLowerCase();
  const trustedXfp = xfp === 'https' || xfp === 'http' ? xfp : undefined;
  const isHttps = context.url.protocol === 'https:' || trustedXfp === 'https';

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
