/**
 * @module @arcis/node/fastify
 *
 * Fastify plugin for Arcis. Registers `onRequest` (rate-limit + bot) and
 * `onSend` (security headers) hooks so the protections compose with any
 * other Fastify plugins your app uses.
 *
 * ```ts
 * import Fastify from 'fastify';
 * import { arcisFastify } from '@arcis/node/fastify';
 *
 * const app = Fastify();
 * await app.register(arcisFastify, {
 *   rateLimit: { max: 100, windowMs: 60_000 },
 *   bot: true,
 * });
 *
 * app.get('/', async () => ({ ok: true }));
 * await app.listen({ port: 3000 });
 * ```
 *
 * No runtime dependency on `fastify` — its types are duck-typed enough to
 * satisfy Fastify's actual `FastifyInstance` / `FastifyRequest` /
 * `FastifyReply` shapes without pulling Fastify into peer-deps.
 *
 * For body-content inspection (the `block: true` flow other adapters
 * expose), drop the standard Express adapter (`arcis()` from the package
 * root) into a custom server, or pair this plugin with the standalone
 * sanitizer middleware on a hook. v1 keeps the surface narrow:
 * rate-limit, bot, headers.
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
import { parseForwardedProto, planSecurityHeaders } from './security-headers';

// ─── Fastify duck-typed contracts ───────────────────────────────────────────
// Mirror just enough of the FastifyInstance / FastifyRequest / FastifyReply
// surface to wire the hooks without taking a runtime dep on `fastify`.

/**
 * Subset of Fastify's request shape used by the hooks. Real
 * `FastifyRequest` is assignable to this.
 */
export interface FastifyRequestLike {
  headers: Record<string, string | string[] | undefined>;
  url?: string;
  method?: string;
  ip?: string;
  socket?: { remoteAddress?: string };
  raw?: { headers: Record<string, string | string[] | undefined>; url?: string };
}

/**
 * Subset of Fastify's reply shape. Real `FastifyReply` is assignable to
 * this — the methods we use (`status`, `header`, `send`) all exist on
 * the actual Fastify reply.
 */
export interface FastifyReplyLike {
  status(code: number): FastifyReplyLike;
  header(name: string, value: string): FastifyReplyLike;
  /** Real Fastify replies expose this; used to strip fingerprinting headers. */
  removeHeader?(name: string): FastifyReplyLike;
  send(payload: unknown): FastifyReplyLike;
}

export type FastifyHookHandler = (
  request: FastifyRequestLike,
  reply: FastifyReplyLike,
) => Promise<void> | void;

export type FastifyOnSendHandler = (
  request: FastifyRequestLike,
  reply: FastifyReplyLike,
  payload: unknown,
) => Promise<unknown> | unknown;

export interface FastifyInstanceLike {
  addHook(name: 'onRequest', handler: FastifyHookHandler): unknown;
  addHook(name: 'onSend', handler: FastifyOnSendHandler): unknown;
}

// ─── Plugin options ─────────────────────────────────────────────────────────

export interface ArcisFastifyOptions {
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
 * Pull the first header value as a plain string. Fastify's request.headers
 * is `Record<string, string | string[] | undefined>` — matches Node's
 * IncomingMessage.headers shape.
 */
function headerValue(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const v = headers[name];
  if (v === undefined) return undefined;
  if (Array.isArray(v)) return v[0];
  return v;
}

/**
 * Adapt the Fastify-style headers object to the shape `detectBot()`
 * reads off an Express request. Only headers `detectBot` consults are
 * forwarded — keeps the surface tiny.
 */
function botInputFor(
  headers: Record<string, string | string[] | undefined>,
): ExpressRequestLike {
  const h: Record<string, string | undefined> = {
    'user-agent': headerValue(headers, 'user-agent'),
    accept: headerValue(headers, 'accept'),
    'accept-language': headerValue(headers, 'accept-language'),
    'accept-encoding': headerValue(headers, 'accept-encoding'),
    connection: headerValue(headers, 'connection'),
  };
  return { headers: h } as unknown as ExpressRequestLike;
}

/**
 * Pull a stable client IP. Order: `request.ip` (Fastify pre-resolves
 * trustProxy when configured) → X-Forwarded-For (leftmost) → X-Real-IP →
 * socket.remoteAddress → "unknown". `request.ip` is the canonical Fastify
 * field — when the user enables `trustProxy: true` Fastify already parsed
 * the right entry from XFF; we honor that when it's set.
 */
function clientIpOf(request: FastifyRequestLike): string {
  if (request.ip) return request.ip;
  const headers = request.headers ?? request.raw?.headers ?? {};
  const xff = headerValue(headers, 'x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  const xrip = headerValue(headers, 'x-real-ip');
  if (xrip) return xrip.trim();
  if (request.socket?.remoteAddress) return request.socket.remoteAddress;
  return 'unknown';
}

function applySecurityHeaders(
  reply: FastifyReplyLike,
  options: HeaderOptions,
  request: FastifyRequestLike,
): void {
  // Fastify exposes only a path, so HTTPS is known from a trusted
  // X-Forwarded-Proto. Deployments behind a TLS proxy must set it for HSTS.
  const headers = request.headers ?? request.raw?.headers ?? {};
  const isHttps = parseForwardedProto(headerValue(headers, 'x-forwarded-proto')) === 'https';
  const plan = planSecurityHeaders(options, { isHttps });
  for (const [name, value] of plan.set) reply.header(name, value);
  for (const name of plan.remove) reply.removeHeader?.(name);
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Fastify plugin. Registers `onRequest` (rate-limit + bot) + `onSend`
 * (security headers) hooks. Use via `app.register(arcisFastify, options)`.
 *
 * Plugin signature follows the canonical async Fastify plugin shape.
 * Returns a Promise<void> so Fastify's encapsulation contract is met
 * even if no async work is currently performed inside.
 */
export async function arcisFastify(
  fastify: FastifyInstanceLike,
  options: ArcisFastifyOptions = {},
): Promise<void> {
  const headersCfg = options.headers ?? true;
  const rateLimitCfg = options.rateLimit ?? true;
  const botCfg = options.bot;

  const limiter = rateLimitCfg
    ? buildLimiter(typeof rateLimitCfg === 'object' ? rateLimitCfg : {})
    : null;

  const botEnabled = !!botCfg;
  const botOpts: BotProtectionOptions =
    typeof botCfg === 'object' ? botCfg : {};
  const botAllow = new Set(botOpts.allow ?? ['SEARCH_ENGINE', 'SOCIAL', 'MONITORING']);
  const botDeny = new Set(botOpts.deny ?? ['AUTOMATED']);
  const botDefault = botOpts.defaultAction ?? 'allow';
  const botStatusCode = botOpts.statusCode ?? 403;
  const botMessage = botOpts.message ?? 'Access denied.';

  fastify.addHook('onRequest', async (request, reply) => {
    // 1. Rate limit
    if (limiter) {
      const key = clientIpOf(request);
      const decision = limiter(key);
      reply.header('X-RateLimit-Limit', decision.max.toString());
      reply.header(
        'X-RateLimit-Remaining',
        decision.allowed ? decision.remaining.toString() : '0',
      );
      reply.header('X-RateLimit-Reset', decision.resetSeconds.toString());
      if (!decision.allowed) {
        reply.header('Retry-After', decision.resetSeconds.toString());
        await reply.status(429).send({
          error: 'Too many requests, please try again later.',
          retryAfter: decision.resetSeconds,
        });
        return;
      }
    }

    // 2. Bot detection
    if (botEnabled) {
      const headers = request.headers ?? request.raw?.headers ?? {};
      const result: BotDetectionResult = detectBot(botInputFor(headers));
      if (result.isBot) {
        const denied =
          botDeny.has(result.category) ||
          (!botAllow.has(result.category) && botDefault === 'deny');
        if (denied) {
          await reply.status(botStatusCode).send({ error: botMessage });
          return;
        }
      }
    }
  });

  if (headersCfg) {
    fastify.addHook('onSend', async (request, reply, payload) => {
      // onSend runs after the route handler but before the response is
      // flushed — last chance to mutate headers. Fastify expects the
      // (possibly transformed) payload returned; we don't touch it.
      applySecurityHeaders(
        reply,
        typeof headersCfg === 'object' ? headersCfg : {},
        request,
      );
      return payload;
    });
  }
}

export default arcisFastify;
