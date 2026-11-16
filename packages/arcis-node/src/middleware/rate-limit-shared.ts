/**
 * @module @arcis/node/middleware/rate-limit-shared
 * Pieces shared by the core rate limiter and the framework adapters: the
 * legacy-store compatibility wrapper, once-per-window store error reporting
 * and the bounded in-memory limiter the adapters use.
 *
 * No Node built-ins here: the adapters run on edge runtimes too.
 */

import { RATE_LIMIT } from '../core/constants';
import { validateMax, validateWindowMs } from '../core/rate-limit-config';
import { warnOnce } from '../core/warn-once';
import type {
  LegacyRateLimitStore,
  RateLimitIncrement,
  RateLimitOptions,
  RateLimitStore,
} from '../core/types';
import { FixedWindowCounter } from '../stores/fixed-window';
import {
  clientKey,
  normalizeIp,
  validateIpv6Subnet,
  warnUnknownClient,
  type ClientIpOptions,
} from '../utils/client-ip';

// ─── Store contract ─────────────────────────────────────────────────────────

function isAtomicStore(store: RateLimitStore | LegacyRateLimitStore): store is RateLimitStore {
  return typeof (store as RateLimitStore).resetKey === 'function';
}

/**
 * Return `store` when it implements the atomic contract; wrap a legacy
 * get/set store otherwise. The wrapper is not atomic across instances and
 * warns once per process.
 */
export function toAtomicStore(store: RateLimitStore | LegacyRateLimitStore): RateLimitStore {
  if (isAtomicStore(store)) return store;
  warnOnce(
    'legacy-store',
    'The rate limit store implements the old get/set interface, so counting is not atomic ' +
      'across instances and concurrent requests can exceed max. Implement ' +
      'increment(key, windowMs) -> { totalHits, resetTime }, decrement(key) and resetKey(key).',
  );
  const legacy = store;
  return {
    async increment(key: string, windowMs: number): Promise<RateLimitIncrement> {
      const now = Date.now();
      const entry = await legacy.get(key);
      if (!entry || entry.resetTime <= now) {
        const resetTime = now + windowMs;
        await legacy.set(key, { count: 1, resetTime });
        return { totalHits: 1, resetTime };
      }
      return { totalHits: await legacy.increment(key), resetTime: entry.resetTime };
    },
    async decrement(key: string): Promise<void> {
      await legacy.decrement?.(key);
    },
    async resetKey(key: string): Promise<void> {
      await legacy.reset?.(key);
    },
    async get(key: string): Promise<RateLimitIncrement | null> {
      const entry = await legacy.get(key);
      return entry && entry.resetTime > Date.now()
        ? { totalHits: entry.count, resetTime: entry.resetTime }
        : null;
    },
    async close(): Promise<void> {
      await legacy.close?.();
    },
  };
}

/**
 * Build a store-error reporter that fires at most once per `windowMs`. It
 * calls `onError` when given, otherwise logs one `console.error` line.
 */
export function createStoreErrorReporter(
  windowMs: number,
  onError?: (error: Error) => void,
): (error: unknown) => void {
  let lastReport = -Infinity;
  return (error) => {
    const now = Date.now();
    if (now - lastReport < windowMs) return;
    lastReport = now;
    const err = error instanceof Error ? error : new Error(String(error));
    if (onError) {
      try {
        onError(err);
      } catch {
        // A failing error callback must not break the request path.
      }
      return;
    }
    // eslint-disable-next-line no-console
    console.error('[arcis] Rate limit store error; counting in memory until it recovers:', err);
  };
}

// ─── Options ────────────────────────────────────────────────────────────────

/**
 * Client IP options for an adapter's limiter: the `rateLimit` object's own
 * settings win over the adapter-level ones.
 */
export function mergeClientIpOptions(
  adapter: ClientIpOptions,
  rateLimit: ClientIpOptions | undefined,
): ClientIpOptions {
  return {
    trustedProxies: rateLimit?.trustedProxies ?? adapter.trustedProxies,
    clientIpHeader: rateLimit?.clientIpHeader ?? adapter.clientIpHeader,
  };
}

/** Client IP options for adapters built on Web Fetch requests. */
export interface FetchClientIpOptions extends ClientIpOptions {
  /**
   * Resolve the client IP yourself, for runtimes without a peer address or
   * a platform header Arcis recognizes. A missing or invalid result falls
   * through to the built-in rules. Default: none.
   */
  getClientIp?: (request: Request) => string | null | undefined;
}

/** The normalized result of a user `getClientIp`, or `null`. */
export function userClientIp(
  getClientIp: FetchClientIpOptions['getClientIp'],
  request: Request,
): string | null {
  if (!getClientIp) return null;
  try {
    return normalizeIp(getClientIp(request));
  } catch {
    return null;
  }
}

/**
 * Peer address from a Hono context's `env`: `@hono/node-server`
 * (`env.incoming`), Bun (`env.requestIP`) or Deno (`env.remoteAddr`).
 * Cloudflare Workers bindings have none.
 */
export function honoPeerAddress(env: unknown, request: Request): string | undefined {
  if (!env || typeof env !== 'object') return undefined;
  const e = env as {
    incoming?: { socket?: { remoteAddress?: string } };
    requestIP?: (req: Request) => { address?: string } | null;
    remoteAddr?: { hostname?: string };
  };
  const nodePeer = e.incoming?.socket?.remoteAddress;
  if (nodePeer) return nodePeer;
  if (typeof e.requestIP === 'function') {
    try {
      const bunPeer = e.requestIP(request)?.address;
      if (bunPeer) return bunPeer;
    } catch {
      // Not a Bun server after all.
    }
  }
  return e.remoteAddr?.hostname;
}

// ─── Adapter limiter ────────────────────────────────────────────────────────

/** One adapter rate-limit decision. */
export interface AdapterRateLimitDecision {
  allowed: boolean;
  count: number;
  max: number;
  remaining: number;
  resetSeconds: number;
}

/** Bounded in-memory fixed-window limiter used by the framework adapters. */
export interface AdapterRateLimiter {
  /** Count one request for `key`. */
  check(key: string): AdapterRateLimitDecision;
  /** IPv6 prefix length for the default key. */
  ipv6Subnet: number | false;
}

/**
 * Rate-limit key for a resolved client IP. A missing address maps to the
 * shared `unknown` key and warns once.
 */
export function adapterKey(ip: string | null, limiter: AdapterRateLimiter, runtime: string): string {
  if (ip === null) warnUnknownClient(runtime);
  return clientKey(ip, limiter.ipv6Subnet);
}

/**
 * Build an adapter limiter. Validates `max`, `windowMs` and `ipv6Subnet` at
 * construction; the counter evicts expired then least recently used keys at
 * its size cap and sweeps expired keys lazily.
 */
export function buildAdapterLimiter(opts: RateLimitOptions, owner: string): AdapterRateLimiter {
  const max = validateMax(opts.max ?? RATE_LIMIT.DEFAULT_MAX_REQUESTS, owner);
  const windowMs = validateWindowMs(opts.windowMs ?? RATE_LIMIT.DEFAULT_WINDOW_MS, owner);
  const ipv6Subnet = validateIpv6Subnet(opts.ipv6Subnet, owner);
  const counter = new FixedWindowCounter();
  return {
    ipv6Subnet,
    check(key) {
      const now = Date.now();
      const { totalHits, resetTime } = counter.increment(key, windowMs, now);
      return {
        allowed: totalHits <= max,
        count: totalHits,
        max,
        remaining: Math.max(0, max - totalHits),
        resetSeconds: Math.ceil((resetTime - now) / 1000),
      };
    },
  };
}
