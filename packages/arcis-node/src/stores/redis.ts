/**
 * @module @arcis/node/stores/redis
 * Redis rate limit store
 *
 * Bring your own client: pass an `ioredis` instance (or any object with an
 * ioredis-style `eval`). Every operation is one Lua script, so each counted
 * request is a single atomic round trip.
 */

import type { RateLimitStore, RateLimitIncrement } from '../core/types';

/**
 * The Redis client surface RedisStore uses: `EVAL` with ioredis argument
 * order. An `ioredis` client satisfies it as-is. For `node-redis` (v4+), wrap
 * `sendCommand`:
 *
 * ```ts
 * const client = {
 *   eval: (script: string, numKeys: number, ...args: Array<string | number>) =>
 *     nodeRedis.sendCommand(['EVAL', script, String(numKeys), ...args.map(String)]),
 * };
 * ```
 */
export interface RedisClientLike {
  /** Run a Lua script: `eval(script, numKeys, ...keys, ...args)`. */
  eval(script: string, numKeys: number, ...keysAndArgs: Array<string | number>): Promise<unknown>;
}

/** RedisStore options. */
export interface RedisStoreOptions {
  /** Redis client instance */
  client: RedisClientLike;
  /** Key prefix. Default: 'arcis:rl:' */
  prefix?: string;
  /**
   * Not used: each `increment` call passes its own window.
   *
   * @deprecated The limiter passes `windowMs` to `increment`.
   */
  windowMs?: number;
}

// INCR and the expiry are created together: the first hit sets PEXPIRE, and a
// counter found without a TTL (left by an older client) gets one, so a key can
// never lock a client out forever.
const INCREMENT_SCRIPT = `
local hits = redis.call('INCR', KEYS[1])
if hits == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {hits, ttl}`;

const DECREMENT_SCRIPT = `
local hits = tonumber(redis.call('GET', KEYS[1]) or '0')
if hits and hits > 0 then return redis.call('DECR', KEYS[1]) end
return 0`;

const GET_SCRIPT = `
local hits = redis.call('GET', KEYS[1])
if not hits then return nil end
return {tonumber(hits) or 0, redis.call('PTTL', KEYS[1])}`;

const RESET_SCRIPT = `return redis.call('DEL', KEYS[1])`;

function toWindowState(reply: unknown, now: number): RateLimitIncrement {
  if (!Array.isArray(reply) || reply.length !== 2) {
    throw new Error('RedisStore: unexpected reply from Redis');
  }
  const totalHits = Number(reply[0]);
  const ttl = Number(reply[1]);
  if (!Number.isFinite(totalHits) || !Number.isFinite(ttl)) {
    throw new Error('RedisStore: unexpected reply from Redis');
  }
  return { totalHits, resetTime: now + Math.max(0, ttl) };
}

/**
 * Redis rate limit store for distributed deployments. Several app instances
 * sharing one Redis never admit more than `max` requests per window.
 *
 * Errors are thrown, never swallowed: the limiter fails open, counts the
 * request in memory and reports the error.
 *
 * @example
 * import Redis from 'ioredis';
 *
 * const store = new RedisStore({ client: new Redis() });
 * app.use(createRateLimiter({ store }));
 */
export class RedisStore implements RateLimitStore {
  private readonly client: RedisClientLike;
  private readonly prefix: string;

  constructor(options: RedisStoreOptions) {
    if (!options?.client || typeof options.client.eval !== 'function') {
      throw new TypeError('RedisStore: options.client must provide eval(script, numKeys, ...args)');
    }
    this.client = options.client;
    this.prefix = options.prefix ?? 'arcis:rl:';
  }

  private redisKey(key: string): string {
    return `${this.prefix}${key}`;
  }

  /** Count one hit (INCR + PEXPIRE on first hit + PTTL in one script). */
  async increment(key: string, windowMs: number): Promise<RateLimitIncrement> {
    const reply = await this.client.eval(INCREMENT_SCRIPT, 1, this.redisKey(key), windowMs);
    return toWindowState(reply, Date.now());
  }

  /** Remove one hit, floored at 0. */
  async decrement(key: string): Promise<void> {
    await this.client.eval(DECREMENT_SCRIPT, 1, this.redisKey(key));
  }

  /** Delete the key. */
  async resetKey(key: string): Promise<void> {
    await this.client.eval(RESET_SCRIPT, 1, this.redisKey(key));
  }

  /** Current window state, or `null` when the key has no live window. */
  async get(key: string): Promise<RateLimitIncrement | null> {
    const reply = await this.client.eval(GET_SCRIPT, 1, this.redisKey(key));
    if (reply === null || reply === undefined) return null;
    return toWindowState(reply, Date.now());
  }

  /** No-op: the client is caller-owned and may be shared. */
  async close(): Promise<void> {}
}

/**
 * Create a Redis store with the given options.
 *
 * @example
 * const store = createRedisStore({ client: redisClient });
 */
export function createRedisStore(options: RedisStoreOptions): RedisStore {
  return new RedisStore(options);
}
