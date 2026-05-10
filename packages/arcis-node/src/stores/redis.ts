/**
 * @module @arcis/node/stores/redis
 * Redis rate limit store
 * 
 * Note: This is a reference implementation. You'll need to install
 * the 'ioredis' or 'redis' package and pass your client instance.
 */

import type { RateLimitStore, RateLimitEntry } from '../core/types';
import { RATE_LIMIT } from '../core/constants';

/** Generic Redis client interface (works with ioredis, redis, etc.) */
export interface RedisClientLike {
  get(key: string): Promise<string | null>;
  /**
   * SET with optional flags. Supports both `set(key, value)` and
   * `set(key, value, 'EX', seconds, 'NX')` shapes for atomic
   * set-if-not-exists with TTL. Returns 'OK' on success; null when NX
   * is supplied and the key already exists.
   */
  set(
    key: string,
    value: string,
    ...args: Array<string | number>
  ): Promise<string | null | unknown>;
  setex(key: string, seconds: number, value: string): Promise<unknown>;
  expire(key: string, seconds: number): Promise<unknown>;
  incr(key: string): Promise<number>;
  decr(key: string): Promise<number>;
  del(key: string): Promise<number>;
  ttl(key: string): Promise<number>;
  quit?(): Promise<unknown>;
  disconnect?(): Promise<unknown>;
}

export interface RedisStoreOptions {
  /** Redis client instance */
  client: RedisClientLike;
  /** Key prefix. Default: 'arcis:rl:' */
  prefix?: string;
  /** Window size in milliseconds. Default: 60000 */
  windowMs?: number;
}

/**
 * Redis rate limit store for distributed deployments.
 * 
 * @example
 * import Redis from 'ioredis';
 * 
 * const redis = new Redis();
 * const store = new RedisStore({ client: redis });
 * const limiter = createRateLimiter({ store });
 * 
 * // Cleanup on shutdown
 * process.on('SIGTERM', async () => {
 *   await store.close();
 * });
 */
export class RedisStore implements RateLimitStore {
  private client: RedisClientLike;
  private prefix: string;
  private windowMs: number;
  private windowSec: number;

  constructor(options: RedisStoreOptions) {
    this.client = options.client;
    this.prefix = options.prefix ?? 'arcis:rl:';
    this.windowMs = options.windowMs ?? RATE_LIMIT.DEFAULT_WINDOW_MS;
    this.windowSec = Math.ceil(this.windowMs / 1000);
  }

  private getKey(key: string): string {
    return `${this.prefix}${key}`;
  }

  async get(key: string): Promise<RateLimitEntry | null> {
    const redisKey = this.getKey(key);
    
    const [countStr, ttl] = await Promise.all([
      this.client.get(redisKey),
      this.client.ttl(redisKey),
    ]);
    
    if (!countStr || ttl < 0) {
      return null;
    }
    
    const count = parseInt(countStr, 10);
    if (isNaN(count)) {
      // Corrupt value in Redis — treat as if key doesn't exist
      return null;
    }

    return {
      count,
      resetTime: Date.now() + (ttl * 1000),
    };
  }

  async set(key: string, entry: RateLimitEntry): Promise<void> {
    const redisKey = this.getKey(key);
    // Clamp to at least 1 second — Math.ceil can produce 0 or negative values
    // when entry.resetTime is in the past due to Redis latency or clock skew.
    const ttlSec = Math.max(1, Math.ceil((entry.resetTime - Date.now()) / 1000));
    await this.client.setex(redisKey, ttlSec, entry.count.toString());
  }

  async increment(key: string): Promise<number> {
    const redisKey = this.getKey(key);

    // SECURITY / RELIABILITY: Atomic first-increment via SET ... EX ... NX.
    // If the key did not exist, this single command creates it with value
    // 1 and the window TTL atomically. If it existed, SET returns null
    // and we fall through to INCR for the actual count. This eliminates
    // the INCR-then-EXPIRE race where a connection drop between the two
    // commands could leave a counter without a TTL, locking out the
    // client until manual intervention.
    const created = await this.client.set(redisKey, '1', 'EX', this.windowSec, 'NX');
    if (created === 'OK' || created === true) {
      return 1;
    }
    return this.client.incr(redisKey);
  }

  async decrement(key: string): Promise<void> {
    const redisKey = this.getKey(key);
    await this.client.decr(redisKey);
  }

  async reset(key: string): Promise<void> {
    const redisKey = this.getKey(key);
    await this.client.del(redisKey);
  }

  async close(): Promise<void> {
    // Don't close the client - it may be shared
    // The caller should manage the client lifecycle
  }
}

/**
 * Create a Redis store with the given options.
 * Convenience function for functional programming style.
 * 
 * @example
 * const store = createRedisStore({ client: redisClient });
 */
export function createRedisStore(options: RedisStoreOptions): RedisStore {
  return new RedisStore(options);
}
