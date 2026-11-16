/**
 * @module @arcis/node/stores/memory
 * In-memory rate limit store
 */

import type { RateLimitStore, RateLimitIncrement } from '../core/types';
import { RATE_LIMIT } from '../core/constants';
import { FixedWindowCounter, DEFAULT_MAX_KEYS } from './fixed-window';
import { validateWindowMs } from '../core/rate-limit-config';

/**
 * In-memory rate limit store implementing the atomic store contract.
 * Suitable for single-instance deployments; for several instances use
 * RedisStore or another shared store.
 *
 * At `maxSize` keys it evicts expired keys first, then the least recently
 * used, so it never stops limiting new keys.
 *
 * @example
 * const store = new MemoryStore();
 * const limiter = createRateLimiter({ store });
 */
export class MemoryStore implements RateLimitStore {
  private readonly counter: FixedWindowCounter;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  /**
   * @param windowMs - Sets the idle cleanup cadence (clamped to 30 s - 5 min).
   *   Each `increment` call passes its own window. Default: 60000
   * @param maxSize - Maximum number of keys held. Default: 10000
   */
  constructor(windowMs: number = RATE_LIMIT.DEFAULT_WINDOW_MS, maxSize: number = DEFAULT_MAX_KEYS) {
    validateWindowMs(windowMs, 'MemoryStore');
    if (!Number.isInteger(maxSize) || maxSize < 1) {
      throw new RangeError(`MemoryStore: maxSize must be an integer >= 1 (got ${maxSize})`);
    }
    this.counter = new FixedWindowCounter(maxSize);

    // Reclaim memory while idle. Hits also sweep lazily, so this only matters
    // when traffic stops.
    const cleanupMs = Math.min(Math.max(windowMs, 30_000), 300_000);
    this.cleanupInterval = setInterval(() => this.counter.sweep(), cleanupMs);
    if (typeof this.cleanupInterval.unref === 'function') {
      this.cleanupInterval.unref();
    }
  }

  /** Count one hit for `key` in a window of `windowMs`. */
  async increment(key: string, windowMs: number): Promise<RateLimitIncrement> {
    return this.counter.increment(key, windowMs);
  }

  /** Remove one hit from `key`, floored at 0. */
  async decrement(key: string): Promise<void> {
    this.counter.decrement(key);
  }

  /** Forget `key`. */
  async resetKey(key: string): Promise<void> {
    this.counter.delete(key);
  }

  /** Current window state for `key`, or `null` when it has no live window. */
  async get(key: string): Promise<RateLimitIncrement | null> {
    return this.counter.get(key);
  }

  /** Stop the cleanup timer and drop every key. */
  async close(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.counter.clear();
  }

  /** Current number of keys (for monitoring). */
  get size(): number {
    return this.counter.size;
  }
}
