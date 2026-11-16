/**
 * @module @arcis/node/stores/fixed-window
 * Bounded in-memory fixed-window counter shared by MemoryStore, the core
 * limiter and every framework adapter.
 *
 * At the size cap it evicts expired keys first, then the least recently
 * used, so it never stops limiting new keys. Expired keys are swept lazily on
 * access, so no timer is needed (edge runtimes included).
 */

import type { RateLimitIncrement } from '../core/types';

/** Default maximum number of keys held in memory. */
export const DEFAULT_MAX_KEYS = 10_000;

/** Periodic expired-key sweep cadence. */
const SWEEP_INTERVAL_MS = 5_000;
/** Minimum gap between sweeps forced by reaching the size cap. */
const CAP_SWEEP_INTERVAL_MS = 1_000;

interface Entry {
  count: number;
  resetTime: number;
}

/** Synchronous fixed-window counter with a size cap and LRU eviction. */
export class FixedWindowCounter {
  // Map iteration order is insertion order; re-inserting on every hit keeps
  // the least recently used key first.
  private readonly entries = new Map<string, Entry>();
  private lastSweep = 0;

  /**
   * @param maxKeys - Size cap. Default: {@link DEFAULT_MAX_KEYS}
   */
  constructor(private readonly maxKeys: number = DEFAULT_MAX_KEYS) {}

  /** Count one hit for `key` and return the window state after it. */
  increment(key: string, windowMs: number, now: number = Date.now()): RateLimitIncrement {
    if (now - this.lastSweep >= SWEEP_INTERVAL_MS) this.sweep(now);
    const entry = this.entries.get(key);
    if (entry) this.entries.delete(key);

    if (entry && entry.resetTime > now) {
      entry.count += 1;
      this.entries.set(key, entry);
      return { totalHits: entry.count, resetTime: entry.resetTime };
    }

    if (!entry) this.makeRoom(now);
    const fresh: Entry = { count: 1, resetTime: now + windowMs };
    this.entries.set(key, fresh);
    return { totalHits: 1, resetTime: fresh.resetTime };
  }

  /** Remove one hit from `key`, floored at 0. */
  decrement(key: string): void {
    const entry = this.entries.get(key);
    if (entry && entry.count > 0) entry.count -= 1;
  }

  /** Forget `key`. */
  delete(key: string): void {
    this.entries.delete(key);
  }

  /** Current window state for `key`, or `null` when absent or expired. */
  get(key: string, now: number = Date.now()): RateLimitIncrement | null {
    const entry = this.entries.get(key);
    if (!entry || entry.resetTime <= now) return null;
    return { totalHits: entry.count, resetTime: entry.resetTime };
  }

  /** Drop every expired key. */
  sweep(now: number = Date.now()): void {
    this.lastSweep = now;
    for (const [key, entry] of this.entries) {
      if (entry.resetTime <= now) this.entries.delete(key);
    }
  }

  /** Drop every key. */
  clear(): void {
    this.entries.clear();
  }

  /** Number of keys currently held. */
  get size(): number {
    return this.entries.size;
  }

  private makeRoom(now: number): void {
    if (this.entries.size < this.maxKeys) return;
    if (now - this.lastSweep >= CAP_SWEEP_INTERVAL_MS) this.sweep(now);
    while (this.entries.size >= this.maxKeys) {
      const oldest = this.entries.keys().next();
      if (oldest.done) return;
      this.entries.delete(oldest.value);
    }
  }
}
