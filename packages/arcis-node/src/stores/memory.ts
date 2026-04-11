/**
 * @module @arcis/node/stores/memory
 * In-memory rate limit store
 */

import type { RateLimitStore, RateLimitEntry } from '../core/types';
import { RATE_LIMIT } from '../core/constants';

/**
 * In-memory rate limit store.
 * Suitable for single-instance deployments.
 * For distributed systems, use RedisStore or a custom store.
 * 
 * @example
 * const store = new MemoryStore(60000); // 1 minute window
 * const limiter = createRateLimiter({ store });
 */
/** Default maximum number of keys the in-memory store will hold. */
const DEFAULT_MAX_SIZE = 10_000;

export class MemoryStore implements RateLimitStore {
  private store: Map<string, RateLimitEntry> = new Map();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;
  private windowMs: number;
  private maxSize: number;

  constructor(windowMs: number = RATE_LIMIT.DEFAULT_WINDOW_MS, maxSize: number = DEFAULT_MAX_SIZE) {
    if (!Number.isFinite(windowMs) || windowMs < RATE_LIMIT.MIN_WINDOW_MS) {
      throw new RangeError(
        `MemoryStore: windowMs must be a finite number >= ${RATE_LIMIT.MIN_WINDOW_MS} (got ${windowMs})`
      );
    }
    if (!Number.isFinite(maxSize) || maxSize < 1) {
      throw new RangeError(`MemoryStore: maxSize must be >= 1 (got ${maxSize})`);
    }
    this.windowMs = windowMs;
    this.maxSize = maxSize;
    this.startCleanup();
  }

  /**
   * Start the cleanup interval to remove expired entries.
   */
  private startCleanup(): void {
    // Clamp the cleanup interval between 30 s and 5 min regardless of windowMs.
    // Running it every windowMs is fine for typical windows but would fire every
    // second for short windows (e.g. windowMs: 1000), causing O(n) GC pressure.
    const CLEANUP_MIN_MS = 30_000;
    const CLEANUP_MAX_MS = 300_000;
    const cleanupMs = Math.min(Math.max(this.windowMs, CLEANUP_MIN_MS), CLEANUP_MAX_MS);

    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [key, entry] of this.store.entries()) {
        if (entry.resetTime < now) {
          this.store.delete(key);
        }
      }
    }, cleanupMs);

    // Prevent interval from keeping the process alive
    if (typeof this.cleanupInterval.unref === 'function') {
      this.cleanupInterval.unref();
    }
  }

  async get(key: string): Promise<RateLimitEntry | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    
    // Check if expired
    if (entry.resetTime < Date.now()) {
      this.store.delete(key);
      return null;
    }
    
    return entry;
  }

  async set(key: string, entry: RateLimitEntry): Promise<void> {
    if (!this.store.has(key) && this.store.size >= this.maxSize) {
      this.evictExpired();
      // If still at capacity after eviction, fail open — don't crash the app
      if (this.store.size >= this.maxSize) return;
    }
    this.store.set(key, entry);
  }

  async increment(key: string): Promise<number> {
    const now = Date.now();
    const entry = this.store.get(key);

    if (!entry || entry.resetTime < now) {
      // Start new window — check capacity first
      if (this.store.size >= this.maxSize) {
        this.evictExpired();
        if (this.store.size >= this.maxSize) return 1; // fail open
      }
      this.store.set(key, { count: 1, resetTime: now + this.windowMs });
      return 1;
    }

    entry.count++;
    return entry.count;
  }

  /** Eagerly remove expired entries to reclaim capacity. */
  private evictExpired(): void {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (entry.resetTime < now) this.store.delete(key);
    }
  }

  async decrement(key: string): Promise<void> {
    const entry = this.store.get(key);
    if (entry && entry.count > 0) {
      entry.count--;
    }
  }

  async reset(key: string): Promise<void> {
    this.store.delete(key);
  }

  async close(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.store.clear();
  }

  /**
   * Get current store size (for monitoring).
   */
  get size(): number {
    return this.store.size;
  }
}
