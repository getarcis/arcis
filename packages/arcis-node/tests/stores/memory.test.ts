/**
 * MemoryStore Tests
 * Tests for src/stores/memory.ts (atomic store contract) and the bounded
 * fixed-window counter behind it.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { MemoryStore } from '../../src/stores/memory';
import { FixedWindowCounter } from '../../src/stores/fixed-window';
import { RATE_LIMIT } from '../../src/core/constants';

describe('MemoryStore', () => {
  let store: MemoryStore;

  afterEach(async () => {
    vi.useRealTimers();
    await store?.close();
  });

  describe('Constructor', () => {
    it('creates a store with the default window', () => {
      store = new MemoryStore();
      expect(store.size).toBe(0);
    });

    it('creates a store with a custom window', () => {
      store = new MemoryStore(30000);
      expect(store).toBeDefined();
    });

    it('rejects invalid windows and sizes', () => {
      expect(() => new MemoryStore(0)).toThrow(RangeError);
      expect(() => new MemoryStore(1.5)).toThrow(RangeError);
      expect(() => new MemoryStore(2 ** 31)).toThrow(RangeError);
      expect(() => new MemoryStore(60_000, 0)).toThrow(RangeError);
      store = new MemoryStore(1); // the smallest valid window
    });
  });

  describe('increment', () => {
    it('starts a window at 1 with resetTime = now + windowMs', async () => {
      store = new MemoryStore();
      const before = Date.now();
      const hit = await store.increment('k', 60_000);
      expect(hit.totalHits).toBe(1);
      expect(hit.resetTime).toBeGreaterThanOrEqual(before + 60_000);
      expect(hit.resetTime).toBeLessThanOrEqual(Date.now() + 60_000);
    });

    it('counts hits and keeps the window reset time', async () => {
      store = new MemoryStore();
      const first = await store.increment('k', 60_000);
      const second = await store.increment('k', 60_000);
      const third = await store.increment('k', 60_000);
      expect([first.totalHits, second.totalHits, third.totalHits]).toEqual([1, 2, 3]);
      expect(third.resetTime).toBe(first.resetTime);
    });

    it('starts a new window once the old one expires', async () => {
      vi.useFakeTimers();
      store = new MemoryStore();
      await store.increment('k', 1_000);
      await store.increment('k', 1_000);
      vi.advanceTimersByTime(1_000);
      expect((await store.increment('k', 1_000)).totalHits).toBe(1);
    });

    it('honors the per-call window', async () => {
      store = new MemoryStore(60_000);
      const now = Date.now();
      const hit = await store.increment('k', 5_000);
      expect(hit.resetTime - now).toBeLessThanOrEqual(5_000 + 50);
    });
  });

  describe('get / decrement / resetKey', () => {
    it('get returns the live window or null', async () => {
      store = new MemoryStore();
      expect(await store.get('k')).toBeNull();
      const hit = await store.increment('k', 60_000);
      expect(await store.get('k')).toEqual(hit);
    });

    it('get returns null for an expired window', async () => {
      vi.useFakeTimers();
      store = new MemoryStore();
      await store.increment('k', 1_000);
      vi.advanceTimersByTime(1_000);
      expect(await store.get('k')).toBeNull();
    });

    it('decrement removes one hit and floors at 0', async () => {
      store = new MemoryStore();
      await store.increment('k', 60_000);
      await store.increment('k', 60_000);
      await store.decrement('k');
      expect((await store.get('k'))?.totalHits).toBe(1);
      await store.decrement('k');
      await store.decrement('k');
      expect((await store.get('k'))?.totalHits).toBe(0);
      await store.decrement('missing');
      expect(store.size).toBe(1);
    });

    it('resetKey forgets the key', async () => {
      store = new MemoryStore();
      await store.increment('k', 60_000);
      await store.resetKey('k');
      expect(await store.get('k')).toBeNull();
      await store.resetKey('missing');
    });
  });

  describe('close', () => {
    it('clears every key and is idempotent', async () => {
      store = new MemoryStore();
      await store.increment('a', 60_000);
      await store.increment('b', 60_000);
      await store.close();
      expect(store.size).toBe(0);
      await store.close();
    });
  });

  describe('Cleanup', () => {
    it('sweeps expired entries on the idle timer', async () => {
      vi.useFakeTimers();
      store = new MemoryStore(1_000);
      await store.increment('short', 500);
      await store.increment('long', 120_000);
      expect(store.size).toBe(2);
      vi.advanceTimersByTime(30_000);
      expect(store.size).toBe(1);
      expect(await store.get('long')).not.toBeNull();
    });
  });

  describe('Size cap', () => {
    it('keeps limiting new keys at the cap by evicting the least recently used', async () => {
      store = new MemoryStore(60_000, 3);
      await store.increment('a', 60_000);
      await store.increment('b', 60_000);
      await store.increment('c', 60_000);
      await store.increment('a', 60_000); // a is now most recently used
      const d1 = await store.increment('d', 60_000);
      const d2 = await store.increment('d', 60_000);
      expect(store.size).toBe(3);
      expect(d1.totalHits).toBe(1);
      expect(d2.totalHits).toBe(2); // the new key is counted, not failed open
      expect(await store.get('b')).toBeNull(); // b was least recently used
      expect((await store.get('a'))?.totalHits).toBe(2);
    });

    it('evicts expired keys before live ones', async () => {
      vi.useFakeTimers();
      store = new MemoryStore(60_000, 2);
      await store.increment('expiring', 1_000);
      await store.increment('live', 60_000);
      await store.increment('live', 60_000); // expiring is now the least recently used...
      await store.increment('expiring', 1_000); // ...until this hit
      vi.advanceTimersByTime(2_000);
      await store.increment('new', 60_000);
      expect(await store.get('live')).not.toBeNull();
      expect(store.size).toBe(2);
    });
  });

  describe('RateLimitStore interface', () => {
    it('implements the atomic contract', () => {
      store = new MemoryStore(RATE_LIMIT.DEFAULT_WINDOW_MS);
      expect(typeof store.increment).toBe('function');
      expect(typeof store.decrement).toBe('function');
      expect(typeof store.resetKey).toBe('function');
      expect(typeof store.get).toBe('function');
      expect(typeof store.close).toBe('function');
    });

    it('counts concurrent increments exactly', async () => {
      store = new MemoryStore();
      const results = await Promise.all(
        Array.from({ length: 10 }, () => store.increment('concurrent', 60_000)),
      );
      expect(results.map((r) => r.totalHits).sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    });

    it('handles long, special-character and empty keys', async () => {
      store = new MemoryStore();
      for (const key of ['a'.repeat(1000), 'user:123:ip:192.168.1.1', '', '__proto__']) {
        expect((await store.increment(key, 60_000)).totalHits).toBe(1);
      }
    });
  });
});

describe('FixedWindowCounter', () => {
  it('never fails open at the cap: a flood of new keys still gets limited', () => {
    const counter = new FixedWindowCounter(100);
    const now = Date.now();
    for (let i = 0; i < 1000; i++) counter.increment(`flood-${i}`, 60_000, now);
    expect(counter.size).toBe(100);
    // A client hammering one key is still counted.
    let last = 0;
    for (let i = 0; i < 5; i++) {
      counter.increment(`flood-${2000 + i}`, 60_000, now);
      last = counter.increment('victim', 60_000, now).totalHits;
    }
    expect(last).toBe(5);
  });

  it('sweeps expired keys lazily on access', () => {
    const counter = new FixedWindowCounter();
    const t0 = 1_000_000;
    counter.increment('a', 1_000, t0);
    counter.increment('b', 1_000, t0);
    counter.increment('c', 60_000, t0 + 10_000); // past the sweep interval
    expect(counter.size).toBe(1);
  });
});
