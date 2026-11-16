/**
 * RedisStore against a real Redis (REDIS_URL, e.g. redis://localhost:6379/0).
 *
 * Every key lives under `arcis-node-test:<run id>:` and is deleted with
 * SCAN + DEL afterwards. The database is never flushed: other suites may
 * share it.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import Redis from 'ioredis';
import { RedisStore } from '../../src/stores/redis';
import { createRateLimiter } from '../../src/middleware/rate-limit';

const REDIS_URL = process.env.REDIS_URL;
const RUN_PREFIX = `arcis-node-test:${process.pid}:${Date.now().toString(36)}:`;

const suiteName = REDIS_URL
  ? `RedisStore (real Redis at REDIS_URL)`
  : 'RedisStore (skipped: set REDIS_URL, e.g. redis://localhost:6379/0, to run against a real Redis)';

describe.skipIf(!REDIS_URL)(suiteName, () => {
  const clients: Redis[] = [];
  const client = (): Redis => {
    const c = new Redis(REDIS_URL as string, { lazyConnect: false, maxRetriesPerRequest: 1 });
    clients.push(c);
    return c;
  };
  let admin: Redis;
  let testNo = 0;
  const prefix = (): string => `${RUN_PREFIX}${++testNo}:`;

  beforeAll(() => {
    admin = client();
  });

  afterAll(async () => {
    let cursor = '0';
    do {
      const [next, keys] = await admin.scan(cursor, 'MATCH', `${RUN_PREFIX}*`, 'COUNT', 500);
      cursor = next;
      if (keys.length > 0) await admin.del(...keys);
    } while (cursor !== '0');
    await Promise.all(clients.map((c) => c.quit()));
  });

  it('increments atomically and sets the expiry on the first hit', async () => {
    const p = prefix();
    const store = new RedisStore({ client: client(), prefix: p });
    const before = Date.now();
    const first = await store.increment('k', 60_000);
    const second = await store.increment('k', 60_000);
    expect(first.totalHits).toBe(1);
    expect(second.totalHits).toBe(2);
    expect(first.resetTime).toBeGreaterThanOrEqual(before + 59_000);
    expect(first.resetTime).toBeLessThanOrEqual(Date.now() + 60_000);
    const pttl = await admin.pttl(`${p}k`);
    expect(pttl).toBeGreaterThan(59_000);
    expect(pttl).toBeLessThanOrEqual(60_000);
  });

  it('starts a new window after the key expires', async () => {
    const store = new RedisStore({ client: client(), prefix: prefix() });
    await store.increment('k', 50);
    await store.increment('k', 50);
    await new Promise((r) => setTimeout(r, 120));
    expect((await store.increment('k', 50)).totalHits).toBe(1);
  });

  it('repairs a counter that has no TTL instead of locking the client out', async () => {
    const p = prefix();
    await admin.set(`${p}k`, '7');
    const store = new RedisStore({ client: client(), prefix: p });
    expect((await store.increment('k', 60_000)).totalHits).toBe(8);
    expect(await admin.pttl(`${p}k`)).toBeGreaterThan(0);
  });

  it('get, decrement (floored at 0) and resetKey', async () => {
    const store = new RedisStore({ client: client(), prefix: prefix() });
    expect(await store.get('k')).toBeNull();
    await store.increment('k', 60_000);
    await store.increment('k', 60_000);
    expect((await store.get('k'))?.totalHits).toBe(2);
    await store.decrement('k');
    await store.decrement('k');
    await store.decrement('k');
    expect((await store.get('k'))?.totalHits).toBe(0);
    await store.resetKey('k');
    expect(await store.get('k')).toBeNull();
  });

  it('50 concurrent requests across 5 limiter instances with max 5 admit exactly 5', async () => {
    const p = prefix();
    // Five instances, each with its own connection, as five app processes would.
    const limiters = Array.from({ length: 5 }, () =>
      createRateLimiter({ max: 5, windowMs: 60_000, store: new RedisStore({ client: client(), prefix: p }) }),
    );
    const outcomes = await Promise.all(
      Array.from({ length: 50 }, (_, i) => {
        const limiter = limiters[i % limiters.length];
        const req = { headers: {}, socket: { remoteAddress: '203.0.113.50' } } as unknown as Request;
        let status = 200;
        const res = {
          setHeader: () => res,
          status: (code: number) => {
            status = code;
            return res;
          },
          json: () => res,
        } as unknown as Response;
        return new Promise<number>((resolve) => {
          const next = (() => resolve(200)) as NextFunction;
          void Promise.resolve(limiter(req, res, next)).then(() => {
            if (status !== 200) resolve(status);
          });
        });
      }),
    );
    const allowed = outcomes.filter((s) => s === 200).length;
    const denied = outcomes.filter((s) => s === 429).length;
    // Reported by the verification run: exactly `max` admitted.
    console.log(`[redis concurrency] allowed=${allowed} denied=${denied} of ${outcomes.length}`);
    expect(allowed).toBe(5);
    expect(denied).toBe(45);
    expect(await admin.get(`${p}203.0.113.50`)).toBe('50');
  });

  it('never hands out a duplicate count under concurrent bursts', async () => {
    const p = prefix();
    const store = new RedisStore({ client: client(), prefix: p });
    let totalAllowed = 0;
    for (let burst = 0; burst < 3; burst++) {
      const results = await Promise.all(
        Array.from({ length: 20 }, () => store.increment('burst', 60_000)),
      );
      totalAllowed += results.filter((r) => r.totalHits <= 10).length;
      expect(new Set(results.map((r) => r.totalHits)).size).toBe(20); // no duplicate counts
    }
    expect(totalAllowed).toBe(10);
  });
});
