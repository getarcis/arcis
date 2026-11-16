/**
 * Rate-limit store contract, failure handling, validation and client-key
 * wiring (spec/API_SPEC.md, "Store contract and counting" and "Client IP
 * resolution").
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { createRateLimiter } from '../../src/middleware/rate-limit';
import { createSlidingWindowLimiter } from '../../src/middleware/rate-limit-sliding';
import { createTokenBucketLimiter } from '../../src/middleware/rate-limit-token';
import { createTelemetryEmitter } from '../../src/middleware/telemetry';
import { protectLogin } from '../../src/middleware/protect';
import { CorrelationWindow } from '../../src/middleware/correlation';
import { arcis } from '../../src/middleware/main';
import { buildAdapterLimiter } from '../../src/middleware/rate-limit-shared';
import { _resetClientIpWarnings } from '../../src/utils/client-ip';
import type { LegacyRateLimitStore, RateLimitStore, RateLimitEntry } from '../../src/core/types';
import type { TelemetryClient } from '../../src/telemetry/client';
import type { TelemetryEvent } from '../../src/telemetry/types';

interface Outcome {
  status: number;
  headers: Record<string, string>;
}

function fakeReq(peer: string, headers: Record<string, string> = {}): Request {
  return { headers, socket: { remoteAddress: peer }, method: 'GET', path: '/', url: '/', body: {} } as unknown as Request;
}

/** Run one Express-style handler and report the status it produced. */
async function run(
  handler: (req: Request, res: Response, next: NextFunction) => unknown,
  req: Request,
): Promise<Outcome> {
  const out: Outcome = { status: 200, headers: {} };
  const res = {
    setHeader: (name: string, value: string) => {
      out.headers[name] = value;
      return res;
    },
    status: (code: number) => {
      out.status = code;
      return res;
    },
    json: () => res,
    on: () => res,
  } as unknown as Response;
  await handler(req, res, (() => undefined) as NextFunction);
  return out;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  _resetClientIpWarnings();
});

describe('store contract', () => {
  it('makes exactly one increment per counted request and none for skipped ones', async () => {
    const calls: Array<[string, number]> = [];
    let hits = 0;
    const store: RateLimitStore = {
      increment: async (key, windowMs) => {
        calls.push([key, windowMs]);
        hits += 1;
        return { totalHits: hits, resetTime: Date.now() + windowMs };
      },
      decrement: vi.fn(async () => undefined),
      resetKey: vi.fn(async () => undefined),
      get: vi.fn(async () => null),
    };
    const limiter = createRateLimiter({ max: 2, windowMs: 30_000, store, skip: (req) => req.headers['x-skip'] === '1' });
    const statuses: number[] = [];
    for (let i = 0; i < 3; i++) statuses.push((await run(limiter, fakeReq('203.0.113.1'))).status);
    await run(limiter, fakeReq('203.0.113.1', { 'x-skip': '1' }));

    expect(statuses).toEqual([200, 200, 429]);
    expect(calls).toEqual([
      ['203.0.113.1', 30_000],
      ['203.0.113.1', 30_000],
      ['203.0.113.1', 30_000],
    ]);
    expect(store.get).not.toHaveBeenCalled();
  });

  it('keeps a legacy get/set store working and warns once that it is not atomic', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const data = new Map<string, RateLimitEntry>();
    const legacy: LegacyRateLimitStore = {
      get: async (key) => data.get(key) ?? null,
      set: async (key, entry) => void data.set(key, { ...entry }),
      increment: async (key) => {
        const entry = data.get(key)!;
        entry.count += 1;
        return entry.count;
      },
    };
    const a = createRateLimiter({ max: 2, store: legacy });
    const b = createRateLimiter({ max: 2, store: legacy });
    const statuses = [
      (await run(a, fakeReq('203.0.113.2'))).status,
      (await run(b, fakeReq('203.0.113.2'))).status,
      (await run(a, fakeReq('203.0.113.2'))).status,
    ];
    expect(statuses).toEqual([200, 200, 429]);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain('not atomic');
  });
});

describe('store errors', () => {
  const failingStore = (): RateLimitStore => ({
    increment: () => Promise.reject(new Error('redis down')),
    decrement: () => Promise.reject(new Error('redis down')),
    resetKey: () => Promise.reject(new Error('redis down')),
  });

  it('fails open into the in-memory counter and reports at most once per window', async () => {
    vi.useFakeTimers();
    const onError = vi.fn();
    const limiter = createRateLimiter({ max: 3, windowMs: 10_000, store: failingStore(), onError });
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) statuses.push((await run(limiter, fakeReq('203.0.113.3'))).status);

    // Still limited by the fallback, so an outage is not a bypass.
    expect(statuses).toEqual([200, 200, 200, 429, 429]);
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0][0]).toBeInstanceOf(Error);

    vi.advanceTimersByTime(10_000);
    await run(limiter, fakeReq('203.0.113.3'));
    await run(limiter, fakeReq('203.0.113.3'));
    expect(onError).toHaveBeenCalledTimes(2);
  });

  it('logs one console.error per window without an onError callback', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const limiter = createRateLimiter({ max: 100, windowMs: 60_000, store: failingStore() });
    for (let i = 0; i < 20; i++) await run(limiter, fakeReq(`203.0.113.${i}`));
    expect(error).toHaveBeenCalledTimes(1);
  });

  it('routes store errors to the telemetry error hook inside arcis()', async () => {
    const telemetryError = vi.fn();
    const stack = arcis({
      bot: false,
      sanitize: false,
      headers: false,
      scannerPaths: false,
      rateLimit: { store: failingStore() },
      telemetry: { endpoint: 'http://127.0.0.1:9/v1/events', onError: telemetryError, flushIntervalMs: 60_000 },
    });
    try {
      for (const handler of stack) {
        await run(handler, fakeReq('203.0.113.9'));
      }
      expect(telemetryError.mock.calls.some(([e]) => String(e).includes('redis down'))).toBe(true);
    } finally {
      stack.close();
    }
  });
});

describe('construction-time validation', () => {
  it.each([0, -1, 1.5, 2 ** 31, Number.NaN, Infinity, '60000'])('rejects windowMs %s', (windowMs) => {
    expect(() => createRateLimiter({ windowMs: windowMs as number })).toThrow(RangeError);
    expect(() => buildAdapterLimiter({ windowMs: windowMs as number }, 'adapter')).toThrow(RangeError);
    expect(() => createSlidingWindowLimiter({ window: windowMs as number })).toThrow();
  });

  it.each([-1, 1.5, Number.NaN, '5'])('rejects max %s', (max) => {
    expect(() => createRateLimiter({ max: max as number })).toThrow(RangeError);
    expect(() => buildAdapterLimiter({ max: max as number }, 'adapter')).toThrow(RangeError);
    expect(() => createSlidingWindowLimiter({ max: max as number })).toThrow(RangeError);
  });

  it('accepts the boundaries 1 and 2^31-1', () => {
    createRateLimiter({ windowMs: 1 }).close();
    createRateLimiter({ windowMs: 2 ** 31 - 1 }).close();
  });

  it('rejects an invalid ipv6Subnet or trustedProxies entry', () => {
    expect(() => createRateLimiter({ ipv6Subnet: 0 })).toThrow(RangeError);
    expect(() => createRateLimiter({ trustedProxies: ['10.0.0.0/40'] })).toThrow(TypeError);
    expect(() => arcis({ trustedProxies: ['nope'] })).toThrow(TypeError);
  });

  it('max 0 blocks every request', async () => {
    const limiter = createRateLimiter({ max: 0 });
    expect((await run(limiter, fakeReq('203.0.113.4'))).status).toBe(429);
    const adapter = buildAdapterLimiter({ max: 0 }, 'adapter');
    expect(adapter.check('k').allowed).toBe(false);
  });
});

describe('sliding window', () => {
  it('ignores a previous window that is not the immediately preceding one', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(10_000);
    const limiter = createSlidingWindowLimiter({ max: 3, window: 1_000 });
    for (let i = 0; i < 3; i++) await run(limiter, fakeReq('203.0.113.5'));

    // Idle through the whole next window, then come back.
    vi.setSystemTime(12_035);
    expect((await run(limiter, fakeReq('203.0.113.5'))).status).toBe(200);
    limiter.close();
  });

  it('still weights the immediately preceding window', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(10_000);
    const limiter = createSlidingWindowLimiter({ max: 3, window: 1_000 });
    for (let i = 0; i < 3; i++) await run(limiter, fakeReq('203.0.113.6'));

    vi.setSystemTime(11_035);
    expect((await run(limiter, fakeReq('203.0.113.6'))).status).toBe(429);
    limiter.close();
  });
});

describe('client keys', () => {
  it('core limiter: a public peer cannot rotate X-Forwarded-For, IPv6 groups by /56', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const limiter = createRateLimiter({ max: 1 });
    expect((await run(limiter, fakeReq('203.0.113.7', { 'x-forwarded-for': '1.1.1.1' }))).status).toBe(200);
    expect((await run(limiter, fakeReq('203.0.113.7', { 'x-forwarded-for': '2.2.2.2' }))).status).toBe(429);

    expect((await run(limiter, fakeReq('2001:db8:1:100::1'))).status).toBe(200);
    expect((await run(limiter, fakeReq('2001:db8:1:1ff:abcd::2'))).status).toBe(429);
    expect((await run(limiter, fakeReq('2001:db8:1:200::1'))).status).toBe(200);
  });

  it('sliding and token bucket limiters use the resolver', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const sliding = createSlidingWindowLimiter({ max: 1 });
    const token = createTokenBucketLimiter({ capacity: 1, refillRate: 0.001 });
    for (const limiter of [sliding, token]) {
      expect((await run(limiter, fakeReq('203.0.113.8', { 'x-forwarded-for': '1.1.1.1' }))).status).toBe(200);
      expect((await run(limiter, fakeReq('203.0.113.8', { 'x-forwarded-for': '2.2.2.2' }))).status).toBe(429);
      limiter.close();
    }
  });

  it('correlation tracking records the resolved client, not a forwarded header', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const window = new CorrelationWindow();
    const record = vi.spyOn(window, 'record');
    const stack = protectLogin({ rateLimit: false, bot: false, csrf: false, sanitize: false, correlation: { window } });
    await run(stack[0], fakeReq('203.0.113.10', { 'x-forwarded-for': '1.1.1.1' }));
    await run(stack[0], fakeReq('10.0.0.5', { 'x-forwarded-for': '198.51.100.20' }));
    expect(record.mock.calls.map((c) => c[0])).toEqual(['203.0.113.10', '198.51.100.20']);
  });

  it('telemetry ip comes from the resolver', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const events: TelemetryEvent[] = [];
    const client = { record: (e: TelemetryEvent) => events.push(e) } as unknown as TelemetryClient;
    const emitter = createTelemetryEmitter(client);
    const listeners: Array<() => void> = [];
    const res = { statusCode: 200, on: (_: string, fn: () => void) => listeners.push(fn) } as unknown as Response;
    emitter(fakeReq('203.0.113.11', { 'x-forwarded-for': '1.1.1.1' }), res, () => undefined);
    listeners.forEach((fn) => fn());
    expect(events[0].ip).toBe('203.0.113.11');
  });
});
