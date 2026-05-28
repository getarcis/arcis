/**
 * Brute-force middleware tests.
 *
 * Verifies the bursty (slow + fast window + block) behavior end-to-end
 * against a fresh middleware instance per test to avoid cross-test
 * counter bleed.
 */

import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { bruteForceProtection } from '../../src/middleware/brute-force';
import { MemoryLimiter, BurstyLimiter, LimiterResult } from '../../src/_third_party/rate-limit';
import { mockRequest, mockResponse } from '../setup';

function freshNext(): ReturnType<typeof vi.fn> {
  return vi.fn();
}

describe('bruteForceProtection', () => {
  it('allows requests under the fast limit', async () => {
    const mw = bruteForceProtection({ fastPoints: 3, fastDuration: 60, slowPoints: 50 });
    const next = freshNext();
    const req = mockRequest({ ip: '10.0.0.1' }) as Request;
    const res = mockResponse() as Response;
    await mw(req, res, next as NextFunction);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalledWith(429);
  });

  it('blocks requests over the fast limit', async () => {
    const mw = bruteForceProtection({
      fastPoints: 2,
      fastDuration: 60,
      slowPoints: 100,
      slowDuration: 900,
    });
    const ip = '10.0.0.2';
    // first 2 succeed
    for (let i = 0; i < 2; i++) {
      const next = freshNext();
      await mw(mockRequest({ ip }) as Request, mockResponse() as Response, next as NextFunction);
      expect(next).toHaveBeenCalled();
    }
    // 3rd hits the fast limit
    const next3 = freshNext();
    const res3 = mockResponse();
    await mw(mockRequest({ ip }) as Request, res3 as Response, next3 as NextFunction);
    expect(next3).not.toHaveBeenCalled();
    expect(res3.status).toHaveBeenCalledWith(429);
    expect(res3.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.any(String), retryAfter: expect.any(Number) }),
    );
  });

  it('trips the slow-window block after enough sustained hits', async () => {
    const mw = bruteForceProtection({
      fastPoints: 100,
      fastDuration: 60,
      slowPoints: 3,
      slowDuration: 900,
      blockDuration: 900,
    });
    const ip = '10.0.0.3';
    // First 3 succeed (consume slow points 1, 2, 3 — none over yet).
    for (let i = 0; i < 3; i++) {
      const next = freshNext();
      await mw(mockRequest({ ip }) as Request, mockResponse() as Response, next as NextFunction);
      expect(next).toHaveBeenCalled();
    }
    // 4th consumes the 4th point — over the slow limit → block kicks in.
    const next4 = freshNext();
    const res4 = mockResponse();
    await mw(mockRequest({ ip }) as Request, res4 as Response, next4 as NextFunction);
    expect(next4).not.toHaveBeenCalled();
    expect(res4.status).toHaveBeenCalledWith(429);
  });

  it('exposes a controller for reward/delete after success', async () => {
    const mw = bruteForceProtection({ fastPoints: 2, slowPoints: 50 });
    const ip = '10.0.0.4';
    const req = mockRequest({ ip }) as Request;
    await mw(req, mockResponse() as Response, freshNext() as NextFunction);
    expect(req.arcisBruteForce).toBeDefined();
    const cleared = await req.arcisBruteForce!.delete(ip);
    expect(cleared).toBe(true);
  });

  it('supports custom keyGenerator (e.g. user id)', async () => {
    const mw = bruteForceProtection({
      fastPoints: 2,
      keyGenerator: (req: Request) => String((req.body as { userId?: string })?.userId ?? 'anon'),
    });
    // Different user ids should not collide.
    for (let i = 0; i < 2; i++) {
      const next = freshNext();
      await mw(
        mockRequest({ body: { userId: 'alice' } }) as Request,
        mockResponse() as Response,
        next as NextFunction,
      );
      expect(next).toHaveBeenCalled();
    }
    // bob still has 2 quota
    const next = freshNext();
    await mw(
      mockRequest({ body: { userId: 'bob' } }) as Request,
      mockResponse() as Response,
      next as NextFunction,
    );
    expect(next).toHaveBeenCalled();
  });

  it('respects skip predicate', async () => {
    const mw = bruteForceProtection({
      fastPoints: 1,
      skip: (req) => (req.headers['x-trusted'] as string | undefined) === 'true',
    });
    // First request is trusted — bypasses the limiter entirely.
    const next1 = freshNext();
    await mw(
      mockRequest({ ip: '10.0.0.5', headers: { 'x-trusted': 'true' } }) as Request,
      mockResponse() as Response,
      next1 as NextFunction,
    );
    expect(next1).toHaveBeenCalled();
    // Second trusted request also passes (no counter consumed).
    const next2 = freshNext();
    await mw(
      mockRequest({ ip: '10.0.0.5', headers: { 'x-trusted': 'true' } }) as Request,
      mockResponse() as Response,
      next2 as NextFunction,
    );
    expect(next2).toHaveBeenCalled();
  });

  it('writes X-RateLimit headers on allowed responses', async () => {
    const mw = bruteForceProtection({ fastPoints: 5, slowPoints: 50 });
    const req = mockRequest({ ip: '10.0.0.6' }) as Request;
    const res = mockResponse();
    await mw(req, res as Response, freshNext() as NextFunction);
    expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', expect.any(String));
    expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', expect.any(String));
    expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Reset', expect.any(String));
  });

  it('writes Retry-After header on blocked responses', async () => {
    const mw = bruteForceProtection({ fastPoints: 1, slowPoints: 50 });
    const ip = '10.0.0.7';
    await mw(mockRequest({ ip }) as Request, mockResponse() as Response, freshNext() as NextFunction);
    const res2 = mockResponse();
    await mw(mockRequest({ ip }) as Request, res2 as Response, freshNext() as NextFunction);
    expect(res2.setHeader).toHaveBeenCalledWith('Retry-After', expect.any(String));
  });
});

describe('MemoryLimiter (internal)', () => {
  it('consumes points and rejects past the limit', async () => {
    const limiter = new MemoryLimiter({ points: 2, duration: 60 });
    await expect(limiter.consume('key1', 1)).resolves.toBeDefined();
    await expect(limiter.consume('key1', 1)).resolves.toBeDefined();
    await expect(limiter.consume('key1', 1)).rejects.toBeInstanceOf(LimiterResult);
  });

  it('reward decreases the counter', async () => {
    const limiter = new MemoryLimiter({ points: 5, duration: 60 });
    await limiter.consume('k', 3);
    const res = await limiter.reward('k', 2);
    expect(res.consumedPoints).toBe(1);
  });

  it('block sets a semi-permanent block', async () => {
    const limiter = new MemoryLimiter({ points: 10, duration: 60 });
    const blocked = await limiter.block('k', 5);
    expect(blocked.consumedPoints).toBeGreaterThan(10);
    // Subsequent consume rejects.
    await expect(limiter.consume('k', 1)).rejects.toBeInstanceOf(LimiterResult);
  });
});

describe('BurstyLimiter (internal)', () => {
  it('falls through to burst limiter when steady rejects', async () => {
    const steady = new MemoryLimiter({ points: 1, duration: 60, keyPrefix: 'st' });
    const burst = new MemoryLimiter({ points: 3, duration: 60, keyPrefix: 'bu' });
    const bursty = new BurstyLimiter(steady, burst);

    // 1 steady point — first hit succeeds.
    await expect(bursty.consume('k', 1)).resolves.toBeDefined();
    // Steady is now exhausted, but burst has 3 — next 3 should succeed.
    await expect(bursty.consume('k', 1)).resolves.toBeDefined();
    await expect(bursty.consume('k', 1)).resolves.toBeDefined();
    await expect(bursty.consume('k', 1)).resolves.toBeDefined();
    // 5th hit: both exhausted — reject.
    await expect(bursty.consume('k', 1)).rejects.toBeDefined();
  });
});
