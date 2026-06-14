/**
 * Rate Limiter Middleware Tests
 * Tests for src/middleware/rate-limit.ts
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { Request, Response } from 'express';
import { createRateLimiter, rateLimit } from '../../src/middleware/rate-limit';
import { mockRequest, mockResponse, mockNext, createTestServer, TestServer } from '../setup';
import type { RateLimitStore } from '../../src/core/types';

describe('createRateLimiter', () => {
  let limiter: ReturnType<typeof createRateLimiter>;

  afterEach(() => {
    limiter?.close();
    vi.clearAllMocks();
  });

  describe('Basic Rate Limiting', () => {
    it('should allow requests under the limit', async () => {
      limiter = createRateLimiter({ max: 5, windowMs: 60000 });
      const req = mockRequest();
      const res = mockResponse();

      await limiter(req as Request, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalledWith(429);
    });

    it('should block requests over the limit', async () => {
      limiter = createRateLimiter({ max: 2, windowMs: 60000 });

      for (let i = 0; i < 3; i++) {
        const req = mockRequest({ ip: '192.168.1.1' });
        const res = mockResponse();
        vi.clearAllMocks();
        await limiter(req as Request, res as Response, mockNext);

        if (i < 2) {
          expect(mockNext).toHaveBeenCalled();
        } else {
          expect(res.status).toHaveBeenCalledWith(429);
          expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
            error: expect.any(String),
          }));
        }
      }
    });

    it('should return 429 status when rate limited', async () => {
      limiter = createRateLimiter({ max: 1, windowMs: 60000 });
      
      // First request
      await limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);
      
      // Second request (should be blocked)
      const req = mockRequest({ ip: '1.1.1.1' });
      const res = mockResponse();
      await limiter(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(429);
    });
  });

  describe('Fail-open on store errors', () => {
    // A store whose every operation rejects, simulating Redis being down.
    const throwingStore = (): RateLimitStore =>
      ({
        get: () => Promise.reject(new Error('redis down')),
        set: () => Promise.reject(new Error('redis down')),
        increment: () => Promise.reject(new Error('redis down')),
        reset: () => Promise.reject(new Error('redis down')),
      } as unknown as RateLimitStore);

    it('allows the request when the store throws (availability over denial)', async () => {
      const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      limiter = createRateLimiter({ max: 5, windowMs: 60000, store: throwingStore() });
      const req = mockRequest({ ip: '9.9.9.9' });
      const res = mockResponse();

      await limiter(req as Request, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalledWith(429);
      errSpy.mockRestore();
    });

    it('still enforces the limit via the in-memory fallback (not a pure bypass)', async () => {
      const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      limiter = createRateLimiter({ max: 1, windowMs: 60000, store: throwingStore() });
      // First request from this IP is allowed via the in-memory fallback.
      await limiter(mockRequest({ ip: '8.8.8.8' }) as Request, mockResponse() as Response, mockNext);
      // Second request from the same IP must be rate-limited by the fallback.
      const res = mockResponse();
      await limiter(mockRequest({ ip: '8.8.8.8' }) as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(429);
      errSpy.mockRestore();
    });
  });

  describe('Rate Limit Headers', () => {
    it('should set X-RateLimit-Limit header', async () => {
      limiter = createRateLimiter({ max: 100, windowMs: 60000 });
      const req = mockRequest();
      const res = mockResponse();

      await limiter(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', '100');
    });

    it('should set X-RateLimit-Remaining header', async () => {
      limiter = createRateLimiter({ max: 100, windowMs: 60000 });
      const req = mockRequest();
      const res = mockResponse();

      await limiter(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', expect.any(String));
    });

    it('should set X-RateLimit-Reset header', async () => {
      limiter = createRateLimiter({ max: 100, windowMs: 60000 });
      const req = mockRequest();
      const res = mockResponse();

      await limiter(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Reset', expect.any(String));
    });

    it('should set Retry-After header when blocked', async () => {
      limiter = createRateLimiter({ max: 1, windowMs: 60000 });
      
      // Exhaust limit
      await limiter(mockRequest({ ip: '2.2.2.2' }) as Request, mockResponse() as Response, mockNext);
      
      const req = mockRequest({ ip: '2.2.2.2' });
      const res = mockResponse();
      await limiter(req as Request, res as Response, mockNext);

      // Retry-After is set as a string (seconds until reset)
      expect(res.setHeader).toHaveBeenCalledWith('Retry-After', expect.anything());
    });
  });

  describe('Skip Function', () => {
    it('should skip rate limiting when skip returns true', async () => {
      limiter = createRateLimiter({
        max: 1,
        windowMs: 60000,
        skip: () => true,
      });

      // Make multiple requests - all should pass
      for (let i = 0; i < 5; i++) {
        const req = mockRequest({ ip: '3.3.3.3' });
        const res = mockResponse();
        vi.clearAllMocks();
        await limiter(req as Request, res as Response, mockNext);
        expect(mockNext).toHaveBeenCalled();
      }
    });

    it('should apply rate limiting when skip returns false', async () => {
      limiter = createRateLimiter({
        max: 1,
        windowMs: 60000,
        skip: () => false,
      });

      // First passes, second blocked
      await limiter(mockRequest({ ip: '4.4.4.4' }) as Request, mockResponse() as Response, mockNext);
      
      const res = mockResponse();
      await limiter(mockRequest({ ip: '4.4.4.4' }) as Request, res as Response, mockNext);
      expect(res.status).toHaveBeenCalledWith(429);
    });
  });

  describe('Custom Key Generator', () => {
    it('should use custom key generator', async () => {
      limiter = createRateLimiter({
        max: 2,
        windowMs: 60000,
        keyGenerator: (req) => req.headers['x-api-key'] as string || 'anonymous',
      });

      // User A makes 2 requests
      await limiter(mockRequest({ headers: { 'x-api-key': 'user-a' } }) as Request, mockResponse() as Response, mockNext);
      await limiter(mockRequest({ headers: { 'x-api-key': 'user-a' } }) as Request, mockResponse() as Response, mockNext);

      // User A is blocked
      const resA = mockResponse();
      await limiter(mockRequest({ headers: { 'x-api-key': 'user-a' } }) as Request, resA as Response, mockNext);
      expect(resA.status).toHaveBeenCalledWith(429);

      // User B can still make requests
      const resB = mockResponse();
      vi.clearAllMocks();
      await limiter(mockRequest({ headers: { 'x-api-key': 'user-b' } }) as Request, resB as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Custom Status Code', () => {
    it('should use custom status code when blocked', async () => {
      limiter = createRateLimiter({
        max: 1,
        windowMs: 60000,
        statusCode: 503,
      });

      await limiter(mockRequest({ ip: '5.5.5.5' }) as Request, mockResponse() as Response, mockNext);
      
      const res = mockResponse();
      await limiter(mockRequest({ ip: '5.5.5.5' }) as Request, res as Response, mockNext);
      expect(res.status).toHaveBeenCalledWith(503);
    });
  });

  describe('Custom Message', () => {
    it('should use custom error message', async () => {
      limiter = createRateLimiter({
        max: 1,
        windowMs: 60000,
        message: 'Custom rate limit message',
      });

      await limiter(mockRequest({ ip: '6.6.6.6' }) as Request, mockResponse() as Response, mockNext);
      
      const res = mockResponse();
      await limiter(mockRequest({ ip: '6.6.6.6' }) as Request, res as Response, mockNext);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        error: 'Custom rate limit message',
      }));
    });
  });

  describe('Cleanup', () => {
    it('should have close method', () => {
      limiter = createRateLimiter({ max: 100, windowMs: 60000 });
      expect(typeof limiter.close).toBe('function');
    });

    it('should not throw when close is called', () => {
      limiter = createRateLimiter({ max: 100, windowMs: 60000 });
      expect(() => limiter.close()).not.toThrow();
    });
  });
});

describe('rateLimit', () => {
  it('should be an alias for createRateLimiter', () => {
    expect(rateLimit).toBe(createRateLimiter);
  });
});

describe('Integration: Rate Limiter', () => {
  let testServer: TestServer;
  let limiter: ReturnType<typeof createRateLimiter>;

  afterEach(async () => {
    limiter?.close();
    await testServer?.close();
  });

  it('should rate limit HTTP requests', async () => {
    limiter = createRateLimiter({ max: 2, windowMs: 60000 });
    testServer = await createTestServer((app) => {
      app.use(limiter);
      app.get('/test', (_req, res) => res.json({ ok: true }));
    });

    // First 2 requests pass
    const res1 = await fetch(`${testServer.url}/test`);
    expect(res1.status).toBe(200);
    
    const res2 = await fetch(`${testServer.url}/test`);
    expect(res2.status).toBe(200);
    
    // Third request blocked
    const res3 = await fetch(`${testServer.url}/test`);
    expect(res3.status).toBe(429);
  });
});
