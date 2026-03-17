/**
 * Token Bucket Rate Limiter Tests
 * Tests for src/middleware/rate-limit-token.ts
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { Request, Response } from 'express';
import { createTokenBucketLimiter } from '../../src/middleware/rate-limit-token';
import { mockRequest, mockResponse, mockNext } from '../setup';

describe('createTokenBucketLimiter', () => {
  let limiter: ReturnType<typeof createTokenBucketLimiter>;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    limiter?.close();
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  describe('Basic Allow / Deny', () => {
    it('should allow requests when tokens are available', () => {
      limiter = createTokenBucketLimiter({ capacity: 10, refillRate: 1 });
      const req = mockRequest();
      const res = mockResponse();

      limiter(req as Request, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalledWith(429);
    });

    it('should block requests when tokens are exhausted', () => {
      limiter = createTokenBucketLimiter({ capacity: 2, refillRate: 1 });

      // Use up all tokens
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      // Third request should be blocked
      const res = mockResponse();
      vi.clearAllMocks();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
      expect(res.status).toHaveBeenCalledWith(429);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        error: expect.any(String),
        retryAfter: expect.any(Number),
      }));
    });

    it('should allow burst up to capacity', () => {
      limiter = createTokenBucketLimiter({ capacity: 5, refillRate: 1 });

      // All 5 burst requests should succeed
      for (let i = 0; i < 5; i++) {
        const res = mockResponse();
        vi.clearAllMocks();
        limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
        expect(mockNext).toHaveBeenCalled();
      }

      // 6th should be blocked
      const res = mockResponse();
      vi.clearAllMocks();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
      expect(res.status).toHaveBeenCalledWith(429);
    });

    it('should track different keys independently', () => {
      limiter = createTokenBucketLimiter({ capacity: 1, refillRate: 1 });

      // User A exhausts tokens
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      // User B should still have tokens
      const res = mockResponse();
      vi.clearAllMocks();
      limiter(mockRequest({ ip: '2.2.2.2' }) as Request, res as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Token Refill', () => {
    it('should refill tokens over time', () => {
      limiter = createTokenBucketLimiter({ capacity: 5, refillRate: 1 });

      // Use all tokens
      for (let i = 0; i < 5; i++) {
        limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);
      }

      // Blocked now
      const res1 = mockResponse();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res1 as Response, mockNext);
      expect(res1.status).toHaveBeenCalledWith(429);

      // Advance 2 seconds (refillRate=1/sec => 2 tokens)
      vi.advanceTimersByTime(2000);

      // Should allow 2 more requests
      const res2 = mockResponse();
      vi.clearAllMocks();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res2 as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();

      const res3 = mockResponse();
      vi.clearAllMocks();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res3 as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should not refill beyond capacity', () => {
      limiter = createTokenBucketLimiter({ capacity: 3, refillRate: 10 });

      // Use 1 token
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      // Wait a long time (way more than needed to refill)
      vi.advanceTimersByTime(60000);

      // Should still only have capacity=3 tokens
      for (let i = 0; i < 3; i++) {
        const res = mockResponse();
        vi.clearAllMocks();
        limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
        expect(mockNext).toHaveBeenCalled();
      }

      // 4th should be blocked
      const res = mockResponse();
      vi.clearAllMocks();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
      expect(res.status).toHaveBeenCalledWith(429);
    });
  });

  describe('Custom Cost', () => {
    it('should consume multiple tokens per request when cost > 1', () => {
      limiter = createTokenBucketLimiter({ capacity: 10, refillRate: 1, cost: 5 });

      // First request: 10 - 5 = 5 tokens left
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      // Second request: 5 - 5 = 0 tokens left
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      // Third request: 0 tokens, blocked
      const res = mockResponse();
      vi.clearAllMocks();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
      expect(res.status).toHaveBeenCalledWith(429);
    });
  });

  describe('Rate Limit Headers', () => {
    it('should set X-RateLimit-Limit header', () => {
      limiter = createTokenBucketLimiter({ capacity: 50, refillRate: 10 });
      const res = mockResponse();
      limiter(mockRequest() as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', '50');
    });

    it('should set X-RateLimit-Remaining header', () => {
      limiter = createTokenBucketLimiter({ capacity: 50, refillRate: 10 });
      const res = mockResponse();
      limiter(mockRequest() as Request, res as Response, mockNext);
      // Header set before consumption: remaining = floor(50 - 1) = 49
      expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', '49');
    });

    it('should set X-RateLimit-Policy header with burst info', () => {
      limiter = createTokenBucketLimiter({ capacity: 100, refillRate: 10 });
      const res = mockResponse();
      limiter(mockRequest() as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Policy', '100;w=10;burst=100');
    });

    it('should set Retry-After when blocked', () => {
      limiter = createTokenBucketLimiter({ capacity: 1, refillRate: 1 });
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      const res = mockResponse();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('Retry-After', expect.any(String));
      expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Reset', expect.any(String));
    });
  });

  describe('Custom Status Code', () => {
    it('should use custom status code when blocked', () => {
      limiter = createTokenBucketLimiter({ capacity: 1, refillRate: 1, statusCode: 503 });
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      const res = mockResponse();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
      expect(res.status).toHaveBeenCalledWith(503);
    });
  });

  describe('Custom Message', () => {
    it('should use custom error message', () => {
      limiter = createTokenBucketLimiter({ capacity: 1, refillRate: 1, message: 'Quota exceeded' });
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      const res = mockResponse();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Quota exceeded' }));
    });
  });

  describe('Skip Function', () => {
    it('should skip rate limiting when skip returns true', () => {
      limiter = createTokenBucketLimiter({
        capacity: 1,
        refillRate: 1,
        skip: () => true,
      });

      for (let i = 0; i < 5; i++) {
        const res = mockResponse();
        vi.clearAllMocks();
        limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
        expect(mockNext).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalledWith(429);
      }
    });

    it('should apply rate limiting when skip returns false', () => {
      limiter = createTokenBucketLimiter({
        capacity: 1,
        refillRate: 1,
        skip: () => false,
      });

      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      const res = mockResponse();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
      expect(res.status).toHaveBeenCalledWith(429);
    });
  });

  describe('Custom Key Generator', () => {
    it('should use custom key generator', () => {
      limiter = createTokenBucketLimiter({
        capacity: 1,
        refillRate: 1,
        keyGenerator: (req) => req.headers['x-api-key'] as string || 'anon',
      });

      limiter(mockRequest({ headers: { 'x-api-key': 'user-a' } }) as Request, mockResponse() as Response, mockNext);

      // User A blocked
      const resA = mockResponse();
      limiter(mockRequest({ headers: { 'x-api-key': 'user-a' } }) as Request, resA as Response, mockNext);
      expect(resA.status).toHaveBeenCalledWith(429);

      // User B still allowed
      const resB = mockResponse();
      vi.clearAllMocks();
      limiter(mockRequest({ headers: { 'x-api-key': 'user-b' } }) as Request, resB as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Validation', () => {
    it('should throw RangeError if capacity < 1', () => {
      expect(() => createTokenBucketLimiter({ capacity: 0 })).toThrow(RangeError);
      expect(() => createTokenBucketLimiter({ capacity: -1 })).toThrow(RangeError);
    });

    it('should throw RangeError if refillRate <= 0', () => {
      expect(() => createTokenBucketLimiter({ refillRate: 0 })).toThrow(RangeError);
      expect(() => createTokenBucketLimiter({ refillRate: -5 })).toThrow(RangeError);
    });

    it('should throw RangeError if cost < 1', () => {
      expect(() => createTokenBucketLimiter({ cost: 0 })).toThrow(RangeError);
      expect(() => createTokenBucketLimiter({ cost: -1 })).toThrow(RangeError);
    });
  });

  describe('Cleanup', () => {
    it('should have a close method', () => {
      limiter = createTokenBucketLimiter({ capacity: 100, refillRate: 10 });
      expect(typeof limiter.close).toBe('function');
    });

    it('should not throw when close is called', () => {
      limiter = createTokenBucketLimiter({ capacity: 100, refillRate: 10 });
      expect(() => limiter.close()).not.toThrow();
    });

    it('should clean up stale buckets on interval', () => {
      limiter = createTokenBucketLimiter({ capacity: 10, refillRate: 10 });

      // Make a request
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      // Advance past cleanup interval (60s) and stale threshold (2x refill time)
      vi.advanceTimersByTime(120000);

      // New request should work fine (bucket was cleaned up and re-created)
      const res = mockResponse();
      vi.clearAllMocks();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Fail open', () => {
    it('should call next() if keyGenerator throws', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      limiter = createTokenBucketLimiter({
        capacity: 10,
        refillRate: 1,
        keyGenerator: () => { throw new Error('boom'); },
      });

      const res = mockResponse();
      limiter(mockRequest() as Request, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalledWith(429);
      consoleSpy.mockRestore();
    });
  });

  describe('Default options', () => {
    it('should use defaults when no options provided', () => {
      limiter = createTokenBucketLimiter();
      const res = mockResponse();
      limiter(mockRequest() as Request, res as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
      // Default capacity is 100
      expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', '100');
    });
  });
});
