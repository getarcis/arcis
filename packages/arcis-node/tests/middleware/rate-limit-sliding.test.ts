/**
 * Sliding Window Rate Limiter Tests
 * Tests for src/middleware/rate-limit-sliding.ts
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { Request, Response } from 'express';
import { createSlidingWindowLimiter } from '../../src/middleware/rate-limit-sliding';
import { mockRequest, mockResponse, mockNext } from '../setup';

describe('createSlidingWindowLimiter', () => {
  let limiter: ReturnType<typeof createSlidingWindowLimiter>;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    limiter?.close();
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  describe('Basic Allow / Deny', () => {
    it('should allow requests under the limit', () => {
      limiter = createSlidingWindowLimiter({ max: 5, window: 60000 });
      const req = mockRequest({ ip: '1.1.1.1' });
      const res = mockResponse();

      limiter(req as Request, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalledWith(429);
    });

    it('should block requests over the limit', () => {
      limiter = createSlidingWindowLimiter({ max: 2, window: 60000 });

      for (let i = 0; i < 3; i++) {
        const req = mockRequest({ ip: '1.1.1.1' });
        const res = mockResponse();
        vi.clearAllMocks();
        limiter(req as Request, res as Response, mockNext);

        if (i < 2) {
          expect(mockNext).toHaveBeenCalled();
        } else {
          expect(res.status).toHaveBeenCalledWith(429);
          expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
            error: expect.any(String),
            retryAfter: expect.any(Number),
          }));
        }
      }
    });

    it('should track different IPs independently', () => {
      limiter = createSlidingWindowLimiter({ max: 1, window: 60000 });

      // User A exhausts limit
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      // User B can still make requests
      const res = mockResponse();
      vi.clearAllMocks();
      limiter(mockRequest({ ip: '2.2.2.2' }) as Request, res as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Duration string parsing', () => {
    it('should accept duration strings for the window option', () => {
      limiter = createSlidingWindowLimiter({ max: 5, window: '1m' });
      const req = mockRequest();
      const res = mockResponse();
      limiter(req as Request, res as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should accept number for the window option', () => {
      limiter = createSlidingWindowLimiter({ max: 5, window: 30000 });
      const req = mockRequest();
      const res = mockResponse();
      limiter(req as Request, res as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Sliding Window Behavior', () => {
    it('should weight previous window requests into the count', () => {
      const windowMs = 60000;
      limiter = createSlidingWindowLimiter({ max: 10, window: windowMs });

      // Fill up current window with 8 requests
      for (let i = 0; i < 8; i++) {
        limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);
      }

      // Advance time to next window (so current becomes previous)
      vi.advanceTimersByTime(windowMs);

      // In the new window, the weight from previous (8 * ~1.0) + current count
      // should cause blocking before reaching max=10
      let blocked = false;
      for (let i = 0; i < 10; i++) {
        const res = mockResponse();
        vi.clearAllMocks();
        limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
        if (res.status.mock.calls.some((c: number[]) => c[0] === 429)) {
          blocked = true;
          break;
        }
      }
      expect(blocked).toBe(true);
    });

    it('should allow full quota after previous window fully expires', () => {
      const windowMs = 60000;
      limiter = createSlidingWindowLimiter({ max: 3, window: windowMs });

      // Fill up limit
      for (let i = 0; i < 3; i++) {
        limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);
      }

      // Advance 2 full windows so previous window weight = 0
      vi.advanceTimersByTime(windowMs * 2);

      // Should now allow full quota again
      for (let i = 0; i < 3; i++) {
        const res = mockResponse();
        vi.clearAllMocks();
        limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
        expect(mockNext).toHaveBeenCalled();
      }
    });
  });

  describe('Rate Limit Headers', () => {
    it('should set X-RateLimit-Limit header', () => {
      limiter = createSlidingWindowLimiter({ max: 50, window: 60000 });
      const res = mockResponse();
      limiter(mockRequest() as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', '50');
    });

    it('should set X-RateLimit-Remaining header', () => {
      limiter = createSlidingWindowLimiter({ max: 50, window: 60000 });
      const res = mockResponse();
      limiter(mockRequest() as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', expect.any(String));
    });

    it('should set X-RateLimit-Reset header', () => {
      limiter = createSlidingWindowLimiter({ max: 50, window: 60000 });
      const res = mockResponse();
      limiter(mockRequest() as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Reset', expect.any(String));
    });

    it('should set X-RateLimit-Policy header', () => {
      limiter = createSlidingWindowLimiter({ max: 100, window: 60000 });
      const res = mockResponse();
      limiter(mockRequest() as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Policy', '100;w=60');
    });

    it('should set Retry-After header when blocked', () => {
      limiter = createSlidingWindowLimiter({ max: 1, window: 60000 });
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      const res = mockResponse();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('Retry-After', expect.any(String));
    });
  });

  describe('Custom Status Code', () => {
    it('should use custom status code when blocked', () => {
      limiter = createSlidingWindowLimiter({ max: 1, window: 60000, statusCode: 503 });
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      const res = mockResponse();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
      expect(res.status).toHaveBeenCalledWith(503);
    });
  });

  describe('Custom Message', () => {
    it('should use custom error message', () => {
      limiter = createSlidingWindowLimiter({ max: 1, window: 60000, message: 'Slow down!' });
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      const res = mockResponse();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Slow down!' }));
    });
  });

  describe('Skip Function', () => {
    it('should skip rate limiting when skip returns true', () => {
      limiter = createSlidingWindowLimiter({
        max: 1,
        window: 60000,
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
      limiter = createSlidingWindowLimiter({
        max: 1,
        window: 60000,
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
      limiter = createSlidingWindowLimiter({
        max: 1,
        window: 60000,
        keyGenerator: (req) => req.headers['x-api-key'] as string || 'anon',
      });

      // User A blocked
      limiter(mockRequest({ headers: { 'x-api-key': 'user-a' } }) as Request, mockResponse() as Response, mockNext);
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

  describe('Cleanup', () => {
    it('should have a close method', () => {
      limiter = createSlidingWindowLimiter({ max: 100, window: 60000 });
      expect(typeof limiter.close).toBe('function');
    });

    it('should not throw when close is called', () => {
      limiter = createSlidingWindowLimiter({ max: 100, window: 60000 });
      expect(() => limiter.close()).not.toThrow();
    });

    it('should clean up stale entries on interval', () => {
      const windowMs = 10000;
      limiter = createSlidingWindowLimiter({ max: 100, window: windowMs });

      // Make a request to create an entry
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, mockResponse() as Response, mockNext);

      // Advance past 2x window (cleanup threshold)
      vi.advanceTimersByTime(windowMs * 3);

      // The cleanup should have run; making a new request should work fine
      const res = mockResponse();
      vi.clearAllMocks();
      limiter(mockRequest({ ip: '1.1.1.1' }) as Request, res as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Fail open', () => {
    it('should call next() if keyGenerator throws', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      limiter = createSlidingWindowLimiter({
        max: 1,
        window: 60000,
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
      limiter = createSlidingWindowLimiter();
      const res = mockResponse();
      limiter(mockRequest() as Request, res as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
      // Default max is 100
      expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', '100');
    });
  });
});
