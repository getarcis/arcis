/**
 * @module @arcis/node/middleware/rate-limit
 * Rate limiting middleware
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { RATE_LIMIT } from '../core/constants';
import type { RateLimitOptions, RateLimiterMiddleware, RateLimitEntry } from '../core/types';

/** In-memory rate limit store */
interface InMemoryRateLimitStore {
  [key: string]: RateLimitEntry;
}

/**
 * Create Express middleware for rate limiting.
 * 
 * @param options - Rate limit configuration
 * @returns Express middleware with cleanup method
 * 
 * @example
 * app.use(createRateLimiter({ max: 100, windowMs: 60000 }));
 * 
 * @example
 * // Skip rate limiting for certain routes
 * app.use(createRateLimiter({
 *   max: 50,
 *   skip: (req) => req.path === '/health'
 * }));
 * 
 * @example
 * // Cleanup on shutdown
 * const limiter = createRateLimiter();
 * app.use(limiter);
 * process.on('SIGTERM', () => limiter.close());
 */
export function createRateLimiter(options: RateLimitOptions = {}): RateLimiterMiddleware {
  const {
    max = RATE_LIMIT.DEFAULT_MAX_REQUESTS,
    windowMs = RATE_LIMIT.DEFAULT_WINDOW_MS,
    message = RATE_LIMIT.DEFAULT_MESSAGE,
    statusCode = RATE_LIMIT.DEFAULT_STATUS_CODE,
    keyGenerator = (req) => {
      const ip = req.ip ?? req.socket?.remoteAddress;
      if (ip) return ip;
      // SECURITY: When IP is unresolvable, fall back to a fingerprint of UA +
      // Accept-Language so unresolvable clients don't share a single counter
      // (one attacker could exhaust the limit and block every other client).
      const ua = (req.headers['user-agent'] ?? '') as string;
      const lang = (req.headers['accept-language'] ?? '') as string;
      const fp = `${ua}|${lang}`;
      // Small non-crypto hash — just needs to disperse unknown clients
      let hash = 0;
      for (let i = 0; i < fp.length; i++) hash = ((hash << 5) - hash + fp.charCodeAt(i)) | 0;
      return `unknown:${hash.toString(36)}`;
    },
    skip,
    store: externalStore,
  } = options;

  // Object.create(null) avoids prototype pollution if keyGenerator ever
  // returns '__proto__', 'constructor', or 'prototype'.
  const inMemoryStore = Object.create(null) as InMemoryRateLimitStore;

  // Cleanup interval for in-memory store (only create if not using external store)
  let cleanupInterval: ReturnType<typeof setInterval> | null = null;
  
  if (!externalStore) {
    cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const key of Object.keys(inMemoryStore)) {
        if (inMemoryStore[key].resetTime < now) {
          delete inMemoryStore[key];
        }
      }
    }, windowMs);

    // Prevent interval from keeping the process alive (Node.js only)
    if (typeof cleanupInterval.unref === 'function') {
      cleanupInterval.unref();
    }
  }

  const handler: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (skip?.(req)) {
        return next();
      }

      const key = keyGenerator(req);
      const now = Date.now();

      let count: number;
      let resetTime: number;

      if (externalStore) {
        // Use external store (e.g., Redis)
        const entry = await externalStore.get(key);
        if (!entry || entry.resetTime < now) {
          await externalStore.set(key, { count: 1, resetTime: now + windowMs });
          count = 1;
          resetTime = now + windowMs;
        } else {
          count = await externalStore.increment(key);
          resetTime = entry.resetTime;
        }
      } else {
        // Use in-memory store
        if (!inMemoryStore[key] || inMemoryStore[key].resetTime < now) {
          inMemoryStore[key] = { count: 1, resetTime: now + windowMs };
        } else {
          inMemoryStore[key].count++;
        }
        count = inMemoryStore[key].count;
        resetTime = inMemoryStore[key].resetTime;
      }

      const remaining = Math.max(0, max - count);
      const resetSeconds = Math.ceil((resetTime - now) / 1000);

      // Set rate limit headers
      res.setHeader('X-RateLimit-Limit', max.toString());
      res.setHeader('X-RateLimit-Remaining', remaining.toString());
      res.setHeader('X-RateLimit-Reset', resetSeconds.toString());

      if (count > max) {
        res.setHeader('Retry-After', resetSeconds.toString());
        res.status(statusCode).json({
          error: message,
          retryAfter: resetSeconds,
        });
        return;
      }

      next();
    } catch (error) {
      // External store failed — fall back to in-memory rate limiting.
      // Pure fail-open is a security bypass; in-memory fallback maintains protection.
      // eslint-disable-next-line no-console
      console.error('[arcis] Rate limiter store error, using in-memory fallback:', error);
      try {
        const key = keyGenerator(req);
        const now = Date.now();
        if (!inMemoryStore[key] || inMemoryStore[key].resetTime < now) {
          inMemoryStore[key] = { count: 1, resetTime: now + windowMs };
        } else {
          inMemoryStore[key].count++;
        }
        const count = inMemoryStore[key].count;
        if (count > max) {
          const resetSeconds = Math.ceil((inMemoryStore[key].resetTime - now) / 1000);
          res.setHeader('Retry-After', resetSeconds.toString());
          res.status(statusCode).json({ error: message, retryAfter: resetSeconds });
          return;
        }
      } catch {
        // If even fallback fails, allow through to preserve availability
      }
      next();
    }
  };

  // Attach close method for cleanup
  const middleware = handler as RateLimiterMiddleware;
  middleware.close = () => {
    if (cleanupInterval) {
      clearInterval(cleanupInterval);
      cleanupInterval = null;
    }
  };

  return middleware;
}

/**
 * Alias for createRateLimiter
 * @see createRateLimiter
 */
export const rateLimit = createRateLimiter;
