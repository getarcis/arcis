/**
 * @module @arcis/node/middleware/rate-limit
 * Rate limiting middleware
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { RATE_LIMIT } from '../core/constants';
import { validateMax, validateWindowMs } from '../core/rate-limit-config';
import type { RateLimitOptions, RateLimiterMiddleware, RateLimitIncrement } from '../core/types';
import { FixedWindowCounter } from '../stores/fixed-window';
import { clientKey, createNodeClientIp, validateIpv6Subnet } from '../utils/client-ip';
import { createStoreErrorReporter, toAtomicStore } from './rate-limit-shared';

/**
 * Create Express middleware for rate limiting.
 *
 * The default key is the client IP resolved with the Arcis trust walk
 * (`trustedProxies`, or Express's own `trust proxy` setting when you changed
 * it) and passed through `ipKeyGenerator`. Each counted request makes exactly
 * one atomic store increment. If the store fails, the request is counted in
 * memory instead and the error is reported at most once per window.
 *
 * @param options - Rate limit configuration
 * @returns Express middleware with cleanup method
 * @throws RangeError when `max`, `windowMs` or `ipv6Subnet` is invalid
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
 * // Behind a load balancer at 10.0.0.0/8 (already in the default trust set)
 * // or a public one that must be listed explicitly
 * app.use(createRateLimiter({ trustedProxies: ['203.0.113.10'] }));
 */
export function createRateLimiter(options: RateLimitOptions = {}): RateLimiterMiddleware {
  const owner = 'createRateLimiter';
  const max = validateMax(options.max ?? RATE_LIMIT.DEFAULT_MAX_REQUESTS, owner);
  const windowMs = validateWindowMs(options.windowMs ?? RATE_LIMIT.DEFAULT_WINDOW_MS, owner);
  const ipv6Subnet = validateIpv6Subnet(options.ipv6Subnet, owner);
  const message = options.message ?? RATE_LIMIT.DEFAULT_MESSAGE;
  const statusCode = options.statusCode ?? RATE_LIMIT.DEFAULT_STATUS_CODE;
  const skip = options.skip;
  const clientIp = createNodeClientIp(options);
  const keyGenerator = options.keyGenerator ?? ((req: Request) => clientKey(clientIp(req), ipv6Subnet));
  const store = options.store ? toAtomicStore(options.store) : null;
  // Counts every request without an external store, and every request while
  // the external store is failing.
  const memory = new FixedWindowCounter();
  const reportError = createStoreErrorReporter(windowMs, options.onError);

  const respond = (req: Request, res: Response, next: NextFunction, hit: RateLimitIncrement): void => {
    const now = Date.now();
    const remaining = Math.max(0, max - hit.totalHits);
    const resetSeconds = Math.ceil((hit.resetTime - now) / 1000);

    res.setHeader('X-RateLimit-Limit', max.toString());
    res.setHeader('X-RateLimit-Remaining', remaining.toString());
    res.setHeader('X-RateLimit-Reset', resetSeconds.toString());

    if (hit.totalHits > max) {
      req.__arcis = {
        decision: 'deny', vector: 'rate-limit',
        rule: 'rate-limit/exceeded', severity: 'medium',
      };
      res.setHeader('Retry-After', resetSeconds.toString());
      res.status(statusCode).json({
        error: message,
        retryAfter: resetSeconds,
      });
      return;
    }
    next();
  };

  const handler: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    let key: string;
    try {
      if (skip?.(req)) return next();
      key = keyGenerator(req);
    } catch (error) {
      // A throwing skip or keyGenerator fails open.
      reportError(error);
      return next();
    }

    let hit: RateLimitIncrement;
    if (store) {
      try {
        hit = await store.increment(key, windowMs);
      } catch (error) {
        reportError(error);
        hit = memory.increment(key, windowMs);
      }
    } else {
      hit = memory.increment(key, windowMs);
    }
    respond(req, res, next, hit);
  };

  // Attach close method for cleanup
  const middleware = handler as RateLimiterMiddleware;
  middleware.close = () => {
    memory.clear();
  };

  return middleware;
}

/**
 * Alias for createRateLimiter
 * @see createRateLimiter
 */
export const rateLimit = createRateLimiter;
