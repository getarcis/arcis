/**
 * @module @arcis/node/middleware/rate-limit-token
 * Token bucket rate limiting middleware.
 *
 * Allows burst traffic while enforcing an average rate.
 * Tokens refill at a steady rate. Each request costs 1 token.
 *
 * Algorithm:
 *   tokens = min(capacity, tokens + elapsed * refillRate)
 *   if tokens >= cost: allow, subtract cost
 *   else: deny
 *
 * @example
 * app.use(createTokenBucketLimiter({ capacity: 50, refillRate: 10 }));
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { RATE_LIMIT } from '../core/constants';

export interface TokenBucketOptions {
  /** Maximum tokens (burst size). Default: 100 */
  capacity?: number;
  /** Tokens added per second. Default: 10 */
  refillRate?: number;
  /** Tokens consumed per request. Default: 1 */
  cost?: number;
  /** Error message when limit exceeded */
  message?: string;
  /** HTTP status code for rate limited responses. Default: 429 */
  statusCode?: number;
  /** Function to generate rate limit key from request */
  keyGenerator?: (req: Request) => string;
  /** Function to skip rate limiting for certain requests */
  skip?: (req: Request) => boolean;
}

interface Bucket {
  tokens: number;
  lastRefill: number;
}

export interface TokenBucketMiddleware extends RequestHandler {
  close: () => void;
}

/**
 * Create token bucket rate limiter middleware.
 *
 * @example
 * // Allow bursts of 50, sustained rate of 10/sec
 * app.use(createTokenBucketLimiter({ capacity: 50, refillRate: 10 }));
 *
 * @example
 * // Strict API: 5 requests burst, 1/sec sustained
 * app.use('/api/expensive', createTokenBucketLimiter({
 *   capacity: 5,
 *   refillRate: 1,
 * }));
 */
export function createTokenBucketLimiter(options: TokenBucketOptions = {}): TokenBucketMiddleware {
  const {
    capacity = 100,
    refillRate = 10,
    cost = 1,
    message = RATE_LIMIT.DEFAULT_MESSAGE,
    statusCode = RATE_LIMIT.DEFAULT_STATUS_CODE,
    keyGenerator = (req) => req.ip ?? req.socket?.remoteAddress ?? 'unknown',
    skip,
  } = options;

  if (capacity < 1) throw new RangeError(`Token bucket capacity must be >= 1, got ${capacity}`);
  if (refillRate <= 0) throw new RangeError(`Token bucket refillRate must be > 0, got ${refillRate}`);
  if (cost < 1) throw new RangeError(`Token bucket cost must be >= 1, got ${cost}`);
  if (cost > capacity) throw new RangeError(`Token bucket cost (${cost}) must be <= capacity (${capacity}), otherwise all requests are permanently denied`);

  const buckets = Object.create(null) as Record<string, Bucket>;

  // Cleanup stale buckets (full buckets that haven't been accessed)
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    const staleThreshold = (capacity / refillRate) * 1000 * 2; // 2x time to refill
    for (const key of Object.keys(buckets)) {
      if (now - buckets[key].lastRefill > staleThreshold) {
        delete buckets[key];
      }
    }
  }, 60_000);

  if (typeof cleanupInterval.unref === 'function') {
    cleanupInterval.unref();
  }

  function refillBucket(bucket: Bucket, now: number): void {
    const elapsed = (now - bucket.lastRefill) / 1000; // seconds
    const tokensToAdd = elapsed * refillRate;
    bucket.tokens = Math.min(capacity, bucket.tokens + tokensToAdd);
    bucket.lastRefill = now;
  }

  const handler: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
    try {
      if (skip?.(req)) return next();

      const key = keyGenerator(req);
      const now = Date.now();

      // Get or create bucket
      if (!buckets[key]) {
        buckets[key] = { tokens: capacity, lastRefill: now };
      }

      const bucket = buckets[key];
      refillBucket(bucket, now);

      // Calculate retry-after (time until enough tokens are available)
      const retryAfterSec = bucket.tokens < cost
        ? Math.ceil((cost - bucket.tokens) / refillRate)
        : 0;

      // Set headers
      res.setHeader('X-RateLimit-Limit', capacity.toString());
      res.setHeader('X-RateLimit-Remaining', Math.floor(Math.max(0, bucket.tokens - cost)).toString());
      res.setHeader('X-RateLimit-Policy', `${capacity};w=${Math.floor(capacity / refillRate)};burst=${capacity}`);

      if (bucket.tokens < cost) {
        res.setHeader('Retry-After', retryAfterSec.toString());
        res.setHeader('X-RateLimit-Reset', retryAfterSec.toString());
        res.status(statusCode).json({
          error: message,
          retryAfter: retryAfterSec,
        });
        return;
      }

      // Consume token
      bucket.tokens -= cost;
      next();
    } catch (error) {
      // Fail open
      // eslint-disable-next-line no-console
      console.error('[arcis] Token bucket rate limiter error:', error);
      next();
    }
  };

  const middleware = handler as TokenBucketMiddleware;
  middleware.close = () => {
    clearInterval(cleanupInterval);
  };

  return middleware;
}
