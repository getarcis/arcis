/**
 * @module @arcis/node/middleware/rate-limit-sliding
 * Sliding window rate limiting middleware.
 *
 * More accurate than fixed window — uses a weighted sum of the previous
 * and current window to approximate a true sliding window.
 *
 * Algorithm:
 *   weight = (windowMs - elapsed) / windowMs
 *   count = (prevWindow * weight) + currentWindow
 *   allow = count < limit
 *
 * @example
 * app.use(createSlidingWindowLimiter({ max: 100, window: '15m' }));
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { parseDuration } from '../utils/duration';
import { RATE_LIMIT } from '../core/constants';
import { validateMax, validateWindowMs } from '../core/rate-limit-config';
import {
  clientKey,
  createNodeClientIp,
  validateIpv6Subnet,
  type ClientIpOptions,
} from '../utils/client-ip';

export interface SlidingWindowOptions extends ClientIpOptions {
  /** Maximum requests per window, a non-negative integer. Default: 100 */
  max?: number;
  /** Window size in ms (1 to 2^31-1) or duration string. Default: '1m' */
  window?: string | number;
  /** Error message when limit exceeded */
  message?: string;
  /** HTTP status code for rate limited responses. Default: 429 */
  statusCode?: number;
  /**
   * Function to generate rate limit key from request. Default: the resolved
   * client IP passed through `ipKeyGenerator`.
   */
  keyGenerator?: (req: Request) => string;
  /** Function to skip rate limiting for certain requests */
  skip?: (req: Request) => boolean;
  /** IPv6 prefix length for the default key (1-128), or `false`. Default: 56 */
  ipv6Subnet?: number | false;
}

interface WindowEntry {
  count: number;
  startTime: number;
}

export interface SlidingWindowMiddleware extends RequestHandler {
  close: () => void;
}

/**
 * Create sliding window rate limiter middleware.
 *
 * @example
 * // 100 requests per 15 minutes
 * app.use(createSlidingWindowLimiter({ max: 100, window: '15m' }));
 *
 * @example
 * // Strict API limit
 * app.use('/api', createSlidingWindowLimiter({ max: 30, window: '1m' }));
 */
export function createSlidingWindowLimiter(options: SlidingWindowOptions = {}): SlidingWindowMiddleware {
  const owner = 'createSlidingWindowLimiter';
  const {
    window: windowOpt = RATE_LIMIT.DEFAULT_WINDOW_MS,
    message = RATE_LIMIT.DEFAULT_MESSAGE,
    statusCode = RATE_LIMIT.DEFAULT_STATUS_CODE,
    skip,
  } = options;
  const max = validateMax(options.max ?? RATE_LIMIT.DEFAULT_MAX_REQUESTS, owner);
  // A numeric window is validated as given (parseDuration would floor and clamp it).
  const windowMs = validateWindowMs(
    typeof windowOpt === 'number' ? windowOpt : parseDuration(windowOpt),
    owner,
  );
  const ipv6Subnet = validateIpv6Subnet(options.ipv6Subnet, owner);
  const clientIp = createNodeClientIp(options);
  const keyGenerator = options.keyGenerator ?? ((req: Request) => clientKey(clientIp(req), ipv6Subnet));

  // Two windows per key: current and previous
  const currentWindows = Object.create(null) as Record<string, WindowEntry>;
  const previousWindows = Object.create(null) as Record<string, WindowEntry>;

  // Pin cleanup cadence to 30s regardless of windowMs. Scaling cleanup
  // with windowMs causes churn on short windows (1s window cleans every
  // second) and stale-entry buildup on long windows (1h window only
  // cleans hourly). 30s bounds memory growth without burning CPU; the
  // cutoff stays at `2 * windowMs` so legitimate active windows survive.
  const CLEANUP_INTERVAL_MS = 30_000;
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    const cutoff = now - windowMs * 2; // Keep 2 windows worth
    for (const key of Object.keys(previousWindows)) {
      if (previousWindows[key].startTime < cutoff) {
        delete previousWindows[key];
      }
    }
    for (const key of Object.keys(currentWindows)) {
      if (currentWindows[key].startTime < cutoff) {
        delete currentWindows[key];
      }
    }
  }, CLEANUP_INTERVAL_MS);

  if (typeof cleanupInterval.unref === 'function') {
    cleanupInterval.unref();
  }

  const handler: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
    try {
      if (skip?.(req)) return next();

      const key = keyGenerator(req);
      const now = Date.now();

      // Determine current window boundaries
      const windowStart = Math.floor(now / windowMs) * windowMs;

      // Rotate windows if needed
      if (!currentWindows[key] || currentWindows[key].startTime < windowStart) {
        // Move current to previous
        if (currentWindows[key]) {
          previousWindows[key] = currentWindows[key];
        }
        currentWindows[key] = { count: 0, startTime: windowStart };
      }

      // Calculate weighted count BEFORE incrementing. The previous window
      // counts only when it is the one immediately before this window; a key
      // idle for a full window starts from zero.
      const elapsed = now - windowStart;
      const weight = Math.max(0, (windowMs - elapsed) / windowMs);
      const previous = previousWindows[key];
      const prevCount = previous && previous.startTime === windowStart - windowMs ? previous.count : 0;
      const estimatedCount = (prevCount * weight) + currentWindows[key].count + 1;

      const remaining = Math.max(0, Math.floor(max - estimatedCount));
      const resetMs = windowStart + windowMs - now;
      const resetSeconds = Math.max(1, Math.ceil(resetMs / 1000));

      // Set rate limit headers
      res.setHeader('X-RateLimit-Limit', max.toString());
      res.setHeader('X-RateLimit-Remaining', remaining.toString());
      res.setHeader('X-RateLimit-Reset', resetSeconds.toString());
      res.setHeader('X-RateLimit-Policy', `${max};w=${Math.floor(windowMs / 1000)}`);

      if (estimatedCount > max) {
        // Don't increment — rejected requests should not consume quota
        res.setHeader('Retry-After', resetSeconds.toString());
        res.status(statusCode).json({
          error: message,
          retryAfter: resetSeconds,
        });
        return;
      }

      // Only increment on allowed requests
      currentWindows[key].count++;

      next();
    } catch (error) {
      // Fail open
      // eslint-disable-next-line no-console
      console.error('[arcis] Sliding window rate limiter error:', error);
      next();
    }
  };

  const middleware = handler as SlidingWindowMiddleware;
  middleware.close = () => {
    clearInterval(cleanupInterval);
  };

  return middleware;
}
