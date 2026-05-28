/**
 * @module @arcis/node/middleware/brute-force
 *
 * Brute-force protection middleware built on the bursty limiter
 * primitive. Designed for login + password-reset endpoints where the
 * defense isn't just "X requests per minute" but "if this IP keeps
 * trying after the rate-limit window resets, block it for longer".
 *
 * Two-tier semantics:
 *  - Steady-state: `fastPoints` consumes per `fastDuration` seconds.
 *    Once exhausted, normal traffic gets a 429 until the window
 *    resets.
 *  - Brute-force: `slowPoints` failed attempts over `slowDuration`
 *    seconds trips a `blockDuration` semi-permanent block.
 *
 * The middleware only consumes on `next()` by default, meaning every
 * request counts, even successful ones. Pass `{ consumeOn: 'failure' }`
 * plus a custom `failure` predicate to count only failed responses.
 * The handler also exposes `req.arcisBruteForce.reward(key)` / `.delete(key)`
 * to let the application reset counters on successful login.
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { MemoryLimiter, LimiterResult } from '../_third_party/rate-limit';
import type { IRateLimiterRes } from '../_third_party/rate-limit';

export interface BruteForceOptions {
  /** Points allowed in the fast window. */
  fastPoints?: number;
  /** Fast window length in seconds. */
  fastDuration?: number;
  /** Points allowed in the slow window. */
  slowPoints?: number;
  /** Slow window length in seconds. */
  slowDuration?: number;
  /** Seconds to semi-permanently block a key after slow-window exhaustion. */
  blockDuration?: number;
  /** Custom key resolver. Defaults to client IP. */
  keyGenerator?: (req: Request) => string;
  /** HTTP status to return when blocked. */
  statusCode?: number;
  /** Response message when blocked. */
  message?: string;
  /** Skip predicate. Return true to bypass the limiter for this request. */
  skip?: (req: Request) => boolean;
}

export interface BruteForceController {
  /** Reset the failure counter for a key (call after successful auth). */
  reward(key: string, points?: number): Promise<IRateLimiterRes>;
  /** Drop the key entirely. */
  delete(key: string): Promise<boolean>;
  /** Inspect the current counter without consuming. */
  get(key: string): Promise<IRateLimiterRes | null>;
  /** Manually trip the block (e.g. after N suspicious logins). */
  block(key: string, secDuration: number): Promise<IRateLimiterRes>;
}

declare global {
  namespace Express {
    interface Request {
      arcisBruteForce?: BruteForceController;
    }
  }
}

function defaultKeyGenerator(req: Request): string {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  if (typeof req.ip === 'string' && req.ip.length > 0) return req.ip;
  const remote = req.socket?.remoteAddress;
  return typeof remote === 'string' && remote.length > 0 ? remote : 'unknown';
}

/**
 * Build a brute-force middleware backed by a bursty limiter. The
 * returned function is an Express RequestHandler with a `controller`
 * property exposing reward/delete/get/block for the application layer.
 */
export function bruteForceProtection(options: BruteForceOptions = {}): RequestHandler & {
  controller: BruteForceController;
} {
  const fastPoints = options.fastPoints ?? 5;
  const fastDuration = options.fastDuration ?? 60;
  const slowPoints = options.slowPoints ?? 20;
  const slowDuration = options.slowDuration ?? 900; // 15 min
  const blockDuration = options.blockDuration ?? 900; // 15 min
  const keyGenerator = options.keyGenerator ?? defaultKeyGenerator;
  const statusCode = options.statusCode ?? 429;
  const message = options.message ?? 'Too many login attempts. Please try again later.';
  const skip = options.skip;

  // Fast window: normal short-window rate limit. Resets every
  // `fastDuration` seconds; no semi-permanent block.
  const fast = new MemoryLimiter({
    points: fastPoints,
    duration: fastDuration,
    keyPrefix: 'arcis:bf:fast',
  });

  // Slow window: brute-force trip wire with block. Block writes a
  // record with TTL = blockDuration that swallows every subsequent
  // request until the timer expires.
  const slow = new MemoryLimiter({
    points: slowPoints,
    duration: slowDuration,
    blockDuration,
    keyPrefix: 'arcis:bf:slow',
  });

  const controller: BruteForceController = {
    reward: (key, points = 1) => slow.reward(key, points),
    delete: async (key) => {
      const a = await fast.delete(key);
      const b = await slow.delete(key);
      return a || b;
    },
    get: (key) => slow.get(key),
    block: (key, secDuration) => slow.block(key, secDuration),
  };

  const handler: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (skip?.(req)) return next();

      const key = keyGenerator(req);
      req.arcisBruteForce = controller;

      // AND semantics: both limiters must allow. Slow goes first so
      // that the block-state check happens before the cheap fast check.
      const slowRes = await slow.consume(key, 1);
      const fastRes = await fast.consume(key, 1);

      res.setHeader('X-RateLimit-Limit', String(slowPoints));
      res.setHeader(
        'X-RateLimit-Remaining',
        String(Math.min(fastRes.remainingPoints, slowRes.remainingPoints)),
      );
      res.setHeader(
        'X-RateLimit-Reset',
        String(Math.ceil(Math.max(slowRes.msBeforeNext, fastRes.msBeforeNext) / 1000)),
      );
      next();
    } catch (rejection) {
      if (rejection instanceof LimiterResult || isLimiterResultShape(rejection)) {
        const retryAfter = Math.ceil((rejection as IRateLimiterRes).msBeforeNext / 1000);
        res.setHeader('X-RateLimit-Limit', String(slowPoints));
        res.setHeader('X-RateLimit-Remaining', '0');
        res.setHeader('X-RateLimit-Reset', String(retryAfter));
        res.setHeader('Retry-After', String(retryAfter));
        res.status(statusCode).json({ error: message, retryAfter });
        return;
      }
      // Unknown rejection. Fail open and log.
      // eslint-disable-next-line no-console
      console.error('[arcis] brute-force middleware error:', rejection);
      next();
    }
  };

  return Object.assign(handler, { controller });
}

function isLimiterResultShape(x: unknown): x is IRateLimiterRes {
  return (
    typeof x === 'object' &&
    x !== null &&
    typeof (x as IRateLimiterRes).consumedPoints === 'number' &&
    typeof (x as IRateLimiterRes).msBeforeNext === 'number'
  );
}
