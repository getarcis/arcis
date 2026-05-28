/**
 * Bursty rate limiter — wraps two underlying limiters. The first is the
 * steady-state limiter; if it rejects, the bursty limiter is consulted
 * to grant short-term burst capacity. Useful for "5 req/sec normally,
 * but allow occasional bursts of up to 15 within 10 sec" patterns.
 *
 * Ported to TypeScript from upstream BurstyRateLimiter — see
 * `THIRDPARTY-LICENSES.md` for attribution.
 */

import type { AbstractLimiter } from './abstract';
import { LimiterResult } from './types';
import type { IRateLimiterRes, LimiterConsumeOptions } from './types';

function combine(steady: IRateLimiterRes, burst: IRateLimiterRes | null): LimiterResult {
  return new LimiterResult(
    steady.remainingPoints,
    Math.min(steady.msBeforeNext, burst ? burst.msBeforeNext : 0),
    steady.consumedPoints,
    steady.isFirstInDuration,
  );
}

export class BurstyLimiter {
  constructor(
    private readonly _steady: AbstractLimiter,
    private readonly _burst: AbstractLimiter,
  ) {}

  consume(
    key: string,
    pointsToConsume: number = 1,
    options: LimiterConsumeOptions = {},
  ): Promise<IRateLimiterRes> {
    return this._steady.consume(key, pointsToConsume, options).catch((steadyRej) => {
      if (steadyRej instanceof LimiterResult || isLimiterResultShape(steadyRej)) {
        return this._burst
          .consume(key, pointsToConsume, options)
          .then((burstRes) => combine(steadyRej, burstRes))
          .catch((burstRej) => {
            if (burstRej instanceof LimiterResult || isLimiterResultShape(burstRej)) {
              return Promise.reject(combine(steadyRej, burstRej));
            }
            return Promise.reject(burstRej);
          });
      }
      return Promise.reject(steadyRej);
    });
  }

  get(key: string): Promise<LimiterResult | null> {
    return Promise.all([this._steady.get(key), this._burst.get(key)]).then(([s, b]) =>
      s ? combine(s, b) : null,
    );
  }

  get points(): number {
    return this._steady.points;
  }
}

function isLimiterResultShape(x: unknown): x is IRateLimiterRes {
  return (
    typeof x === 'object' &&
    x !== null &&
    typeof (x as IRateLimiterRes).consumedPoints === 'number' &&
    typeof (x as IRateLimiterRes).msBeforeNext === 'number'
  );
}
