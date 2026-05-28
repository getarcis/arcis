/**
 * Rate-limiter response object. The shape returned (or rejected with) by
 * every limiter call. Mirrors the upstream `RateLimiterRes` contract.
 *
 * See `THIRDPARTY-LICENSES.md` for upstream attribution. This file is
 * an internal TypeScript port; do not re-export the class name verbatim.
 */

export interface IRateLimiterRes {
  remainingPoints: number;
  msBeforeNext: number;
  consumedPoints: number;
  isFirstInDuration: boolean;
}

export class LimiterResult implements IRateLimiterRes {
  remainingPoints: number;
  msBeforeNext: number;
  consumedPoints: number;
  isFirstInDuration: boolean;

  constructor(
    remainingPoints: number = 0,
    msBeforeNext: number = 0,
    consumedPoints: number = 0,
    isFirstInDuration: boolean = false,
  ) {
    this.remainingPoints = remainingPoints;
    this.msBeforeNext = msBeforeNext;
    this.consumedPoints = consumedPoints;
    this.isFirstInDuration = isFirstInDuration;
  }
}

export interface LimiterOptions {
  /** Total points available per duration window. */
  points: number;
  /** Window length in seconds. 0 = never expires. */
  duration: number;
  /** Seconds to block a key after it consumed more than `points`. 0 = no block. */
  blockDuration?: number;
  /** Spread allowed actions evenly across the window via setTimeout delays. */
  execEvenly?: boolean;
  /** Floor on the per-call delay introduced by `execEvenly`. */
  execEvenlyMinDelayMs?: number;
  /** Namespace prefix for keys inside the underlying storage. */
  keyPrefix?: string;
}

export interface LimiterConsumeOptions {
  /** Override the configured duration for this call only (seconds). */
  customDuration?: number;
}
