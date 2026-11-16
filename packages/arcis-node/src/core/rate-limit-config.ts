/**
 * @module @arcis/node/core/rate-limit-config
 * Construction-time validation shared by every rate limiter
 * (spec/API_SPEC.md, "Store contract and counting").
 */

/** Largest window a JavaScript timer can represent (2^31-1 ms). */
export const MAX_WINDOW_MS = 2 ** 31 - 1;

/**
 * Check that `windowMs` is a whole number of milliseconds from 1 to 2^31-1.
 *
 * @throws RangeError otherwise
 */
export function validateWindowMs(windowMs: unknown, owner: string): number {
  if (typeof windowMs !== 'number' || !Number.isInteger(windowMs) || windowMs < 1 || windowMs > MAX_WINDOW_MS) {
    throw new RangeError(
      `${owner}: windowMs must be a whole number of milliseconds from 1 to ${MAX_WINDOW_MS} (got ${String(windowMs)})`,
    );
  }
  return windowMs;
}

/**
 * Check that `max` is a non-negative integer. `0` is valid and blocks every request.
 *
 * @throws RangeError otherwise
 */
export function validateMax(max: unknown, owner: string): number {
  if (typeof max !== 'number' || !Number.isInteger(max) || max < 0) {
    throw new RangeError(`${owner}: max must be a non-negative integer (got ${String(max)})`);
  }
  return max;
}
