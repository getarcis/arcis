/**
 * Internal limiter primitives. Not part of the public Arcis API — these
 * are wired into `middleware/brute-force.ts` and the protect helpers.
 *
 * Upstream attribution lives in `THIRDPARTY-LICENSES.md` (Source E:
 * animir/node-rate-limiter-flexible, ISC).
 */

export { MemoryLimiter } from './memory';
export { BurstyLimiter } from './bursty';
export { LimiterResult } from './types';
export type {
  IRateLimiterRes,
  LimiterOptions,
  LimiterConsumeOptions,
} from './types';
