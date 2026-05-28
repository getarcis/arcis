/**
 * In-memory rate limiter backed by `MemoryStorage`. Implements the
 * `consume()` / `penalty()` / `reward()` / `block()` / `get()` /
 * `delete()` surface from the upstream limiter library.
 *
 * Ported to TypeScript from RateLimiterMemory. See
 * `THIRDPARTY-LICENSES.md` for attribution.
 */

import { AbstractLimiter } from './abstract';
import { MemoryStorage } from './memory-storage';
import { LimiterResult } from './types';
import type { LimiterOptions, LimiterConsumeOptions, IRateLimiterRes } from './types';

export class MemoryLimiter extends AbstractLimiter {
  private _storage: MemoryStorage;

  constructor(opts: LimiterOptions) {
    super(opts);
    this._storage = new MemoryStorage();
  }

  consume(key: string, pointsToConsume: number = 1, options: LimiterConsumeOptions = {}): Promise<IRateLimiterRes> {
    return new Promise((resolve, reject) => {
      const rlKey = this._getKey(key);
      const secDuration = this._getKeySecDuration(options);
      let res = this._storage.incrby(rlKey, pointsToConsume, secDuration);
      res.remainingPoints = Math.max(this._points - res.consumedPoints, 0);

      if (res.consumedPoints > this._points) {
        // Only block the first time the key spills past `points`. The
        // `consumedPoints <= points + pointsToConsume` guard prevents
        // re-blocking on every subsequent call inside the block window.
        if (this._blockDuration > 0 && res.consumedPoints <= this._points + pointsToConsume) {
          res = this._storage.set(rlKey, res.consumedPoints, this._blockDuration);
        }
        reject(res);
        return;
      }

      if (this._execEvenly && res.msBeforeNext > 0 && !res.isFirstInDuration) {
        let delay = Math.ceil(res.msBeforeNext / (res.remainingPoints + 2));
        if (delay < this._execEvenlyMinDelayMs) {
          delay = res.consumedPoints * this._execEvenlyMinDelayMs;
        }
        res.msBeforeNext = Math.max(res.msBeforeNext - delay, 0);
        setTimeout(resolve, delay, res);
        return;
      }

      resolve(res);
    });
  }

  penalty(key: string, points: number = 1, options: LimiterConsumeOptions = {}): Promise<IRateLimiterRes> {
    const rlKey = this._getKey(key);
    const secDuration = this._getKeySecDuration(options);
    const res = this._storage.incrby(rlKey, points, secDuration);
    res.remainingPoints = Math.max(this._points - res.consumedPoints, 0);
    return Promise.resolve(res);
  }

  reward(key: string, points: number = 1, options: LimiterConsumeOptions = {}): Promise<IRateLimiterRes> {
    const rlKey = this._getKey(key);
    const secDuration = this._getKeySecDuration(options);
    const res = this._storage.incrby(rlKey, -points, secDuration);
    res.remainingPoints = Math.max(this._points - res.consumedPoints, 0);
    return Promise.resolve(res);
  }

  block(key: string, secDuration: number): Promise<IRateLimiterRes> {
    const msDuration = secDuration * 1000;
    const initPoints = this._points + 1;
    this._storage.set(this._getKey(key), initPoints, secDuration);
    return Promise.resolve(new LimiterResult(0, msDuration === 0 ? -1 : msDuration, initPoints, false));
  }

  get(key: string): Promise<IRateLimiterRes | null> {
    const res = this._storage.get(this._getKey(key));
    if (res !== null) {
      res.remainingPoints = Math.max(this._points - res.consumedPoints, 0);
    }
    return Promise.resolve(res);
  }

  delete(key: string): Promise<boolean> {
    return Promise.resolve(this._storage.delete(this._getKey(key)));
  }

  /** Test/teardown helper. Drops every key and clears timers. */
  dispose(): void {
    this._storage.clear();
  }
}
