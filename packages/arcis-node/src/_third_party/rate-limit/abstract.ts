/**
 * Abstract base for storage-backed rate limiters. Holds the `points` /
 * `duration` / `blockDuration` / `execEvenly` configuration that any
 * concrete limiter shares. Subclasses (`MemoryLimiter`, future Redis
 * backend) implement `consume()` and friends.
 *
 * Ported to TypeScript from upstream RateLimiterAbstract. See
 * `THIRDPARTY-LICENSES.md` for attribution.
 */

import type { LimiterOptions, LimiterConsumeOptions, IRateLimiterRes } from './types';

export abstract class AbstractLimiter {
  protected _points: number;
  protected _duration: number;
  protected _blockDuration: number;
  protected _execEvenly: boolean;
  protected _execEvenlyMinDelayMs: number;
  protected _keyPrefix: string;

  constructor(opts: LimiterOptions) {
    if (!Number.isFinite(opts.points)) {
      throw new Error('points must be a finite number');
    }
    if (!Number.isFinite(opts.duration) || opts.duration < 0) {
      throw new Error('duration must be a finite, non-negative number');
    }
    this._points = opts.points;
    this._duration = opts.duration;
    this._blockDuration = typeof opts.blockDuration === 'undefined' ? 0 : opts.blockDuration;
    this._execEvenly = Boolean(opts.execEvenly);
    this._execEvenlyMinDelayMs =
      typeof opts.execEvenlyMinDelayMs === 'undefined'
        ? Math.ceil((this._duration * 1000) / Math.max(this._points, 1))
        : opts.execEvenlyMinDelayMs;
    if (typeof opts.keyPrefix === 'undefined') {
      this._keyPrefix = 'arcis';
    } else if (typeof opts.keyPrefix !== 'string') {
      throw new Error('keyPrefix must be a string');
    } else {
      this._keyPrefix = opts.keyPrefix;
    }
  }

  get points(): number {
    return this._points;
  }
  get duration(): number {
    return this._duration;
  }
  get msDuration(): number {
    return this._duration * 1000;
  }
  get blockDuration(): number {
    return this._blockDuration;
  }
  get msBlockDuration(): number {
    return this._blockDuration * 1000;
  }
  get execEvenly(): boolean {
    return this._execEvenly;
  }
  get execEvenlyMinDelayMs(): number {
    return this._execEvenlyMinDelayMs;
  }
  get keyPrefix(): string {
    return this._keyPrefix;
  }

  protected _getKeySecDuration(options: LimiterConsumeOptions = {}): number {
    return typeof options.customDuration === 'number' && options.customDuration >= 0
      ? options.customDuration
      : this._duration;
  }

  protected _getKey(key: string): string {
    return this._keyPrefix.length > 0 ? `${this._keyPrefix}:${key}` : key;
  }

  abstract consume(key: string, pointsToConsume?: number, options?: LimiterConsumeOptions): Promise<IRateLimiterRes>;
  abstract penalty(key: string, points?: number, options?: LimiterConsumeOptions): Promise<IRateLimiterRes>;
  abstract reward(key: string, points?: number, options?: LimiterConsumeOptions): Promise<IRateLimiterRes>;
  abstract block(key: string, secDuration: number): Promise<IRateLimiterRes>;
  abstract get(key: string): Promise<IRateLimiterRes | null>;
  abstract delete(key: string): Promise<boolean>;
}
