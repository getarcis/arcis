/**
 * In-memory storage backend for the rate limiter. Tracks integer counters
 * per key with optional TTL expiry. Ported to TypeScript from the upstream
 * MemoryStorage class. See `THIRDPARTY-LICENSES.md` for attribution.
 */

import { LimiterResult } from './types';
import { StorageRecord } from './record';

export class MemoryStorage {
  private _storage: Map<string, StorageRecord> = new Map();

  /**
   * Increment the counter for `key` by `value`. If the key has no record
   * (or its TTL has expired), a new record is created with `durationSec`
   * lifetime.
   */
  incrby(key: string, value: number, durationSec: number): LimiterResult {
    const record = this._storage.get(key);
    if (record) {
      const msBeforeExpires = record.expiresAt ? record.expiresAt - Date.now() : -1;
      if (!record.expiresAt || msBeforeExpires > 0) {
        record.value = record.value + value;
        return new LimiterResult(0, msBeforeExpires, record.value, false);
      }
      return this.set(key, value, durationSec);
    }
    return this.set(key, value, durationSec);
  }

  /**
   * Write the counter for `key` to `value`, replacing any existing
   * record. `durationSec` of 0 means "never expires".
   */
  set(key: string, value: number, durationSec: number): LimiterResult {
    const durationMs = durationSec * 1000;
    const existing = this._storage.get(key);
    if (existing && existing.timeoutId) {
      clearTimeout(existing.timeoutId);
    }

    const record = new StorageRecord(value, durationMs > 0 ? Date.now() + durationMs : null);
    this._storage.set(key, record);

    if (durationMs > 0) {
      record.timeoutId = setTimeout(() => {
        this._storage.delete(key);
      }, durationMs);
      if (typeof record.timeoutId.unref === 'function') {
        record.timeoutId.unref();
      }
    }

    return new LimiterResult(0, durationMs === 0 ? -1 : durationMs, record.value, true);
  }

  get(key: string): LimiterResult | null {
    const record = this._storage.get(key);
    if (!record) return null;
    const msBeforeExpires = record.expiresAt ? record.expiresAt - Date.now() : -1;
    return new LimiterResult(0, msBeforeExpires, record.value, false);
  }

  delete(key: string): boolean {
    const record = this._storage.get(key);
    if (!record) return false;
    if (record.timeoutId) {
      clearTimeout(record.timeoutId);
    }
    this._storage.delete(key);
    return true;
  }

  /** Inspect the underlying map. Test-only and not part of the public API. */
  _dump(): IterableIterator<[string, StorageRecord]> {
    return this._storage.entries();
  }

  /** Clear all records. Used by tests and by `Limiter.dispose()`. */
  clear(): void {
    for (const record of this._storage.values()) {
      if (record.timeoutId) clearTimeout(record.timeoutId);
    }
    this._storage.clear();
  }
}
