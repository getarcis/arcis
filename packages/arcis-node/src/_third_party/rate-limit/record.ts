/**
 * Internal record stored inside the in-memory storage map. One per key.
 * See `THIRDPARTY-LICENSES.md` for upstream attribution.
 */

export class StorageRecord {
  value: number;
  expiresAt: number | null;
  timeoutId: ReturnType<typeof setTimeout> | null;

  constructor(value: number, expiresAt: number | null, timeoutId: ReturnType<typeof setTimeout> | null = null) {
    this.value = Math.trunc(value);
    this.expiresAt = expiresAt;
    this.timeoutId = timeoutId;
  }
}
