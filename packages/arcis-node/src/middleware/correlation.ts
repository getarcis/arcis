/**
 * @module @arcis/node/middleware/correlation
 *
 * V1.6 / improvements.md §1.3 — Stateful per-IP correlation window.
 *
 * Today's middleware is stateless: each request is judged on its own.
 * That misses three classes of attack:
 *
 *   - Scanner sweep. One IP firing payloads from every category in
 *     quick succession is a scanner, not a real user.
 *   - Credential stuffing. Same login route, same IP, dozens of
 *     distinct usernames in 60 seconds.
 *   - Race-condition probe. POST /a immediately followed by GET /b
 *     from the same IP, within 200 ms. Either is fine alone.
 *
 * This module records a small rolling event log per IP (capped) and
 * exposes detection helpers. Detection is *additive* — Pattern 4
 * applies (fail-open). If something goes wrong here, the existing
 * rate-limit + per-vector defenses still run.
 *
 * Mirrors `arcis-python/arcis/middleware/correlation.py`. Both SDKs
 * must accept the same base corpus per Pattern 7.
 */

export interface CorrelationEvent {
  /** Wall-clock seconds (Date.now() / 1000) or test-injected value. */
  timestamp: number;
  /** Detector or operation that produced this event. */
  vector: string;
  route: string;
  method: string;
  /** Username / email / token bucket if relevant; otherwise undefined. */
  distinctValue?: string;
}

export interface CorrelationDetections {
  scanner: boolean;
  credentialStuffing: boolean;
  raceWindow: boolean;
  distinctVectors: number;
  distinctValues: number;
  requestsInWindow: number;
}

export interface CorrelationWindowOptions {
  windowSeconds?: number;
  maxIps?: number;
  maxEventsPerIp?: number;
  scannerDistinctVectors?: number;
  scannerMinRequests?: number;
  credentialStuffingDistinctValues?: number;
  raceWindowMs?: number;
  /** Pre-registered race-pair routes; ad-hoc detect_race_window also works. */
  racePairs?: Array<[string, string]>;
}

const EMPTY_DETECTIONS: CorrelationDetections = Object.freeze({
  scanner: false,
  credentialStuffing: false,
  raceWindow: false,
  distinctVectors: 0,
  distinctValues: 0,
  requestsInWindow: 0,
});

interface IpBucket {
  events: CorrelationEvent[];
}

function normalizePair(a: string, b: string): string {
  return a < b ? `${a}${b}` : `${b}${a}`;
}

/**
 * Rolling per-IP correlation window. Mirrors the Python
 * `CorrelationWindow` class.
 *
 * All detection helpers are read-only; only `record` mutates state.
 */
export class CorrelationWindow {
  private readonly windowSeconds: number;
  private readonly maxIps: number;
  private readonly maxEventsPerIp: number;
  private readonly scannerDistinctVectors: number;
  private readonly scannerMinRequests: number;
  private readonly csDistinctValues: number;
  private readonly raceWindowSeconds: number;
  private readonly racePairKeys: Set<string>;
  private readonly racePairTuples: Array<[string, string]>;

  // Map iteration order in JS is insertion order, so re-inserting on
  // access gives us LRU behaviour without a separate linked list.
  private readonly buckets: Map<string, IpBucket> = new Map();

  constructor(options: CorrelationWindowOptions = {}) {
    const {
      windowSeconds = 60,
      maxIps = 10_000,
      maxEventsPerIp = 200,
      scannerDistinctVectors = 3,
      scannerMinRequests = 20,
      credentialStuffingDistinctValues = 10,
      raceWindowMs = 200,
      racePairs,
    } = options;

    if (windowSeconds <= 0) throw new Error('windowSeconds must be > 0');
    if (maxIps < 1) throw new Error('maxIps must be >= 1');
    if (maxEventsPerIp < 1) throw new Error('maxEventsPerIp must be >= 1');

    this.windowSeconds = windowSeconds;
    this.maxIps = maxIps;
    this.maxEventsPerIp = maxEventsPerIp;
    this.scannerDistinctVectors = scannerDistinctVectors;
    this.scannerMinRequests = scannerMinRequests;
    this.csDistinctValues = credentialStuffingDistinctValues;
    this.raceWindowSeconds = raceWindowMs / 1000;
    this.racePairKeys = new Set();
    this.racePairTuples = [];
    if (racePairs) {
      for (const [a, b] of racePairs) {
        const key = normalizePair(a, b);
        if (!this.racePairKeys.has(key)) {
          this.racePairKeys.add(key);
          const sorted: [string, string] = a < b ? [a, b] : [b, a];
          this.racePairTuples.push(sorted);
        }
      }
    }
  }

  record(
    ip: string,
    vector: string,
    route: string,
    method = 'GET',
    distinctValue?: string,
    now?: number,
  ): CorrelationDetections {
    if (!ip) return EMPTY_DETECTIONS;
    const ts = now ?? Date.now() / 1000;
    const event: CorrelationEvent = {
      timestamp: ts,
      vector,
      route,
      method,
      distinctValue,
    };

    let bucket = this.buckets.get(ip);
    if (bucket === undefined) {
      bucket = { events: [] };
      this.buckets.set(ip, bucket);
      while (this.buckets.size > this.maxIps) {
        const oldest = this.buckets.keys().next().value as string | undefined;
        if (oldest === undefined) break;
        this.buckets.delete(oldest);
      }
    } else {
      // LRU touch: re-insert at the end.
      this.buckets.delete(ip);
      this.buckets.set(ip, bucket);
    }

    bucket.events.push(event);
    this.evictStale(bucket, ts);
    return this.evaluate(bucket, route);
  }

  detectScanner(ip: string, now?: number): boolean {
    const bucket = this.buckets.get(ip);
    if (bucket === undefined) return false;
    this.evictStale(bucket, now ?? Date.now() / 1000);
    return this.isScanner(bucket);
  }

  detectCredentialStuffing(ip: string, route: string, now?: number): boolean {
    const bucket = this.buckets.get(ip);
    if (bucket === undefined) return false;
    this.evictStale(bucket, now ?? Date.now() / 1000);
    return this.isCredentialStuffing(bucket, route);
  }

  detectRaceWindow(
    ip: string,
    routePair: [string, string],
    now?: number,
  ): boolean {
    const bucket = this.buckets.get(ip);
    if (bucket === undefined) return false;
    this.evictStale(bucket, now ?? Date.now() / 1000);
    const sorted: [string, string] =
      routePair[0] < routePair[1] ? routePair : [routePair[1], routePair[0]];
    return this.racePairInBucket(bucket, sorted);
  }

  reset(ip?: string): void {
    if (ip === undefined) {
      this.buckets.clear();
    } else {
      this.buckets.delete(ip);
    }
  }

  stats(): { trackedIps: number; eventsInWindow: number } {
    let events = 0;
    for (const b of this.buckets.values()) events += b.events.length;
    return { trackedIps: this.buckets.size, eventsInWindow: events };
  }

  // -------------------------------------------------------- internals

  private evictStale(bucket: IpBucket, now: number): void {
    const cutoff = now - this.windowSeconds;
    let drop = 0;
    while (drop < bucket.events.length && bucket.events[drop].timestamp < cutoff) {
      drop++;
    }
    if (drop > 0) bucket.events.splice(0, drop);
    if (bucket.events.length > this.maxEventsPerIp) {
      bucket.events.splice(0, bucket.events.length - this.maxEventsPerIp);
    }
  }

  private evaluate(bucket: IpBucket, route: string): CorrelationDetections {
    const vectors = new Set<string>();
    const values = new Set<string>();
    for (const e of bucket.events) {
      vectors.add(e.vector);
      if (e.route === route && e.distinctValue !== undefined) {
        values.add(e.distinctValue);
      }
    }
    return {
      scanner: this.isScanner(bucket),
      credentialStuffing: this.isCredentialStuffing(bucket, route),
      raceWindow: this.isRaceAny(bucket),
      distinctVectors: vectors.size,
      distinctValues: values.size,
      requestsInWindow: bucket.events.length,
    };
  }

  private isScanner(bucket: IpBucket): boolean {
    if (bucket.events.length < this.scannerMinRequests) return false;
    const vectors = new Set<string>();
    for (const e of bucket.events) vectors.add(e.vector);
    return vectors.size >= this.scannerDistinctVectors;
  }

  private isCredentialStuffing(bucket: IpBucket, route: string): boolean {
    const values = new Set<string>();
    for (const e of bucket.events) {
      if (e.route === route && e.distinctValue !== undefined) {
        values.add(e.distinctValue);
      }
    }
    return values.size >= this.csDistinctValues;
  }

  private racePairInBucket(bucket: IpBucket, sorted: [string, string]): boolean {
    const [a, b] = sorted;
    const aTs: number[] = [];
    const bTs: number[] = [];
    for (const e of bucket.events) {
      if (e.route === a) aTs.push(e.timestamp);
      else if (e.route === b) bTs.push(e.timestamp);
    }
    if (aTs.length === 0 || bTs.length === 0) return false;
    let ai = 0;
    let bi = 0;
    while (ai < aTs.length && bi < bTs.length) {
      const diff = aTs[ai] - bTs[bi];
      if (Math.abs(diff) <= this.raceWindowSeconds) return true;
      if (diff < 0) ai++;
      else bi++;
    }
    return false;
  }

  private isRaceAny(bucket: IpBucket): boolean {
    for (const pair of this.racePairTuples) {
      if (this.racePairInBucket(bucket, pair)) return true;
    }
    return false;
  }
}
