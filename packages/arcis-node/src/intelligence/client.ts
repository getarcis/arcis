/**
 * @module @arcis/node/intelligence/client
 * Cloud IP-reputation client with a local LRU+TTL cache.
 *
 * Design rules:
 *   1. `check()` is synchronous and never blocks the request path. On a cache
 *      miss it returns `found:false` for THIS request and schedules a
 *      background refresh, so the hot path adds ~0ms. Subsequent requests from
 *      the same IP read the cached verdict (Pattern: opportunistic refresh, not
 *      on the hot path).
 *   2. Fail-open (Pattern 4): a network error, timeout, or non-200 resolves to
 *      `found:false` and never throws into the request path.
 *   3. Private / loopback / unresolved IPs are never looked up.
 *   4. A "not found" (clean) result IS cached so clean IPs are not re-queried
 *      every request; transport errors are NOT cached so they retry.
 */

import { isPrivateIp } from '../utils/ip';
import type { IntelligenceOptions, IpReputation, BotCorpusEntry } from './types';

const DEFAULT_CACHE_MAX = 1000;
const DEFAULT_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const DEFAULT_TIMEOUT_MS = 2000;
const MIN_TIMEOUT_MS = 100;

interface CacheEntry {
  value: IpReputation;
  expires: number;
}

/** Insertion-ordered LRU with per-entry TTL. */
class LruTtlCache {
  private readonly map = new Map<string, CacheEntry>();
  constructor(
    private readonly max: number,
    private readonly ttlMs: number,
  ) {}

  get(key: string): IpReputation | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expires) {
      this.map.delete(key);
      return undefined;
    }
    // Mark most-recently-used by reinserting at the tail.
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.value;
  }

  set(key: string, value: IpReputation): void {
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, { value, expires: Date.now() + this.ttlMs });
    while (this.map.size > this.max) {
      const oldest = this.map.keys().next().value;
      if (oldest === undefined) break;
      this.map.delete(oldest);
    }
  }

  clear(): void {
    this.map.clear();
  }

  get size(): number {
    return this.map.size;
  }
}

interface RawReputation {
  ip?: unknown;
  found?: unknown;
  severity?: unknown;
  categories?: unknown;
  sources?: unknown;
  first_seen?: unknown;
  last_seen?: unknown;
  matched?: unknown;
}

function asStringArray(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out = v.filter((s): s is string => typeof s === 'string');
  return out.length > 0 ? out : undefined;
}

/** Map the dashboard wire shape (snake_case) to the SDK result (camelCase). */
function normalize(ip: string, body: RawReputation): IpReputation {
  if (body.found !== true) return { ip, found: false };
  const result: IpReputation = { ip, found: true };
  if (typeof body.severity === 'number') result.severity = body.severity;
  const categories = asStringArray(body.categories);
  if (categories) result.categories = categories;
  const sources = asStringArray(body.sources);
  if (sources) result.sources = sources;
  if (typeof body.first_seen === 'string') result.firstSeen = body.first_seen;
  if (typeof body.last_seen === 'string') result.lastSeen = body.last_seen;
  if (typeof body.matched === 'string') result.matched = body.matched;
  return result;
}

function isBotCorpusEntry(v: unknown): v is BotCorpusEntry {
  if (typeof v !== 'object' || v === null) return false;
  const e = v as Record<string, unknown>;
  return (
    typeof e.id === 'string' &&
    typeof e.category === 'string' &&
    typeof e.name === 'string' &&
    Array.isArray(e.patterns) &&
    e.patterns.every((p) => typeof p === 'string') &&
    Array.isArray(e.forbidden) &&
    e.forbidden.every((p) => typeof p === 'string')
  );
}

export class IntelligenceClient {
  private readonly base: string;
  private readonly apiKey: string | undefined;
  private readonly workspaceId: string | undefined;
  private readonly timeoutMs: number;
  private readonly ipRepEnabled: boolean;
  private readonly onError: (err: Error) => void;
  private readonly cache: LruTtlCache;
  private readonly inFlight = new Set<string>();
  private closed = false;

  constructor(options: IntelligenceOptions) {
    if (!options.endpoint || typeof options.endpoint !== 'string') {
      throw new TypeError('IntelligenceClient: `endpoint` is required');
    }
    this.base = options.endpoint.replace(/\/+$/, '');
    this.apiKey = options.apiKey;
    this.workspaceId = options.workspaceId;
    this.timeoutMs = Math.max(MIN_TIMEOUT_MS, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    this.ipRepEnabled = (options.cloudDecisions ?? []).includes('ip-rep');
    this.onError = options.onError ?? (() => {
      // default: swallow (fail-open)
    });
    this.cache = new LruTtlCache(
      Math.max(1, options.cacheMax ?? DEFAULT_CACHE_MAX),
      Math.max(1000, options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS),
    );
  }

  /**
   * Synchronous, cache-first reputation read. Never blocks: a cache miss
   * returns `found:false` and schedules a background refresh so later requests
   * from the same IP get the verdict. Safe to call on the hot path.
   */
  check(ip: string): IpReputation {
    if (!this.ipRepEnabled || this.closed) return { ip, found: false };
    if (!ip || ip === 'unknown' || isPrivateIp(ip)) return { ip, found: false };
    const cached = this.cache.get(ip);
    if (cached) return cached;
    this.scheduleRefresh(ip);
    return { ip, found: false };
  }

  /**
   * Await a lookup and return the verdict. Fail-open: any transport error
   * resolves to `found:false`. Used by direct callers and tests; the request
   * path uses `check()` instead.
   */
  async lookup(ip: string): Promise<IpReputation> {
    if (!ip || ip === 'unknown' || isPrivateIp(ip)) return { ip, found: false };
    try {
      return await this.fetchReputation(ip);
    } catch (err) {
      this.safeNotify(err);
      return { ip, found: false };
    }
  }

  /**
   * Fetch the full bot corpus from the intelligence endpoint. Fail-open: any
   * transport/parse error resolves to an empty array (the caller keeps the
   * bundled corpus). Returns only well-formed entries.
   */
  async fetchBotCorpus(): Promise<BotCorpusEntry[]> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers: Record<string, string> = { accept: 'application/json' };
      if (this.apiKey) headers['authorization'] = `Bearer ${this.apiKey}`;
      if (this.workspaceId) headers['x-workspace-id'] = this.workspaceId;
      const res = await fetch(`${this.base}/v1/intel/bot-corpus/snapshot`, {
        headers,
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`bot-corpus fetch returned HTTP ${res.status}`);
      const body = (await res.json()) as { entries?: unknown };
      if (!Array.isArray(body.entries)) return [];
      return body.entries.filter(isBotCorpusEntry);
    } catch (err) {
      this.safeNotify(err);
      return [];
    } finally {
      clearTimeout(timer);
    }
  }

  /** Current number of cached entries. Useful for tests. */
  get cacheSize(): number {
    return this.cache.size;
  }

  /** Stop scheduling refreshes and drop the cache. Idempotent. */
  close(): void {
    this.closed = true;
    this.cache.clear();
    this.inFlight.clear();
  }

  // ── internals ───────────────────────────────────────────────────────────

  private scheduleRefresh(ip: string): void {
    if (this.inFlight.has(ip)) return;
    this.inFlight.add(ip);
    // Real results (including a clean "not found") are cached; transport
    // errors are not, so they retry on the next request from this IP.
    this.fetchReputation(ip)
      .then((rep) => {
        if (!this.closed) this.cache.set(ip, rep);
      })
      .catch((err) => this.safeNotify(err))
      .finally(() => this.inFlight.delete(ip));
  }

  private async fetchReputation(ip: string): Promise<IpReputation> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers: Record<string, string> = { accept: 'application/json' };
      if (this.apiKey) headers['authorization'] = `Bearer ${this.apiKey}`;
      if (this.workspaceId) headers['x-workspace-id'] = this.workspaceId;
      const url = `${this.base}/v1/intel/ip-reputation/${encodeURIComponent(ip)}`;
      const res = await fetch(url, { headers, signal: controller.signal });
      if (!res.ok) {
        throw new Error(`ip-reputation lookup returned HTTP ${res.status}`);
      }
      const body = (await res.json()) as RawReputation;
      return normalize(ip, body);
    } finally {
      clearTimeout(timer);
    }
  }

  private safeNotify(err: unknown): void {
    try {
      this.onError(err instanceof Error ? err : new Error(String(err)));
    } catch {
      // user hook must never bubble up
    }
  }
}

/** Map a numeric reputation severity (1-10) to a coarse telemetry severity. */
export function reputationSeverityTier(
  severity: number | undefined,
): 'critical' | 'high' | 'medium' | 'low' {
  const s = severity ?? 0;
  if (s >= 9) return 'critical';
  if (s >= 7) return 'high';
  if (s >= 4) return 'medium';
  return 'low';
}
