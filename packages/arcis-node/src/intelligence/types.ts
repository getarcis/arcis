/**
 * @module @arcis/node/intelligence/types
 * Types for the optional cloud intelligence client (IP reputation refresh).
 *
 * Opt-in: when omitted, the SDK does zero network work and stays fully local.
 * The data is served by an Arcis intelligence endpoint (the dashboard's
 * /v1/intel/* routes). Reputation is one signal in a multi-signal decision,
 * never a standalone verdict.
 */

/**
 * A cloud capability the SDK may opt into.
 * - `ip-rep`: per-request IP reputation lookups (cache-first).
 * - `bot-corpus`: refresh the bot fingerprint corpus from the cloud and merge
 *   it on top of the bundled corpus (so new scanners/AI crawlers are classified
 *   without an SDK release).
 */
export type CloudDecision = 'ip-rep' | 'bot-corpus';

/**
 * One bot-corpus entry as served by the intelligence endpoint. Same shape the
 * bot detector compiles, so a fetched entry merges with no transformation.
 */
export interface BotCorpusEntry {
  id: string;
  category: string;
  name: string;
  patterns: string[];
  forbidden: string[];
}

/** Result of an IP reputation lookup. `found:false` for unknown / clean IPs. */
export interface IpReputation {
  /** The address that was looked up. */
  ip: string;
  /** Whether the intelligence service had an indicator for this IP. */
  found: boolean;
  /** Aggregated severity, 1-10. Higher is worse. Present only when found. */
  severity?: number;
  /** Reputation categories, e.g. ['tor', 'scanner']. Present only when found. */
  categories?: string[];
  /** Feeds that reported this IP, e.g. ['tor-exit']. Present only when found. */
  sources?: string[];
  /** First-seen date (YYYY-MM-DD), when present. */
  firstSeen?: string;
  /** Last-seen date (YYYY-MM-DD), when present. */
  lastSeen?: string;
  /** The stored key that matched (the exact IP, or a containing CIDR). */
  matched?: string;
}

/** Configuration for the cloud intelligence client, passed via ArcisOptions.intelligence. */
export interface IntelligenceOptions {
  /**
   * Base URL of the Arcis intelligence service, e.g.
   * "https://arcis.mycorp.com". The client appends
   * "/v1/intel/ip-reputation/:ip". Required to activate.
   */
  endpoint: string;
  /** API key. Sent as `Authorization: Bearer <apiKey>`. */
  apiKey?: string;
  /** Workspace id. Sent as `x-workspace-id`. */
  workspaceId?: string;
  /**
   * Which cloud decisions to enable. Include 'ip-rep' to turn on IP reputation
   * lookups. Omitted / empty = the client is inert (no network calls).
   */
  cloudDecisions?: CloudDecision[];
  /**
   * Block a request when the looked-up IP severity is at or above this
   * threshold (1-10). Omitted = never block on reputation alone (annotate
   * only). Reputation is a signal, not a binary gate, so observe-only is the
   * default.
   */
  blockThreshold?: number;
  /** Local LRU cache capacity (entries). Default 1000. */
  cacheMax?: number;
  /** Local cache TTL in milliseconds. Default 3600000 (1 hour). */
  cacheTtlMs?: number;
  /** Per-lookup network timeout in milliseconds. Default 2000. */
  timeoutMs?: number;
  /**
   * How often to re-fetch the bot corpus when `cloudDecisions` includes
   * `bot-corpus`. Default 604800000 (7 days). The first fetch fires on startup.
   */
  botCorpusRefreshMs?: number;
  /**
   * Error hook for network/HTTP failures. Omitted = swallowed silently
   * (fail-open: an unreachable intelligence service never affects requests).
   */
  onError?: (err: Error) => void;
}
