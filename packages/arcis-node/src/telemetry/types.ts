/**
 * Telemetry contract — mirrors spec/API_SPEC.md §9 exactly.
 * Shape accepted by the Arcis dashboard server's POST /v1/events endpoint.
 */

export type TelemetryDecision = 'allow' | 'deny' | 'challenge';

export type TelemetrySeverity = 'critical' | 'high' | 'medium' | 'low';

/**
 * A single decision event emitted by the Arcis middleware.
 * All optional fields are filled server-side with defaults when omitted.
 */
export interface TelemetryEvent {
  /** ISO-8601 timestamp. SDK populates; server falls back to now() if missing. */
  ts?: string;
  /** Client IP extracted from the request. */
  ip: string;
  /** HTTP method (e.g., "GET", "POST"). */
  method: string;
  /** Request path without query string. */
  path: string;
  /** Final middleware decision. */
  decision: TelemetryDecision;
  /** Attack family (e.g., "xss", "sql", "ssrf"). Null for allowed traffic. */
  vector?: string;
  /** Specific rule fired (e.g., "sql/union-select"). */
  rule?: string;
  /** Finding severity. */
  severity?: TelemetrySeverity;
  /** ISO-3166 alpha-2 country code. */
  country?: string;
  /** Request User-Agent header. Server defaults to "" if missing. */
  userAgent?: string;
  /** Human-readable explanation for the dashboard. */
  reason?: string;
  /** HTTP status code returned by the middleware. Server defaults to 200. */
  status: number;
  /** Exact token that triggered the rule (e.g., "UNION SELECT"). */
  matchedPattern?: string;
  /** Middleware processing time in milliseconds, fractional. */
  latencyMs?: number;
}

/**
 * User-provided configuration for the telemetry client.
 * Passed via `telemetry` on the main `ArcisOptions`.
 */
export interface TelemetryOptions {
  /** Full URL of the ingest endpoint, e.g., "https://arcis.mycorp.com/v1/events". */
  endpoint: string;
  /** Optional bearer token. Sent as `Authorization: Bearer <apiKey>`. */
  apiKey?: string;
  /** Optional workspace id. Sent as `x-workspace-id`. Defaults server-side to "default". */
  workspaceId?: string;
  /** Flush when queue reaches this size. Default: 50. Range: 1-500. */
  batchSize?: number;
  /** Periodic flush interval in milliseconds. Default: 5000. Minimum: 500. */
  flushIntervalMs?: number;
  /** Error hook for network/HTTP failures. If omitted, errors are swallowed silently. */
  onError?: (err: Error) => void;
}
