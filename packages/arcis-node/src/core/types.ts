/**
 * @module @arcis/node/core/types
 * All TypeScript interfaces and types for Arcis
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { TelemetryOptions } from '../telemetry/types';
import type { IntelligenceOptions } from '../intelligence/types';

// =============================================================================
// MAIN CONFIGURATION
// =============================================================================

/** Main Arcis configuration options */
export interface ArcisOptions {
  /** Enable/configure input sanitization. Default: true */
  sanitize?: boolean | SanitizeOptions;
  /** Enable/configure rate limiting. Default: true */
  rateLimit?: boolean | RateLimitOptions;
  /** Enable/configure security headers. Default: true */
  headers?: boolean | HeaderOptions;
  /**
   * Enable/configure bot User-Agent classification. Default: true.
   * Default deny list when enabled: ['AUTOMATED', 'SCRAPER'] (more aggressive
   * than the standalone `botProtection` factory which only denies AUTOMATED).
   * Pass `false` to disable. Pass a `BotProtectionOptions` object to override.
   */
  bot?: boolean | import('../middleware/bot-detection').BotProtectionOptions;
  /**
   * Enable/configure sensitive-path probe blocking (v1.7 W2). Default: true.
   * Blocks well-known scanner probe paths like `/.env`, `/.git/`, `/wp-admin`,
   * `/phpmyadmin`, etc. Pass `false` to disable. Pass an options object to
   * customize the matcher list or status code. See `SENSITIVE_PATH_PATTERNS`
   * for the default list. Apps with a legitimate `/admin` panel or running
   * actual WordPress should override `patterns` to a narrower set.
   */
  scannerPaths?: boolean | import('../middleware/sensitive-paths').ScannerPathsOptions;
  /**
   * Enable/configure GraphQL inspection (v1.7 W3). Default: true.
   * When a request body contains a `query` field that looks like a
   * GraphQL document, inspect it for depth-bomb, alias-bomb, fragment
   * cycle, and introspection abuse. Blocks on threshold breach.
   *
   * Default thresholds are tighter than the standalone
   * `inspectGraphqlQuery` defaults: maxDepth=10, maxAliases=10 (vs 50),
   * blockIntrospection=true, blockFragmentCycles=true. Real apps using
   * Apollo Studio in dev should pass `{ blockIntrospection: false }`
   * in their dev profile. Pass `false` to disable entirely.
   */
  graphql?: boolean | import('../sanitizers/graphql').GraphqlGuardOptions;
  /**
   * Enable/configure mass-assignment field detection (v1.7 W4). Default: true.
   * Scans JSON request bodies (recursively) for privilege-escalation field
   * names like `isAdmin`, `role`, `permissions` and blocks when one is
   * present. Detection-only (does not strip). Pass `false` to disable, or
   * an options object to customize the sensitive-field list / recursion
   * depth. Admin APIs that legitimately accept `role`/`permissions` should
   * disable this and use the allowlist filter (`applyMassAssignFilter`)
   * on those routes instead.
   */
  massAssign?: boolean | import('../sanitizers/mass-assignment').MassAssignDetectOptions;
  /**
   * Enable/configure SSRF body-URL validation (v1.7 W5). Default: true.
   * Walks JSON request bodies for URL-shaped string values and validates
   * each with the SSRF checker. Blocks URLs targeting private/loopback/
   * link-local/metadata addresses or disallowed schemes (`file:`,
   * `gopher:`, ...). Public URLs pass unchanged. Pass `false` to disable,
   * or a `ValidateUrlOptions` object (e.g. `{ allowedHosts: [...] }`) to
   * customize. Apps that legitimately accept internal URLs should scope
   * this off or pass `allowPrivate: true`.
   */
  ssrf?: boolean | import('../validation/url').ValidateUrlOptions;
  /**
   * Enable/configure prompt-injection detection on body strings (v1.7 W6).
   * Default: true. Scans string values in the JSON body for prompt-
   * injection / jailbreak / tool-call-forgery signatures and blocks when
   * a match at or above `minSeverity` is found. Default `minSeverity` is
   * `'medium'`. Pass `false` to disable, or `{ minSeverity: 'high' }` to
   * only block the highest-confidence overrides. Apps that legitimately
   * accept text discussing prompt injection (docs, support tickets)
   * should raise the threshold or disable this.
   */
  promptInjection?: boolean | { minSeverity?: 'low' | 'medium' | 'high' };
  /**
   * Enable/configure forwarded-header inspection (v1.7 W7). Default: true.
   * Flags a LOOPBACK address (127.x, ::1, localhost) in a forwarded /
   * client-IP header (X-Forwarded-For, X-Forwarded-Host, X-Real-IP,
   * Forwarded, Client-IP, True-Client-IP) — a client claiming to be
   * localhost is spoofing to bypass IP allowlists. Private ranges are NOT
   * flagged (internal load balancers legitimately add them). Pass an
   * options object with `trustedHosts: [...]` to also reject Host /
   * X-Forwarded-Host values not in the allowlist (host-header poisoning);
   * without it, host validation is off. Pass `false` to disable entirely.
   */
  forwardedHeaders?: boolean | { trustedHosts?: string[] };
  /** Enable/configure safe logging. Default: true */
  logging?: boolean | LogOptions;
  /**
   * When true, the sanitizer middleware blocks attack payloads (returns 403)
   * instead of silently sanitizing. Forwards to SanitizeOptions.block. Opt-in.
   */
  block?: boolean;
  /**
   * Stream decision events to a dashboard endpoint. Opt-in: zero overhead when omitted.
   * See spec/API_SPEC.md §9.
   */
  telemetry?: TelemetryOptions;
  /**
   * Opt-in cloud intelligence (IP reputation). When set with
   * `cloudDecisions: ['ip-rep']` and an `endpoint`, the middleware consults a
   * locally-cached IP reputation feed served by an Arcis intelligence endpoint.
   * Lookups are cache-first and never block the request path; an unreachable
   * service fails open. Omitted = zero network work, fully local.
   *
   * Reputation is a signal, not a binary gate: blocking on it requires an
   * explicit `blockThreshold`. Without one, the verdict is attached to the
   * request for observability (telemetry) but does not block.
   */
  intelligence?: IntelligenceOptions;
  /**
   * Dry-run mode: detection runs as normal but the middleware never blocks,
   * never strips, and never returns 429. Pair with `onSanitize` to log what
   * WOULD have been blocked before flipping enforcement on. Issue #47.
   *
   * When true, this overrides `block: true` and suppresses rate-limit 429
   * responses (the X-RateLimit-* headers still surface so dashboards see
   * what the limiter decided).
   */
  dryRun?: boolean;
  /**
   * Callback invoked once per detected threat per request. Fires regardless
   * of `block` / `dryRun` mode — the hook is informational, not control flow.
   * Errors thrown from the callback are caught and swallowed so a buggy
   * observer can't break the response.
   *
   * Use case: deploy with `dryRun: true` + `onSanitize: (e) => log(e)`,
   * collect a few days of events, audit for false positives, then flip
   * `dryRun: false` to enforce.
   */
  onSanitize?: (event: SanitizeEvent) => void;
}

/** One entry passed to the `onSanitize` callback. */
export interface SanitizeEvent {
  /** Threat vector — same wire shape as `ThreatHit.vector`. */
  type:
    | 'xss'
    | 'sql'
    | 'nosql'
    | 'path'
    | 'command'
    | 'prototype'
    | 'ssti'
    | 'xxe'
    | 'ldap'
    | 'xpath'
    | 'header'
    | 'deserialization';
  /** Where the hit was found, e.g. `body.name`, `query.q`, `params.id`, `path`. */
  field: string;
  /** First 80 chars of the offending value (truncated to keep logs sane). */
  original: string;
  /** Matched pattern excerpt — same string `ThreatHit.matchedPattern` carries. */
  pattern: string;
}

// =============================================================================
// SANITIZERS
// =============================================================================

/** Sanitization configuration */
export interface SanitizeOptions {
  /** Sanitize XSS attempts. Default: true */
  xss?: boolean;
  /** Sanitize SQL injection attempts. Default: true */
  sql?: boolean;
  /** Sanitize NoSQL injection attempts. Default: true */
  nosql?: boolean;
  /** Sanitize path traversal attempts. Default: true */
  path?: boolean;
  /** Protect against prototype pollution. Default: true */
  proto?: boolean;
  /** Sanitize command injection attempts. Default: true */
  command?: boolean;
  /** Maximum input size in bytes. Default: 1000000 (1MB) */
  maxSize?: number;
  /**
   * How to handle detected SQL and command injection threats.
   * - 'reject': Throw SecurityThreatError (returns 400). Recommended for APIs. Default.
   * - 'sanitize': Strip/replace threats in-place. Use only when rejection is not feasible.
   */
  mode?: 'sanitize' | 'reject';
  /**
   * HTML-encode output after XSS stripping.
   * Enable for SSR/template rendering. Do NOT enable for JSON REST APIs
   * — it corrupts stored data with HTML entities. Default: false.
   */
  htmlEncode?: boolean;
  /** Freeze sanitized objects with Object.freeze() to prevent mutation. Default: false */
  freeze?: boolean;
  /**
   * When true, scan req.body, req.query, req.params for attack patterns and
   * respond 403 with a SECURITY_THREAT payload instead of silently sanitizing.
   * Writes the deny decision to the telemetry marker. Default: false (opt-in).
   */
  block?: boolean;
}

/** Result of sanitizing a string */
export interface SanitizeResult {
  /** The sanitized value */
  value: string;
  /** Whether any sanitization was applied */
  wasSanitized: boolean;
  /** Details about detected threats */
  threats: ThreatInfo[];
}

/** Information about a detected threat */
export interface ThreatInfo {
  /** Type of threat detected */
  type: ThreatType;
  /** Pattern that matched */
  pattern: string;
  /** Original matched content */
  original: string;
  /** Location in the input (if applicable) */
  location?: string;
}

/** Types of security threats */
export type ThreatType =
  | 'xss'
  | 'sql_injection'
  | 'nosql_injection'
  | 'path_traversal'
  | 'command_injection'
  | 'prototype_pollution'
  | 'header_injection'
  | 'ssti'
  | 'xxe';

// =============================================================================
// RATE LIMITING
// =============================================================================

/** Rate limiting configuration */
export interface RateLimitOptions {
  /** Maximum requests per window. Default: 100 */
  max?: number;
  /** Window size in milliseconds. Default: 60000 (1 minute) */
  windowMs?: number;
  /** Error message when limit exceeded */
  message?: string;
  /** HTTP status code for rate limited responses. Default: 429 */
  statusCode?: number;
  /** Function to generate rate limit key from request */
  keyGenerator?: (req: Request) => string;
  /** Function to skip rate limiting for certain requests */
  skip?: (req: Request) => boolean;
  /** Optional external store for distributed rate limiting */
  store?: RateLimitStore;
}

/** External store interface for distributed rate limiting */
export interface RateLimitStore {
  /** Get current count for a key */
  get(key: string): Promise<RateLimitEntry | null>;
  /** Set entry for a key */
  set(key: string, entry: RateLimitEntry): Promise<void>;
  /** Increment count for a key */
  increment(key: string): Promise<number>;
  /** Decrement count for a key (for sliding window) */
  decrement?(key: string): Promise<void>;
  /** Reset count for a key */
  reset?(key: string): Promise<void>;
  /** Close the store (cleanup connections) */
  close?(): Promise<void>;
}

/** Rate limit entry stored in a store */
export interface RateLimitEntry {
  /** Number of requests in the current window */
  count: number;
  /** Timestamp when the window resets */
  resetTime: number;
}

/** Result from incrementing a rate limit counter */
export interface RateLimitResult {
  /** Current request count */
  count: number;
  /** When the window resets */
  resetTime: Date;
}

/** Rate limiter middleware with cleanup support */
export interface RateLimiterMiddleware extends RequestHandler {
  /** Clean up the rate limiter (clear intervals, close stores) */
  close: () => void;
}

// =============================================================================
// SECURITY HEADERS
// =============================================================================

/** Security headers configuration */
export interface HeaderOptions {
  /** Content Security Policy. true = default, string = custom, false = disabled */
  contentSecurityPolicy?: boolean | string;
  /** Enable X-XSS-Protection header. Default: true (sends '0' to disable legacy XSS auditor) */
  xssFilter?: boolean;
  /** Enable X-Content-Type-Options: nosniff. Default: true */
  noSniff?: boolean;
  /** X-Frame-Options value. Default: 'DENY' */
  frameOptions?: 'DENY' | 'SAMEORIGIN' | false;
  /** HSTS configuration. Default: true */
  hsts?: boolean | HstsOptions;
  /** Referrer-Policy value. Default: 'strict-origin-when-cross-origin' */
  referrerPolicy?: string | false;
  /** Permissions-Policy value */
  permissionsPolicy?: string | false;
  /** Cache-Control configuration. Default: true (no-cache) */
  cacheControl?: boolean | string;
  /** Cross-Origin-Opener-Policy value. Default: 'same-origin'. false to disable. */
  crossOriginOpenerPolicy?: string | false;
  /** Cross-Origin-Resource-Policy value. Default: 'same-origin'. false to disable. */
  crossOriginResourcePolicy?: string | false;
  /** Cross-Origin-Embedder-Policy value. Default: 'require-corp'. false to disable. */
  crossOriginEmbedderPolicy?: string | false;
  /** Origin-Agent-Cluster header. Default: true (sends '?1'). false to disable. */
  originAgentCluster?: boolean;
  /** X-DNS-Prefetch-Control value. Default: true (sends 'off'). false to disable. */
  dnsPrefetchControl?: boolean;
}

/** HSTS (HTTP Strict Transport Security) options */
export interface HstsOptions {
  /** Max age in seconds. Default: 31536000 (1 year) */
  maxAge?: number;
  /** Include subdomains. Default: true */
  includeSubDomains?: boolean;
  /** Enable HSTS preload. Default: false */
  preload?: boolean;
}

// =============================================================================
// VALIDATION
// =============================================================================

/** Validation configuration */
export interface ValidationConfig {
  /** Strip fields not in schema. Default: true (prevents mass assignment) */
  stripUnknown?: boolean;
  /** Stop on first error. Default: false */
  abortEarly?: boolean;
}

/** Validation schema for request data */
export interface ValidationSchema {
  [key: string]: FieldValidator;
}

/** Field validation rules */
export interface FieldValidator {
  /** Expected data type */
  type: 'string' | 'number' | 'boolean' | 'email' | 'url' | 'uuid' | 'array' | 'object';
  /** Whether field is required. Default: false */
  required?: boolean;
  /** Minimum value (number) or length (string/array) */
  min?: number;
  /** Maximum value (number) or length (string/array) */
  max?: number;
  /** Regex pattern for string validation */
  pattern?: RegExp;
  /** Allowed values */
  enum?: unknown[];
  /** Whether to sanitize the value. Default: true */
  sanitize?: boolean;
  /**
   * Custom validation function.
   * Return `true` to pass, `false` to fail with a default message,
   * or a non-empty string to fail with that message.
   * Returning `undefined` (i.e. forgetting to return) throws at runtime.
   */
  custom?: (value: unknown) => true | false | string;
}

/** Validation result */
export interface ValidationResult {
  /** Whether validation passed */
  valid: boolean;
  /** Validation errors */
  errors: ValidationError[];
  /** Validated and sanitized data */
  data: Record<string, unknown>;
}

/** Single validation error */
export interface ValidationError {
  /** Field that failed validation */
  field: string;
  /** Human-readable error message */
  message: string;
  /** Error code for programmatic handling */
  code: string;
}

// =============================================================================
// LOGGING
// =============================================================================

/** Safe logging configuration */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';

export interface LogOptions {
  /** Additional keys to redact beyond defaults */
  redactKeys?: string[];
  /** Maximum message length before truncation. Default: 10000 */
  maxLength?: number;
  /** Additional patterns to redact (e.g., custom tokens) */
  redactPatterns?: RegExp[];
  /** Minimum log level. Messages below this level are skipped (no redaction work). Default: 'debug' */
  level?: LogLevel;
}

/** Safe logger interface */
export interface SafeLogger {
  /** Log at specified level */
  log: (level: string, message: string, data?: unknown) => void;
  /** Log info message */
  info: (message: string, data?: unknown) => void;
  /** Log warning message */
  warn: (message: string, data?: unknown) => void;
  /** Log error message */
  error: (message: string, data?: unknown) => void;
  /** Log debug message */
  debug: (message: string, data?: unknown) => void;
}

// =============================================================================
// ERROR HANDLING
// =============================================================================

/** Error handler configuration */
export interface ErrorHandlerOptions {
  /** Show stack traces and detailed errors. Default: false */
  isDev?: boolean;
  /** Log errors. Default: true */
  logErrors?: boolean;
  /** Custom error logger */
  logger?: SafeLogger;
  /** Custom error handler */
  customHandler?: (err: Error, req: Request, res: Response) => void;
}

/** Extended Error with optional status code */
export interface HttpError extends Error {
  statusCode?: number;
  status?: number;
  /**
   * Whether the error message is safe to expose to API clients.
   * Set to true for known client-facing errors (4xx with controlled messages).
   * Defaults to false — message is hidden in production unless explicitly exposed.
   */
  expose?: boolean;
}

// =============================================================================
// MIDDLEWARE TYPES
// =============================================================================

/** Generic Arcis middleware type */
export type ArcisMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => void | Promise<void>;

/** Array of middlewares returned by arcis() with an attached cleanup method */
export type ArcisMiddlewareStack = RequestHandler[] & {
  /** Clean up resources created by arcis() (rate limiter intervals, etc.) */
  close: () => void;
};

/** Arcis function with attached utilities */
export interface ArcisFunction {
  (options?: ArcisOptions): ArcisMiddlewareStack;
  sanitize: (options?: SanitizeOptions) => RequestHandler;
  rateLimit: (options?: RateLimitOptions) => RateLimiterMiddleware;
  headers: (options?: HeaderOptions) => RequestHandler;
  validate: (schema: ValidationSchema, source?: 'body' | 'query' | 'params') => RequestHandler;
  logger: (options?: LogOptions) => SafeLogger;
  errorHandler: (options?: ErrorHandlerOptions | boolean) => (err: Error, req: Request, res: Response, next: NextFunction) => void;
}
