/**
 * @module @arcis/node/core/types
 * All TypeScript interfaces and types for Arcis
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { TelemetryOptions } from '../telemetry/types';

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
  type: 'xss' | 'sql' | 'nosql' | 'path' | 'command' | 'prototype' | 'ssti' | 'xxe';
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
