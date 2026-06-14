/**
 * @module @arcis/node/core/constants
 * Named constants for Arcis - no magic numbers
 */

import { compileCategory, compileRule, dangerousKeysFor } from './patterns-loader';

// =============================================================================
// INPUT LIMITS
// =============================================================================
export const INPUT = {
  /** Default maximum input size (1MB) */
  DEFAULT_MAX_SIZE: 1_000_000,
  /** Maximum recursion depth for nested objects */
  MAX_RECURSION_DEPTH: 10,
} as const;

// =============================================================================
// RATE LIMITING
// =============================================================================
export const RATE_LIMIT = {
  /** Default window size (1 minute) */
  DEFAULT_WINDOW_MS: 60_000,
  /** Default max requests per window */
  DEFAULT_MAX_REQUESTS: 100,
  /** Default HTTP status code for rate limited responses */
  DEFAULT_STATUS_CODE: 429,
  /** Default error message */
  DEFAULT_MESSAGE: 'Too many requests, please try again later.',
  /** Minimum window size (1 second) */
  MIN_WINDOW_MS: 1_000,
  /** Maximum window size (24 hours) */
  MAX_WINDOW_MS: 86_400_000,
} as const;

// =============================================================================
// SECURITY HEADERS
// =============================================================================
export const HEADERS = {
  /** Default Content Security Policy */
  DEFAULT_CSP: [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
  ].join('; '),
  /** Default HSTS max age (1 year in seconds) */
  HSTS_MAX_AGE: 31_536_000,
  /** Default X-Frame-Options value */
  FRAME_OPTIONS: 'DENY' as const,
  /** Default X-Content-Type-Options value */
  CONTENT_TYPE_OPTIONS: 'nosniff',
  /** Default Referrer-Policy value */
  REFERRER_POLICY: 'strict-origin-when-cross-origin',
  /** Default Permissions-Policy value */
  PERMISSIONS_POLICY: 'geolocation=(), microphone=(), camera=()',
  /** Default Cache-Control value for security */
  CACHE_CONTROL: 'no-store, no-cache, must-revalidate, proxy-revalidate',
} as const;

// =============================================================================
// XSS PATTERNS (sourced from patterns.json)
// =============================================================================

/**
 * XSS patterns, compiled from the shared `patterns.json` `xss` category.
 *
 * Both detection (detectXss) and removal (sanitizeXss) iterate the same rule
 * list: the rules are precise capture patterns (full tag / attribute / protocol)
 * so they double as removal targets, and patterns.json file order keeps every
 * block rule (e.g. `<script>...</script>`) ahead of its bare-tag counterpart so
 * removal strips the larger match first. Pre-migration these were two hardcoded
 * arrays (a broad detect set + a precise remove set); single-sourcing them here
 * ends the dual-write against patterns.json and converges Node onto the same
 * detection Python + Go already ship (Pattern 2 + Pattern 7).
 */
export const XSS_PATTERNS = compileCategory('xss');

/** Removal patterns for sanitizeXss(): the same patterns.json `xss` rules.
 *  A separate compiled array so its RegExp lastIndex state is independent of
 *  the detection pass. */
export const XSS_REMOVE_PATTERNS = compileCategory('xss');

// =============================================================================
// SQL INJECTION PATTERNS (sourced from patterns.json)
// =============================================================================
/** Compiled from the shared `patterns.json` `sql_injection` category. The
 *  quoted-boolean rules use RE2-safe `['"]...['"]` (no backreference) since
 *  patterns.json is also consumed by Go's RE2 engine; validated equivalent to
 *  the former backreference forms on the O'Brien / tautology corpus. */
export const SQL_PATTERNS = compileCategory('sql_injection');

// =============================================================================
// PATH TRAVERSAL PATTERNS (sourced from patterns.json)
// =============================================================================
/** Compiled from the shared `patterns.json` `path_traversal` category. */
export const PATH_PATTERNS = compileCategory('path_traversal');

// =============================================================================
// COMMAND INJECTION PATTERNS (sourced from patterns.json)
// =============================================================================
/** Compiled from the shared `patterns.json` `command_injection` category. */
export const COMMAND_PATTERNS = compileCategory('command_injection');

// =============================================================================
// DANGEROUS KEYS
// =============================================================================

/**
 * Prototype pollution keys to block.
 * Stored lowercase — always compare with key.toLowerCase().
 *
 * Includes:
 * - __proto__: direct prototype assignment
 * - constructor: access to constructor.prototype chain
 * - prototype: direct prototype property
 * - __defineGetter__/__defineSetter__: legacy property definition (can override getters/setters)
 * - __lookupGetter__/__lookupSetter__: legacy property introspection
 */
export const DANGEROUS_PROTO_KEYS = new Set(dangerousKeysFor('prototype_pollution'));

/** MongoDB operators to block, from `patterns.json` nosql_injection.dangerous_keys. */
export const NOSQL_DANGEROUS_KEYS = new Set(dangerousKeysFor('nosql_injection'));

/**
 * String-form NoSQL operator detection (block-mode scanThreats).
 *
 * NOSQL_DANGEROUS_KEYS catches operators that arrive as OBJECT KEYS
 * (`{"$gt": ""}`). But MongoDB operators also bypass as STRING VALUES —
 * query params like `?username[$ne]=1` arrive as the literal string
 * `$ne` before the body parser ever builds an object, and mongo-shell
 * payloads (`$where: '1==1'`) are plain strings. Node previously had no
 * string-level NoSQL check, so GoTestWAF scored NoSQL at 0% while Python
 * (which loads the shared `nosql-operators` rule) caught these. This
 * closes that Pattern-7 parity gap.
 *
 * Sourced from the `nosql-operators` rule in patterns.json. The trailing
 * `\b` word boundary keeps `$invoice`/`$order`/`$index` from matching
 * `$in`/`$or` (a false-positive class the un-bounded rule had).
 */
const nosqlStringRule = compileRule('nosql_injection', 'nosql-operators');
if (!nosqlStringRule) {
  throw new Error('arcis: nosql-operators rule missing from patterns.json');
}
export const NOSQL_STRING_PATTERN = nosqlStringRule;

/**
 * Identity/auth field names that must hold a scalar value. A field here
 * carrying an array or object is a NoSQL type-juggling operator-injection
 * shape (e.g. {"username":["admin"]}). v1.7 nosql-type-juggle.
 */
export const AUTH_FIELDS = new Set([
  'username', 'user', 'userid', 'user_id', 'login', 'email',
  'password', 'pass', 'passwd', 'pwd', 'token', 'apikey', 'api_key',
  'secret', 'otp', 'pin',
]);

// =============================================================================
// REDACTION
// =============================================================================
export const REDACTION = {
  /** Replacement text for redacted values */
  REPLACEMENT: '[REDACTED]',
  /** Truncation indicator */
  TRUNCATED: '[TRUNCATED]',
  /** Max depth indicator */
  MAX_DEPTH: '[MAX_DEPTH]',
  /** Default max message length */
  DEFAULT_MAX_LENGTH: 10_000,
  /** Default sensitive keys to redact */
  SENSITIVE_KEYS: new Set([
    'password', 'passwd', 'pwd', 'secret', 'token', 'apikey',
    'api_key', 'apiKey', 'auth', 'authorization', 'credit_card',
    'creditcard', 'cc', 'ssn', 'social_security', 'private_key',
    'privateKey', 'access_token', 'accessToken', 'refresh_token',
    'refreshToken', 'bearer', 'jwt', 'session', 'cookie',
    'credentials', 'x-api-key', 'x-auth-token',
  ]),
} as const;

// =============================================================================
// VALIDATION PATTERNS
// =============================================================================
export const VALIDATION = {
  /**
   * Email regex pattern.
   * Rejects consecutive dots in local part (e.g. test..foo@example.com),
   * leading/trailing dots, and other common invalid forms.
   */
  EMAIL: /^[^\s@.][^\s@]*(?:\.[^\s@.][^\s@]*)*@[^\s@]+\.[^\s@]+$/,
  /**
   * URL regex pattern.
   * Only allows http:// and https:// (case-insensitive scheme per
   * RFC 3986); explicitly rejects javascript:, data:, vbscript:, and
   * other dangerous URI schemes.
   */
  URL: /^https?:\/\/[^\s/$.?#][^\s]*$/i,
  /** UUID regex pattern (v4) */
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
} as const;

// =============================================================================
// ERROR MESSAGES
// =============================================================================
export const ERRORS = {
  /** Generic error message (production) */
  INTERNAL_SERVER_ERROR: 'Internal Server Error',
  /** Input too large error */
  INPUT_TOO_LARGE: (maxSize: number) => `Input exceeds maximum size of ${maxSize} bytes`,
  /** Validation error messages */
  VALIDATION: {
    REQUIRED: (field: string) => `${field} is required`,
    INVALID_TYPE: (field: string, type: string) => `${field} must be a ${type}`,
    MIN_LENGTH: (field: string, min: number) => `${field} must be at least ${min} characters`,
    MAX_LENGTH: (field: string, max: number) => `${field} must be at most ${max} characters`,
    MIN_VALUE: (field: string, min: number) => `${field} must be at least ${min}`,
    MAX_VALUE: (field: string, max: number) => `${field} must be at most ${max}`,
    INVALID_FORMAT: (field: string) => `${field} format is invalid`,
    INVALID_EMAIL: (field: string) => `${field} must be a valid email`,
    INVALID_URL: (field: string) => `${field} must be a valid URL`,
    INVALID_UUID: (field: string) => `${field} must be a valid UUID`,
    INVALID_ENUM: (field: string, values: unknown[]) => `${field} must be one of: ${values.join(', ')}`,
    MIN_ITEMS: (field: string, min: number) => `${field} must have at least ${min} items`,
    MAX_ITEMS: (field: string, max: number) => `${field} must have at most ${max} items`,
  },
} as const;

// =============================================================================
// BLOCKED TEXT (for sanitizer replacements)
// =============================================================================
export const BLOCKED = '[BLOCKED]' as const;
