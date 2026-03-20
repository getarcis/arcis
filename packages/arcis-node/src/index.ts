/**
 * Arcis - One-line security for Node.js apps
 * A cross-platform security library
 *
 * @module @arcis/node
 * @version 1.0.0
 *
 * @example
 * // Full protection (recommended)
 * import { arcis } from '@arcis/node';
 * app.use(arcis());
 *
 * @example
 * // Granular control
 * app.use(arcis.headers());
 * app.use(arcis.rateLimit({ max: 100, windowMs: 60000 }));
 * app.use(arcis.sanitize());
 *
 * @example
 * // With validation
 * app.post('/users', arcis.validate({
 *   email: { type: 'email', required: true },
 *   age: { type: 'number', min: 0, max: 150 }
 * }), handler);
 */

// =============================================================================
// MAIN EXPORT
// =============================================================================
export { arcis, arcisFunction } from './middleware/main';
export { default } from './middleware/main';

// =============================================================================
// MIDDLEWARE
// =============================================================================
export { createRateLimiter, rateLimit } from './middleware/rate-limit';
export { createSlidingWindowLimiter } from './middleware/rate-limit-sliding';
export { createTokenBucketLimiter } from './middleware/rate-limit-token';
export { createHeaders, securityHeaders } from './middleware/headers';
export { errorHandler, createErrorHandler } from './middleware/error-handler';
export { safeCors, createCors } from './middleware/cors';
export { secureCookieDefaults, createSecureCookies, enforceSecureCookie } from './middleware/cookies';
export { botProtection, detectBot } from './middleware/bot-detection';
export { csrfProtection, createCsrf, generateCsrfToken, validateCsrfToken } from './middleware/csrf';

// =============================================================================
// SANITIZERS
// =============================================================================
export { 
  sanitizeString, 
  sanitizeObject, 
  createSanitizer,
} from './sanitizers/sanitize';

export { sanitizeXss, detectXss } from './sanitizers/xss';
export { sanitizeSql, detectSql } from './sanitizers/sql';
export { sanitizePath, detectPathTraversal } from './sanitizers/path';
export { sanitizeCommand, detectCommandInjection } from './sanitizers/command';
export { sanitizeSsti, detectSsti } from './sanitizers/ssti';
export { sanitizeXxe, detectXxe } from './sanitizers/xxe';
export { sanitizeJsonpCallback, detectJsonpInjection } from './sanitizers/jsonp';
export { isDangerousNoSqlKey, detectNoSqlInjection } from './sanitizers/nosql';
export { isDangerousProtoKey, detectPrototypePollution } from './sanitizers/prototype';
export { sanitizeHeaderValue, sanitizeHeaders, detectHeaderInjection } from './sanitizers/headers';
export { scanPii, detectPii, redactPii, scanObjectPii, redactObjectPii } from './sanitizers/pii';

// =============================================================================
// VALIDATION
// =============================================================================
export { validate, createValidator } from './validation/schema';
export { validateUrl, isUrlSafe } from './validation/url';
export { validateRedirect, isRedirectSafe } from './validation/redirect';
export { validateFile, sanitizeFilename, isDangerousExtension } from './validation/file';
export { validateEmail, verifyEmailMx, isValidEmailSyntax } from './validation/email';

// =============================================================================
// UTILITIES
// =============================================================================
export { parseDuration, formatDuration } from './utils/duration';
export { detectClientIp, isPrivateIp } from './utils/ip';
export { fingerprint } from './utils/fingerprint';

// =============================================================================
// LOGGING
// =============================================================================
export { createSafeLogger, createRedactor, safeLog } from './logging/redactor';

// =============================================================================
// STORES
// =============================================================================
export { MemoryStore } from './stores/memory';
export { RedisStore, createRedisStore } from './stores/redis';

// =============================================================================
// TYPES
// =============================================================================
export type {
  // Main config
  ArcisOptions,
  ArcisFunction,
  ArcisMiddleware,
  // Sanitizers
  SanitizeOptions,
  SanitizeResult,
  ThreatInfo,
  ThreatType,
  // Rate limiting
  RateLimitOptions,
  RateLimitStore,
  RateLimitEntry,
  RateLimitResult,
  RateLimiterMiddleware,
  // Headers
  HeaderOptions,
  HstsOptions,
  // Validation
  ValidationConfig,
  ValidationSchema,
  FieldValidator,
  ValidationResult,
  ValidationError,
  // Logging
  LogOptions,
  SafeLogger,
  // Error handling
  ErrorHandlerOptions,
  HttpError,
} from './core/types';

// URL validation types
export type { ValidateUrlOptions, ValidateUrlResult } from './validation/url';
export type { CorsOptions } from './middleware/cors';
export type { SecureCookieOptions } from './middleware/cookies';
export type { ValidateFileOptions, FileInput, ValidateFileResult } from './validation/file';
export type { ValidateRedirectOptions, ValidateRedirectResult } from './validation/redirect';

// Redis store types
export type { RedisClientLike, RedisStoreOptions } from './stores/redis';

// Utility types
export type { Platform, DetectIpOptions } from './utils/ip';
export type { FingerprintOptions } from './utils/fingerprint';
export type { EmailValidationOptions, EmailValidationResult } from './validation/email';
export type { SlidingWindowOptions, SlidingWindowMiddleware } from './middleware/rate-limit-sliding';
export type { TokenBucketOptions, TokenBucketMiddleware } from './middleware/rate-limit-token';
export type { BotCategory, BotDetectionResult, BotProtectionOptions } from './middleware/bot-detection';
export type { CsrfOptions } from './middleware/csrf';
export type { PiiType, PiiMatch, PiiScanOptions, PiiRedactOptions } from './sanitizers/pii';

// =============================================================================
// ERRORS
// =============================================================================
export {
  ArcisError,
  ArcisValidationError,
  RateLimitError,
  InputTooLargeError,
  SecurityThreatError,
  SanitizationError,
} from './core/errors';

// =============================================================================
// CONSTANTS (for advanced users)
// =============================================================================
export {
  INPUT,
  RATE_LIMIT,
  HEADERS,
  REDACTION,
  VALIDATION,
  ERRORS,
  BLOCKED,
} from './core/constants';
