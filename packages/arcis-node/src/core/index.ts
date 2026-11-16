/**
 * @module @arcis/node/core
 * Core types, constants, and errors for Arcis
 */

// Types
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
  RateLimitIncrement,
  LegacyRateLimitStore,
  RateLimitEntry,
  RateLimitResult,
  RateLimiterMiddleware,
  // Headers
  HeaderOptions,
  LegacyHeaderOptions,
  BaselineHeaderOptions,
  ReferrerPolicyToken,
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
} from './types';

// Constants
export {
  INPUT,
  RATE_LIMIT,
  HEADERS,
  XSS_PATTERNS,
  SQL_PATTERNS,
  PATH_PATTERNS,
  COMMAND_PATTERNS,
  DANGEROUS_PROTO_KEYS,
  NOSQL_DANGEROUS_KEYS,
  REDACTION,
  VALIDATION,
  ERRORS,
  BLOCKED,
} from './constants';

// Errors
export {
  ArcisError,
  ValidationError as ArcisValidationError,
  RateLimitError,
  InputTooLargeError,
  SecurityThreatError,
  SanitizationError,
} from './errors';
