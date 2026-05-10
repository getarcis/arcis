/**
 * @module @arcis/node/logging/redactor
 * Safe logging with PII/secret redaction
 */

import { REDACTION, INPUT } from '../core/constants';
import type { LogOptions, SafeLogger } from '../core/types';

const LOG_LEVELS: Record<string, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  silent: 4,
};

/**
 * Create a safe logger that redacts sensitive data and prevents log injection.
 * 
 * @param options - Logger configuration
 * @returns SafeLogger instance
 * 
 * @example
 * const logger = createSafeLogger();
 * logger.info('User login', { email: 'user@test.com', password: 'secret' });
 * // Logs: { "email": "user@test.com", "password": "[REDACTED]" }
 * 
 * @example
 * // With custom redact keys
 * const logger = createSafeLogger({ redactKeys: ['customToken', 'internalId'] });
 */
export function createSafeLogger(options: LogOptions = {}): SafeLogger {
  const {
    redactKeys = [],
    maxLength = REDACTION.DEFAULT_MAX_LENGTH,
    redactPatterns = [],
    level: minLevel = 'debug',
  } = options;

  const minLevelNum = LOG_LEVELS[minLevel] ?? 0;

  // Combine default and custom keys (lowercase for case-insensitive matching)
  const allRedactKeys = new Set([
    ...Array.from(REDACTION.SENSITIVE_KEYS),
    ...redactKeys.map(k => k.toLowerCase()),
  ]);

  /**
   * Redact sensitive data from an object recursively.
   */
  function redact(obj: unknown, depth = 0): unknown {
    if (depth > INPUT.MAX_RECURSION_DEPTH) return REDACTION.MAX_DEPTH;
    if (obj === null || obj === undefined) return obj;

    if (typeof obj === 'string') {
      return redactString(obj, maxLength, redactPatterns);
    }

    if (typeof obj !== 'object') return obj;

    if (Array.isArray(obj)) {
      return obj.map(item => redact(item, depth + 1));
    }

    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      if (allRedactKeys.has(key.toLowerCase())) {
        result[key] = REDACTION.REPLACEMENT;
      } else {
        result[key] = redact(value, depth + 1);
      }
    }
    return result;
  }

  /**
   * Log a message at the specified level.
   */
  function log(level: string, message: string, data?: unknown): void {
    // Early exit: skip all work if message level is below minimum
    const levelNum = LOG_LEVELS[level] ?? 0;
    if (levelNum < minLevelNum) return;

    const entry: Record<string, unknown> = {
      timestamp: new Date().toISOString(),
      level,
      message: redactString(message, maxLength, redactPatterns),
    };

    if (data !== undefined) {
      entry.data = redact(data);
    }

    // eslint-disable-next-line no-console
    console.log(JSON.stringify(entry));
  }

  return {
    log,
    info: (msg: string, data?: unknown) => log('info', msg, data),
    warn: (msg: string, data?: unknown) => log('warn', msg, data),
    error: (msg: string, data?: unknown) => log('error', msg, data),
    debug: (msg: string, data?: unknown) => log('debug', msg, data),
  };
}

/**
 * Redact a string value.
 * Removes newlines (log injection prevention), applies patterns, and truncates.
 */
function redactString(str: string, maxLength: number, patterns: RegExp[]): string {
  // Remove newlines/tabs (log injection prevention) and genuine control characters.
  // Only strip C0/C1 control chars and null bytes — preserve all printable Unicode
  // (CJK, Cyrillic, Arabic, etc.) so multilingual content isn't silently lost.
  let safe = str
    .replace(/[\r\n\t]/g, ' ')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x80-\x9F]/g, '');

  // Apply custom redaction patterns
  for (const pattern of patterns) {
    safe = safe.replace(pattern, REDACTION.REPLACEMENT);
  }

  // Truncate if too long
  if (safe.length > maxLength) {
    safe = safe.substring(0, maxLength) + `...${REDACTION.TRUNCATED}`;
  }

  return safe;
}

/**
 * Create a redactor function for custom use.
 * 
 * @param sensitiveKeys - Keys to redact
 * @returns Redactor function
 */
export function createRedactor(sensitiveKeys: string[] = []): (obj: unknown) => unknown {
  const allKeys = new Set([
    ...Array.from(REDACTION.SENSITIVE_KEYS),
    ...sensitiveKeys.map(k => k.toLowerCase()),
  ]);

  function redact(obj: unknown, depth = 0): unknown {
    if (depth > INPUT.MAX_RECURSION_DEPTH) return REDACTION.MAX_DEPTH;
    if (obj === null || obj === undefined) return obj;
    if (typeof obj !== 'object') return obj;

    if (Array.isArray(obj)) {
      return obj.map(item => redact(item, depth + 1));
    }

    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      if (allKeys.has(key.toLowerCase())) {
        result[key] = REDACTION.REPLACEMENT;
      } else {
        result[key] = redact(value, depth + 1);
      }
    }
    return result;
  }

  return redact;
}

/**
 * Alias for createSafeLogger
 * @see createSafeLogger
 */
export const safeLog = createSafeLogger;
