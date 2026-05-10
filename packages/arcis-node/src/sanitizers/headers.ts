/**
 * @module @arcis/node/sanitizers/headers
 * HTTP Header Injection & CRLF Injection prevention
 *
 * Prevents attackers from injecting newline characters (\r\n) into HTTP header
 * values, which can lead to response splitting, session fixation, XSS via
 * injected headers, and cache poisoning.
 */

import type { SanitizeResult, ThreatInfo } from '../core/types';

/**
 * Characters and sequences that enable header injection.
 * - \r\n (CRLF) — HTTP header delimiter, enables response splitting
 * - \r, \n alone — partial line breaks, some servers normalize to CRLF
 * - \0 (null byte) — can truncate header values in some implementations
 */
const HEADER_INJECTION_PATTERN = /\r\n|\r|\n|\0/g;

/**
 * Sanitizes a header value by stripping CRLF sequences, bare CR/LF, and null bytes.
 *
 * @param input - The header value to sanitize
 * @param collectThreats - Whether to collect threat information (default: false)
 * @returns Sanitized string or SanitizeResult if collectThreats is true
 *
 * @example
 * sanitizeHeaderValue("safe-value")
 * // Returns: "safe-value"
 *
 * sanitizeHeaderValue("value\r\nX-Injected: evil")
 * // Returns: "valueX-Injected: evil"
 */
export function sanitizeHeaderValue(input: string, collectThreats?: false): string;
export function sanitizeHeaderValue(input: string, collectThreats: true): SanitizeResult;
export function sanitizeHeaderValue(input: string, collectThreats = false): string | SanitizeResult {
  if (typeof input !== 'string') {
    return collectThreats
      ? { value: String(input), wasSanitized: false, threats: [] }
      : String(input);
  }

  const threats: ThreatInfo[] = [];
  let wasSanitized = false;

  if (HEADER_INJECTION_PATTERN.test(input)) {
    HEADER_INJECTION_PATTERN.lastIndex = 0;
    wasSanitized = true;

    if (collectThreats) {
      const matches = input.match(HEADER_INJECTION_PATTERN);
      if (matches) {
        for (const match of matches) {
          threats.push({
            type: 'header_injection',
            pattern: HEADER_INJECTION_PATTERN.source,
            original: match,
          });
        }
      }
    }
  }

  HEADER_INJECTION_PATTERN.lastIndex = 0;
  const value = input.replace(HEADER_INJECTION_PATTERN, '');

  if (collectThreats) {
    return { value, wasSanitized, threats };
  }

  return value;
}

/**
 * Sanitizes an object of header key-value pairs.
 * Strips CRLF/null bytes from both keys and values.
 *
 * @param headers - Object with header names as keys and header values as values
 * @returns New object with sanitized header names and values
 *
 * @example
 * sanitizeHeaders({ "X-Custom": "safe", "X-Bad\r\n": "value\r\ninjected" })
 * // Returns: { "X-Custom": "safe", "X-Bad": "valueinjected" }
 */
export function sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
  if (!headers || typeof headers !== 'object') {
    return {};
  }

  const result: Record<string, string> = {};

  for (const [key, value] of Object.entries(headers)) {
    const sanitizedKey = sanitizeHeaderValue(String(key));
    const sanitizedValue = sanitizeHeaderValue(String(value));
    result[sanitizedKey] = sanitizedValue;
  }

  return result;
}

/**
 * Checks if a string contains HTTP header injection patterns (CRLF, null bytes).
 * Does not sanitize — use sanitizeHeaderValue() for that.
 *
 * @param input - The string to check
 * @returns True if header injection patterns detected
 */
export function detectHeaderInjection(input: string): boolean {
  if (typeof input !== 'string') return false;

  HEADER_INJECTION_PATTERN.lastIndex = 0;
  return HEADER_INJECTION_PATTERN.test(input);
}

/**
 * Email-header injection prevention. Same byte-level threat as HTTP
 * header injection — `\r\n` in a user-controlled email field
 * (`To`, `From`, `Subject`, etc.) lets an attacker inject extra headers
 * (most commonly Bcc) and pivot a contact form into a spam relay.
 *
 * Aliased to the HTTP-header sanitizers because the wire-level fix is
 * identical: strip CRLF + null bytes from the value before
 * concatenating into the header. Use these in form-to-email handlers:
 *
 * ```ts
 * const subject = sanitizeEmailHeader(req.body.subject);
 * const to = sanitizeEmailHeader(req.body.to);
 * if (detectEmailHeaderInjection(req.body.to)) reject(...);
 * ```
 */
export const sanitizeEmailHeader = sanitizeHeaderValue;
export const detectEmailHeaderInjection = detectHeaderInjection;
