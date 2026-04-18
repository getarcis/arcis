/**
 * @module @arcis/node/sanitizers/path
 * Path traversal prevention
 */

import { PATH_PATTERNS } from '../core/constants';
import type { SanitizeResult, ThreatInfo } from '../core/types';

/**
 * Sanitizes a string to prevent path traversal attacks.
 * Removes ../ and ..\ patterns (including URL-encoded variants).
 * 
 * @param input - The string to sanitize
 * @param collectThreats - Whether to collect threat information (default: false for performance)
 * @returns Sanitized string or SanitizeResult if collectThreats is true
 * 
 * @example
 * sanitizePath("../../etc/passwd")
 * // Returns: "etc/passwd"
 */
export function sanitizePath(input: string, collectThreats?: false): string;
export function sanitizePath(input: string, collectThreats: true): SanitizeResult;
export function sanitizePath(input: string, collectThreats = false): string | SanitizeResult {
  if (typeof input !== 'string') {
    return collectThreats 
      ? { value: String(input), wasSanitized: false, threats: [] }
      : String(input);
  }

  const threats: ThreatInfo[] = [];
  let value = input;
  let wasSanitized = false;

  // SECURITY: Normalize Unicode to NFKC before pattern matching.
  // Fullwidth dot U+FF0E normalizes to '.', preventing ．．/ bypass of ../ detection.
  value = value.normalize('NFKC');

  // Apply patterns repeatedly until the string stops changing.
  // Single-pass stripping is bypassable: "....//".replace("../","") → "../"
  let prev: string;
  do {
    prev = value;
    for (const pattern of PATH_PATTERNS) {
      pattern.lastIndex = 0;

      if (pattern.test(value)) {
        pattern.lastIndex = 0;

        if (collectThreats) {
          const matches = value.match(pattern);
          if (matches) {
            for (const match of matches) {
              threats.push({
                type: 'path_traversal',
                pattern: pattern.source,
                original: match,
              });
            }
          }
        }

        value = value.replace(pattern, '');
        wasSanitized = true;
      }
    }
  } while (value !== prev);

  if (collectThreats) {
    return { value, wasSanitized, threats };
  }
  
  return value;
}

/**
 * Checks if a string contains path traversal patterns.
 * Does not sanitize — use sanitizePath() for that.
 * 
 * @param input - The string to check
 * @returns True if path traversal patterns detected
 */
export function detectPathTraversal(input: string): boolean {
  if (typeof input !== 'string') return false;

  // SECURITY: Normalize Unicode to NFKC — same as sanitizePath
  const normalized = input.normalize('NFKC');

  for (const pattern of PATH_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(normalized)) {
      return true;
    }
  }
  
  return false;
}
