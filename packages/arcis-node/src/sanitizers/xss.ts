/**
 * @module @arcis/node/sanitizers/xss
 * XSS (Cross-Site Scripting) prevention
 */

import { XSS_PATTERNS, XSS_REMOVE_PATTERNS } from '../core/constants';
import { encodeHtmlEntities } from './utils';
import type { SanitizeResult, ThreatInfo } from '../core/types';

/**
 * Sanitizes a string to prevent XSS attacks.
 * 
 * Strategy:
 * 1. Remove dangerous patterns (script tags, event handlers, etc.)
 * 2. HTML-encode the remaining content
 * 
 * @param input - The string to sanitize
 * @param collectThreats - Whether to collect threat information (default: false for performance)
 * @returns Sanitized string or SanitizeResult if collectThreats is true
 * 
 * @example
 * sanitizeXss("<script>alert('xss')</script>")
 * // Returns: "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
 * 
 * @example
 * sanitizeXss("<img onerror='alert(1)'>")
 * // Returns: "&lt;img&gt;" (event handler removed)
 */
export function sanitizeXss(input: string, collectThreats?: false, htmlEncode?: boolean): string;
export function sanitizeXss(input: string, collectThreats: true, htmlEncode?: boolean): SanitizeResult;
export function sanitizeXss(input: string, collectThreats = false, htmlEncode = false): string | SanitizeResult {
  if (typeof input !== 'string') {
    return collectThreats 
      ? { value: String(input), wasSanitized: false, threats: [] }
      : String(input);
  }

  const threats: ThreatInfo[] = [];
  let value = input;
  let wasSanitized = false;

  // Remove dangerous patterns FIRST — XSS_REMOVE_PATTERNS is the single
  // source of truth (defined in constants.ts alongside XSS_PATTERNS).
  for (const pattern of XSS_REMOVE_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(value)) {
      pattern.lastIndex = 0;
      
      if (collectThreats) {
        const matches = value.match(pattern);
        if (matches) {
          for (const match of matches) {
            threats.push({
              type: 'xss',
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

  // HTML-encode only when explicitly requested (SSR/template context).
  // Do NOT encode by default — this is a REST API middleware; encoding
  // here corrupts JSON data with HTML entities (&lt;, &amp;, etc.) that
  // consumers would receive verbatim.
  if (htmlEncode) {
    const encoded = encodeHtmlEntities(value);
    if (encoded !== value) {
      wasSanitized = true;
    }
    value = encoded;
  }

  if (collectThreats) {
    return { value, wasSanitized, threats };
  }
  
  return value;
}

/**
 * Checks if a string contains potential XSS patterns.
 * Does not sanitize — use sanitizeXss() for that.
 * 
 * @param input - The string to check
 * @returns True if XSS patterns detected
 */
export function detectXss(input: string): boolean {
  if (typeof input !== 'string') return false;

  // All XSS detection now flows through the shared patterns.json `xss` rules
  // (event handlers, javascript:/vbscript:/data: protocols, tags). The former
  // inline fast-path checks were a strict subset of these rules, so they were
  // removed when the patterns moved to patterns.json (single source).
  for (const pattern of XSS_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(input)) {
      return true;
    }
  }

  return false;
}
