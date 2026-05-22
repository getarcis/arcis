/**
 * @module @arcis/node/sanitizers/sanitize
 * Main sanitization functions that combine all sanitizers
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { INPUT, DANGEROUS_PROTO_KEYS, NOSQL_DANGEROUS_KEYS } from '../core/constants';
import { InputTooLargeError, SecurityThreatError } from '../core/errors';
import type { SanitizeOptions } from '../core/types';
import { sanitizeXss, detectXss } from './xss';
import { sanitizeSql, detectSql } from './sql';
import { sanitizePath, detectPathTraversal } from './path';
import { sanitizeCommand, detectCommandInjection } from './command';
import { detectSsti } from './ssti';
import { detectXxe } from './xxe';
import { detectLdapInjection } from './ldap';
import { detectXpathInjection } from './xpath';
import { detectHeaderInjection } from './headers';

/**
 * Sanitize a string value against multiple attack vectors.
 * 
 * Order matters: We do XSS encoding LAST because:
 * 1. Other sanitizers need to see the original patterns (e.g., SQL keywords)
 * 2. HTML encoding is the final safe output transformation
 * 3. Encoded entities like &lt; shouldn't be treated as SQL/command threats
 * 
 * @param value - The string to sanitize
 * @param options - Sanitization options
 * @returns The sanitized string
 * 
 * @example
 * sanitizeString("<script>alert('xss')</script>")
 * // Returns: "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
 * 
 * @example
 * sanitizeString("../../etc/passwd")
 * // Returns: "etc/passwd"
 */
/**
 * Decode URL + HTML entity layers until the string is stable.
 *
 * improvements.md §1.1.b — closes the encoding-stack bypass class.
 * A payload like `%2526%2523x3c%253bscript%2526%2523x3e%253b` is a
 * triple-encoded `<script>`: pass 1 URL-decodes to
 * `%26%23x3c%3bscript%26%23x3e%3b`, pass 2 URL-decodes to
 * `&#x3c;script&#x3e;`, pass 3 HTML-decodes to `<script>`. Without
 * this helper the literal ASCII `<script>` never appears in the
 * string, so the XSS regex never fires.
 *
 * Bounded at 4 passes to prevent pathological-input loops. Base64
 * decoding is intentionally NOT in the chain — false-positive rate
 * on arbitrary text would be high.
 */
function multiDecode(value: string, maxPasses = 4): string {
  for (let i = 0; i < maxPasses; i++) {
    const prev = value;

    // URL-decode. decodeURIComponent throws on malformed sequences
    // (lone `%` with no hex pair); treat that as "no further
    // URL-decoding possible" and continue with the current value.
    try {
      value = decodeURIComponent(value);
    } catch {
      // leave value as-is
    }

    // HTML entity decode. No built-in in Node, so inline the common
    // entities here. Numeric (`&#NN;`, `&#xHH;`) covers the bulk of
    // XSS-encoding tricks; the five named entities below cover the
    // rest of the encoding-bypass test corpus.
    value = htmlEntityDecode(value);

    if (value === prev) break;
  }
  return value;
}

/** Decode HTML entities — numeric (decimal + hex) plus the five core
 * named entities that XSS payloads use. Keeps the dep-free zero-dep
 * footprint of `@arcis/node`. */
function htmlEntityDecode(s: string): string {
  // &#NN; decimal numeric
  s = s.replace(/&#(\d+);/g, (_m, n) => {
    const code = parseInt(n, 10);
    return Number.isFinite(code) && code >= 0 && code <= 0x10ffff
      ? String.fromCodePoint(code)
      : _m;
  });
  // &#xHH; or &#XHH; hex numeric
  s = s.replace(/&#x([0-9a-fA-F]+);/g, (_m, h) => {
    const code = parseInt(h, 16);
    return Number.isFinite(code) && code >= 0 && code <= 0x10ffff
      ? String.fromCodePoint(code)
      : _m;
  });
  // The five named entities that matter for XSS detection.
  const named: Record<string, string> = {
    '&lt;': '<',
    '&gt;': '>',
    '&amp;': '&',
    '&quot;': '"',
    '&apos;': "'",
    '&nbsp;': ' ',
  };
  for (const [entity, ch] of Object.entries(named)) {
    s = s.split(entity).join(ch);
  }
  return s;
}

export function sanitizeString(value: string, options: SanitizeOptions = {}): string {
  if (typeof value !== 'string') return value;

  // Input size limit to prevent DoS
  const maxSize = options.maxSize ?? INPUT.DEFAULT_MAX_SIZE;
  if (value.length > maxSize) {
    throw new InputTooLargeError(maxSize, value.length);
  }

  // Default mode is 'sanitize' (strip threats and return cleaned string).
  // Pass mode: 'reject' to throw SecurityThreatError instead of stripping.
  const reject = options.mode === 'reject';

  // SECURITY: Normalize Unicode to NFKC BEFORE every detector runs.
  // Fullwidth glyphs (`＜script＞`, `１+１＝２`) collapse to their ASCII
  // equivalents, closing the entire fullwidth-bypass class for XSS,
  // SQL, command-injection, and path-traversal in a single pass.
  // improvements.md §1.1.a. Bypass example closed:
  //   `＜script＞alert(1)＜/script＞`  →  `<script>alert(1)</script>`
  let result = value.normalize('NFKC');

  // SECURITY: Multi-pass URL + HTML decode (improvements.md §1.1.b).
  // Closes the encoding-stack bypass class. After NFKC,
  // `%2526%2523x3c%253bscript%2526%2523x3e%253b` (triple-encoded
  // `<script>`) decodes all the way to `<script>` and hits the
  // normal XSS strip below. Bounded at 4 passes.
  result = multiDecode(result);

  // 1. SQL injection
  if (options.sql !== false) {
    if (reject) {
      if (detectSql(result)) {
        throw new SecurityThreatError('sql_injection', 'SQL pattern detected in input');
      }
    } else {
      result = sanitizeSql(result);
    }
  }

  // 2. Path traversal prevention
  if (options.path !== false) {
    result = sanitizePath(result);
  }

  // 3. Command injection
  if (options.command !== false) {
    if (reject) {
      if (detectCommandInjection(result)) {
        throw new SecurityThreatError('command_injection', 'Shell metacharacter detected in input');
      }
    } else {
      result = sanitizeCommand(result);
    }
  }

  // 4. XSS stripping — always runs to remove dangerous patterns.
  // HTML encoding is opt-in via options.htmlEncode (for SSR contexts only).
  if (options.xss !== false) {
    result = sanitizeXss(result, false, options.htmlEncode ?? false);
  }

  return result;
}

/**
 * Sanitize an object recursively, including nested objects and arrays.
 * Also removes prototype pollution and NoSQL injection keys.
 * 
 * @param obj - The object to sanitize
 * @param options - Sanitization options
 * @returns The sanitized object
 */
export function sanitizeObject(obj: unknown, options: SanitizeOptions = {}): unknown {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return sanitizeString(obj, options);
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(item => sanitizeObject(item, options));

  const result = sanitizeObjectDepth(obj as Record<string, unknown>, options, 0);
  return options.freeze ? Object.freeze(result) : result;
}

/**
 * Internal recursive sanitization with depth tracking.
 */
function sanitizeObjectDepth(
  obj: Record<string, unknown>,
  options: SanitizeOptions,
  depth: number
): Record<string, unknown> {
  if (depth >= INPUT.MAX_RECURSION_DEPTH) return obj;

  const result: Record<string, unknown> = {};

  for (const key of Object.keys(obj)) {
    // Prototype pollution protection - always block dangerous keys (case-insensitive)
    if (options.proto !== false && DANGEROUS_PROTO_KEYS.has(key.toLowerCase())) {
      continue;
    }

    // NoSQL injection - skip dangerous MongoDB operators in keys
    if (options.nosql !== false && NOSQL_DANGEROUS_KEYS.has(key)) {
      continue;
    }

    // Sanitize the key against all active threat vectors (not just XSS).
    // Keys can carry injection payloads that bubble into query builders or ORMs.
    const sanitizedKey = sanitizeString(key, options);

    // Recursively sanitize value
    const value = obj[key];
    if (value === null || value === undefined) {
      result[sanitizedKey] = value;
    } else if (typeof value === 'string') {
      result[sanitizedKey] = sanitizeString(value, options);
    } else if (Array.isArray(value)) {
      result[sanitizedKey] = value.map(item => sanitizeObject(item, options));
    } else if (typeof value === 'object') {
      result[sanitizedKey] = sanitizeObjectDepth(value as Record<string, unknown>, options, depth + 1);
    } else {
      result[sanitizedKey] = value;
    }
  }

  return result;
}

/** Threat triple returned from scanThreats. */
export interface ThreatHit {
  vector:
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
    | 'header';
  rule: string;
  matchedPattern: string;
}

/**
 * Walk a value (string, array, or object) and return the first threat hit
 * found. Used by block-mode middleware to attribute the deny decision.
 *
 * Vector ordering matches Python's scan_threats for cross-SDK parity.
 */
export function scanThreats(data: unknown, depth = 0): ThreatHit | null {
  if (depth > INPUT.MAX_RECURSION_DEPTH) return null;

  if (data && typeof data === 'object' && !Array.isArray(data)) {
    for (const key of Object.keys(data as Record<string, unknown>)) {
      const lower = key.toLowerCase();
      if (DANGEROUS_PROTO_KEYS.has(lower)) {
        return { vector: 'prototype', rule: 'prototype/match', matchedPattern: key };
      }
      if (NOSQL_DANGEROUS_KEYS.has(key)) {
        return { vector: 'nosql', rule: 'nosql/match', matchedPattern: key };
      }
      const inner = scanThreats((data as Record<string, unknown>)[key], depth + 1);
      if (inner) return inner;
    }
    return null;
  }

  if (Array.isArray(data)) {
    for (const item of data) {
      const inner = scanThreats(item, depth + 1);
      if (inner) return inner;
    }
    return null;
  }

  if (typeof data !== 'string') return null;

  const sample = data.slice(0, 80);
  if (detectXss(data)) {
    return { vector: 'xss', rule: 'xss/match', matchedPattern: sample };
  }
  if (detectSsti(data)) {
    return { vector: 'ssti', rule: 'ssti/match', matchedPattern: sample };
  }
  if (detectXxe(data)) {
    return { vector: 'xxe', rule: 'xxe/match', matchedPattern: sample };
  }
  if (detectSql(data)) {
    return { vector: 'sql', rule: 'sql/match', matchedPattern: sample };
  }
  if (detectPathTraversal(data)) {
    return { vector: 'path', rule: 'path/match', matchedPattern: sample };
  }
  if (detectCommandInjection(data)) {
    return { vector: 'command', rule: 'command/match', matchedPattern: sample };
  }
  // LDAP + XPath checks come AFTER command/path so a string that's
  // primarily a path-traversal payload (`../`) gets attributed to
  // path, not LDAP (the `\` in `..\..\` would otherwise hit the LDAP
  // backslash filter).
  if (detectLdapInjection(data)) {
    return { vector: 'ldap', rule: 'ldap/match', matchedPattern: sample };
  }
  if (detectXpathInjection(data)) {
    return { vector: 'xpath', rule: 'xpath/match', matchedPattern: sample };
  }
  // Header injection (HTTP response splitting + email-header injection
  // share the same byte-level threat: CRLF in a value that gets
  // concatenated into a header). Last in the chain so the more-specific
  // detectors (xss / sql / etc.) win on input that's both — e.g. an XSS
  // payload with a stray newline still attributes to xss.
  if (detectHeaderInjection(data)) {
    return { vector: 'header', rule: 'header/match', matchedPattern: sample };
  }
  return null;
}

/**
 * Create Express middleware for request sanitization.
 * Sanitizes req.body, req.query, and req.params.
 * 
 * @param options - Sanitization options
 * @returns Express middleware
 * 
 * @example
 * app.use(createSanitizer());
 * 
 * @example
 * app.use(createSanitizer({ xss: true, sql: true, nosql: true }));
 */
export function createSanitizer(options: SanitizeOptions = {}): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Block mode: scan first, return 403 on threat. The telemetry emitter
      // reads the marker on res.finish to attribute the deny decision.
      if (options.block) {
        const hit =
          scanThreats(req.body) ||
          scanThreats(req.query) ||
          scanThreats(req.params) ||
          scanThreats(req.path);
        if (hit) {
          req.__arcis = {
            vector: hit.vector,
            rule: hit.rule,
            severity: 'high',
            matchedPattern: hit.matchedPattern,
            reason: `${hit.vector} pattern detected in request`,
            decision: 'deny',
          };
          res.status(403).json({
            error: 'Request blocked for security reasons',
            code: 'SECURITY_THREAT',
            vector: hit.vector,
          });
          return;
        }
      }

      if (req.body && typeof req.body === 'object') {
        req.body = sanitizeObject(req.body, options);
      }
      if (req.query && typeof req.query === 'object') {
        const sanitizedQuery = sanitizeObject(req.query, options);
        // Express 5: req.query is a getter with no setter — override on instance
        Object.defineProperty(req, 'query', { value: sanitizedQuery, writable: true, configurable: true });
      }
      if (req.params && typeof req.params === 'object') {
        const sanitizedParams = sanitizeObject(req.params, options);
        Object.defineProperty(req, 'params', { value: sanitizedParams, writable: true, configurable: true });
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}
