/**
 * @module @arcis/node/sanitizers/jsonp
 * JSONP callback sanitization to prevent XSS via callback parameters
 */

/**
 * Valid JSONP callback pattern: only alphanumeric, underscore, dollar, and dot.
 * Bracket notation is rejected — it enables bypasses like `cb[x` (unbalanced)
 * and isn't needed for real-world JSONP callbacks.
 */
const SAFE_CALLBACK_PATTERN = /^[a-zA-Z_$][a-zA-Z0-9_$.]*$/;

/**
 * Dangerous patterns that should never appear in a callback name,
 * even if they technically match the safe pattern.
 */
const DANGEROUS_CALLBACK_PATTERNS = [
  /\.\./,        // prototype chain traversal
] as const;

/**
 * Validates and sanitizes a JSONP callback parameter.
 *
 * Returns the callback name if safe, or null if the callback is dangerous.
 * Use this to validate `?callback=` query parameters before wrapping responses.
 *
 * @param callback - The callback parameter value
 * @param maxLength - Maximum allowed length (default: 128)
 * @returns The safe callback name, or null if invalid
 *
 * @example
 * ```ts
 * const cb = sanitizeJsonpCallback(req.query.callback);
 * if (cb) {
 *   res.set('Content-Type', 'application/javascript');
 *   res.send(`${cb}(${JSON.stringify(data)})`);
 * } else {
 *   res.status(400).json({ error: 'Invalid callback' });
 * }
 * ```
 */
export function sanitizeJsonpCallback(callback: string, maxLength = 128): string | null {
  if (typeof callback !== 'string' || callback.length === 0) {
    return null;
  }

  if (callback.length > maxLength) {
    return null;
  }

  if (!SAFE_CALLBACK_PATTERN.test(callback)) {
    return null;
  }

  for (const pattern of DANGEROUS_CALLBACK_PATTERNS) {
    if (pattern.test(callback)) {
      return null;
    }
  }

  return callback;
}

/**
 * Checks if a JSONP callback parameter contains potentially dangerous content.
 *
 * @param callback - The callback parameter value
 * @returns True if the callback is dangerous / invalid
 */
export function detectJsonpInjection(callback: string): boolean {
  if (typeof callback !== 'string' || callback.length === 0) {
    return false;
  }

  // If it doesn't match the safe pattern, it's potentially dangerous
  if (!SAFE_CALLBACK_PATTERN.test(callback)) {
    return true;
  }

  for (const pattern of DANGEROUS_CALLBACK_PATTERNS) {
    if (pattern.test(callback)) {
      return true;
    }
  }

  return false;
}
