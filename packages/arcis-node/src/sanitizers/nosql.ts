/**
 * @module @arcis/node/sanitizers/nosql
 * NoSQL injection prevention (MongoDB operators)
 */

import { NOSQL_DANGEROUS_KEYS, NOSQL_STRING_PATTERN } from '../core/constants';

/**
 * Checks if a key is a dangerous MongoDB operator.
 * 
 * @param key - The key to check
 * @returns True if the key is a MongoDB operator
 * 
 * @example
 * isDangerousNoSqlKey('$gt') // true
 * isDangerousNoSqlKey('name') // false
 */
export function isDangerousNoSqlKey(key: string): boolean {
  return NOSQL_DANGEROUS_KEYS.has(key);
}

/**
 * Recursively checks if an object contains dangerous MongoDB operators.
 * 
 * @param obj - The object to check
 * @param maxDepth - Maximum recursion depth (default: 10)
 * @returns True if dangerous operators found
 */
export function detectNoSqlInjection(obj: unknown, maxDepth = 10): boolean {
  if (maxDepth <= 0) return false;
  if (obj === null || typeof obj !== 'object') return false;
  
  if (Array.isArray(obj)) {
    return obj.some(item => detectNoSqlInjection(item, maxDepth - 1));
  }
  
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    if (isDangerousNoSqlKey(key)) {
      return true;
    }
    
    const value = (obj as Record<string, unknown>)[key];
    if (typeof value === 'object' && value !== null) {
      if (detectNoSqlInjection(value, maxDepth - 1)) {
        return true;
      }
    }
  }
  
  return false;
}

/**
 * Detects a MongoDB operator appearing in a STRING value.
 *
 * detectNoSqlInjection only inspects object keys. But operators also
 * arrive as strings: `?user[$ne]=1` reaches the handler as the literal
 * `$ne` before any object is built, and mongo-shell payloads like
 * `$where: '1==1'` are plain strings. This is the string-level check
 * used by block-mode scanThreats, matching Python's `_NOSQL_DETECT`.
 *
 * @param input - The string to check
 * @returns True if a NoSQL operator token is present
 *
 * @example
 * detectNoSqlString("$where: 'this.a==1'") // true
 * detectNoSqlString("$invoice total")      // false ($in not a token here)
 */
export function detectNoSqlString(input: string): boolean {
  if (typeof input !== 'string') return false;
  return NOSQL_STRING_PATTERN.test(input);
}

/**
 * Get list of all MongoDB operators considered dangerous.
 * Useful for documentation or custom validation.
 *
 * @returns Array of dangerous operator strings
 */
export function getDangerousOperators(): string[] {
  return Array.from(NOSQL_DANGEROUS_KEYS);
}
