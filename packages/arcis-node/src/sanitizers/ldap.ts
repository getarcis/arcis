/**
 * @module @arcis/node/sanitizers/ldap
 * LDAP injection prevention
 *
 * LDAP special characters in filter context: * ( ) \ NUL
 * LDAP special characters in DN context:     , + < > ; " = / \ NUL
 *
 * RFC 4515 (filter) and RFC 4514 (DN) define the escaping rules.
 * Sanitization escapes rather than strips — preserves the original value
 * while making it safe to embed in LDAP queries.
 */

// LDAP filter special characters per RFC 4515 (single pass includes NUL)
const LDAP_FILTER_CHARS = /[*()\\\x00]/g;

// LDAP DN special characters per RFC 4514 (single pass includes NUL)
const LDAP_DN_CHARS = /[,+<>;"=\/\\\x00*()\x00]/g;

// Detection pattern — unescaped LDAP special chars in filter context
const LDAP_DETECT_PATTERN = /[*()\\\x00]/;

// Detection pattern for OR/AND bypass and wildcard abuse
const LDAP_INJECTION_PATTERN = /\)\s*\(|\*\s*\)\s*\(/;

const escapeChar = (char: string) => '\\' + char.charCodeAt(0).toString(16).padStart(2, '0');

/**
 * Sanitizes a string for safe use in LDAP filter expressions.
 * Escapes * ( ) \ and NUL per RFC 4515.
 *
 * @example
 * sanitizeLdapFilter("user*(admin)")
 * // Returns: "user\2a\28admin\29"
 */
export function sanitizeLdapFilter(input: string): string {
  if (typeof input !== 'string') return String(input);
  return input.replace(LDAP_FILTER_CHARS, escapeChar);
}

/**
 * Sanitizes a string for safe use in LDAP Distinguished Names (DN).
 * Escapes , + < > ; " = / \ and NUL per RFC 4514.
 *
 * @example
 * sanitizeLdapDn("cn=admin,dc=example")
 * // Returns: "cn\3dadmin\2cdc\3dexample"
 */
export function sanitizeLdapDn(input: string): string {
  if (typeof input !== 'string') return String(input);
  return input.replace(LDAP_DN_CHARS, escapeChar);
}

/**
 * Detects potential LDAP injection patterns in a string.
 * Does not sanitize — use sanitizeLdapFilter() or sanitizeLdapDn() for that.
 *
 * @param input - The string to check
 * @returns True if LDAP injection patterns detected
 *
 * @example
 * detectLdapInjection("*)(uid=*))(|(uid=*")  // true
 * detectLdapInjection("john")                 // false
 */
export function detectLdapInjection(input: string): boolean {
  if (typeof input !== 'string') return false;
  return LDAP_DETECT_PATTERN.test(input) || LDAP_INJECTION_PATTERN.test(input);
}
