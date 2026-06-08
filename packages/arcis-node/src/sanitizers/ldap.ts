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

// LDAP filter special characters per RFC 4515 (single pass includes NUL).
// Used for ESCAPING — broad set is fine here because escaping a benign
// char is safe; the value just gets a `\xx` representation.
const LDAP_FILTER_CHARS = /[*()\\\x00]/g;

// LDAP DN special characters per RFC 4514 (single pass includes NUL)
const LDAP_DN_CHARS = /[,+<>;"=\/\\\x00*()\x00]/g;

// Wildcard-value detection: `=*` inside a filter (e.g. `(uid=*)`).
// Real LDAP filter abuse; legitimate values don't end in `=*`.
const LDAP_WILDCARD_VALUE_PATTERN = /=\s*\*/;

// NUL byte detection — used for LDAP query truncation attacks.
// Matches both a real NUL (`\x00`) and the literal escape sequence
// `\00` (backslash-zero-zero), which is how it arrives over JSON/form
// text before any decode. Benchmark ldap-null-byte-truncate.
const LDAP_NUL_PATTERN = /\x00|\\00/;

// Detection pattern for OR/AND bypass and wildcard abuse.
// Real shapes: `*)(uid=*` (break the filter, inject a new clause).
const LDAP_INJECTION_PATTERN = /\)\s*\(|\*\s*\)\s*\(/;

// Detection pattern for LDAP NOT-operator bypass (improvements.md Q8).
// Catches ')(!', '&(!', '|(!' shapes that legitimate filters never contain;
// these are the attacker's NOT-clause appended to enumerate or exclude
// entries (e.g. '*)(uid=*)(!(uid=admin))'). Companion to
// LDAP_INJECTION_PATTERN; together they cover the OR-then-NOT corpus.
const LDAP_NOT_BYPASS_PATTERN = /\)\s*\(\s*!|&\s*\(\s*!|\|\s*\(\s*!/;

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
 * Designed for request-boundary scanning: matches only the specific
 * shapes real LDAP injection produces. The older broad
 * `[*()\\\x00]` pattern was removed because it false-positived on
 * every markdown bold `**bold**`, every parenthesised string, every
 * apostrophe-in-name. Mirrors the `ldap-injection-strict` +
 * `ldap-not-bypass` rules from packages/core/patterns.json which are
 * marked `request_boundary_safe: true`. Benchmark FP class B2, 2026-06-07.
 *
 * @param input - The string to check
 * @returns True if LDAP injection patterns detected
 *
 * @example
 * detectLdapInjection("*)(uid=*))(|(uid=*")  // true  — filter break-out
 * detectLdapInjection("(uid=*)")              // true  — wildcard value
 * detectLdapInjection("ad\x00min")            // true  — NUL truncation
 * detectLdapInjection("**bold**")             // false — markdown
 * detectLdapInjection("hello *world*")        // false — emphasis
 * detectLdapInjection("john")                 // false
 */
export function detectLdapInjection(input: string): boolean {
  if (typeof input !== 'string') return false;
  return (
    LDAP_INJECTION_PATTERN.test(input) ||
    LDAP_NOT_BYPASS_PATTERN.test(input) ||
    LDAP_WILDCARD_VALUE_PATTERN.test(input) ||
    LDAP_NUL_PATTERN.test(input)
  );
}
