/**
 * @module @arcis/node/sanitizers/xpath
 * XPath injection prevention.
 *
 * XPath 1.0 has no escape syntax for string literals — the only way to
 * embed user input safely is parameterised queries / variable bindings.
 * Neither libxml2 nor most JS XPath libraries expose a canonical escape
 * function. The pragmatic answer everyone ships:
 *
 *   - Detect: scan for unescaped quotes or expression-control chars
 *     that suggest the user is trying to break out of a string literal.
 *   - Sanitize: strip the offending control characters. Lossy by design;
 *     callers that need lossless input should use parameterised queries
 *     directly.
 *
 * Detection is the load-bearing surface for this vector. Sanitization is
 * a fallback for users running existing XPath strings through user input
 * who can't switch to bound parameters today.
 */

// XPath expression-control characters that an attacker uses to escape
// a string literal: single quote, double quote, comma (changes function
// arity), the union operator |, and parens (used in `) or (` toggles
// against XPath function calls). These are the same shapes Aikido /
// Snyk's xpath rules look for.
const XPATH_INJECTION_CHARS = /['"|,()]/;

// Common operator-injection patterns: unescaped boolean injection
// (`' or '1'='1`), function tampering (`,`), and union (`|`).
// Also blind-extraction functions (`substring(name(...))`,
// `string-length(`, `count(/`) used to leak the document one char at a
// time. Benchmark xpath-blind-substring.
const XPATH_INJECTION_PATTERN =
  /('\s*(or|and)\s*'|"\s*(or|and)\s*"|\)\s*(or|and)\s*\(|\|\s*\/|\bsubstring\s*\(\s*name\s*\(|\bstring-length\s*\(|\bcount\s*\(\s*\/)/i;

/**
 * Detects XPath-injection-shaped patterns in a string. Returns true when
 * the input looks like it's trying to break out of an XPath string
 * literal or hijack the expression structure.
 *
 * Conservative on purpose: triggers on any control char in the input
 * combined with a boolean / union pattern. Plain user names and emails
 * (no quotes, no pipes) pass clean.
 */
export function detectXpathInjection(input: string): boolean {
  if (typeof input !== 'string' || input.length === 0) return false;
  // Fast path: skip the regex test entirely when no control chars exist.
  if (!XPATH_INJECTION_CHARS.test(input)) return false;
  return XPATH_INJECTION_PATTERN.test(input);
}

/**
 * Strips XPath expression-control characters from a string. Lossy —
 * `O'Brien` becomes `OBrien`. Use only when migrating legacy code that
 * concatenates user input into XPath; new code should use bound
 * parameters via the underlying XPath library.
 */
export function sanitizeXpath(input: string): string {
  if (typeof input !== 'string') return String(input);
  return input.replace(/['"|,]/g, '');
}
