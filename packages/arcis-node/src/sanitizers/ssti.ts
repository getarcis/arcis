/**
 * @module @arcis/node/sanitizers/ssti
 * Server-Side Template Injection (SSTI) prevention
 */

import type { SanitizeResult, ThreatInfo } from '../core/types';

/**
 * SSTI detection patterns (ReDoS-safe).
 *
 * Covers Jinja2, Twig, Nunjucks, Freemarker, Thymeleaf, Spring EL,
 * ERB, EJS, Pug/Jade, and Python sandbox-escape dunder chains.
 */
const SSTI_DETECT_PATTERNS = [
  /** Jinja2 / Twig / Nunjucks: {{ ... }} */
  /\{\{.*?\}\}/g,
  /** Freemarker / Thymeleaf / Spring EL: ${ ... } */
  /\$\{.*?\}/g,
  /** ERB / EJS: <%= ... %> or <% ... %> */
  /<%[=\-]?.*?%>/gs,
  /** Pug / Jade / Slim: #{ ... } */
  /#\{.*?\}/g,
  /** Python dunder sandbox escape */
  /__(?:class|mro|subclasses|globals|builtins|import)__/gi,
  /** Jinja2 config leak: {{config.X}} or {{config['X']}} */
  /\{\{\s*config[.\[]/gi,
  /** Jinja2 built-in objects */
  /\{\{\s*(?:self|request|lipsum|cycler|joiner|namespace|range)\b/gi,
] as const;

/**
 * Removal patterns — strip template expressions that look like actual attacks.
 *
 * ${ and #{ patterns are narrowed to require operators/method-calls inside to
 * avoid false-positives on JS template literals (${name}) and Ruby/Pug output
 * expressions (#{name}) that appear in legitimate user-submitted content.
 *
 * The broader detection patterns above still flag these for detectSsti() —
 * narrowing only applies to destructive sanitization.
 */
const SSTI_REMOVE_PATTERNS = [
  /** Jinja2 / Twig: {{ ... }} — always strip (not valid in any JS context) */
  /\{\{.*?\}\}/g,
  /**
   * Freemarker / Spring EL: ${...} — only strip when the expression contains
   * operators (?!*+-/), method calls (), or known-dangerous prefixes.
   * Bare ${name} and ${user.name} are left intact (JS template literal syntax).
   */
  /\$\{[^}]*[?!()*+\-/][^}]*\}/g,
  /** ERB / EJS: <%= ... %> */
  /<%[=\-]?.*?%>/gs,
  /**
   * Pug / Jade: #{...} — same narrowing as ${ above.
   * #{name} output expressions are left intact.
   */
  /#\{[^}]*[?!()*+\-/][^}]*\}/g,
  /** Python dunder sandbox escape — always strip */
  /__(?:class|mro|subclasses|globals|builtins|import)__/gi,
] as const;

/**
 * Sanitizes a string to prevent SSTI attacks.
 * Removes template expression syntax.
 */
export function sanitizeSsti(input: string, collectThreats?: false): string;
export function sanitizeSsti(input: string, collectThreats: true): SanitizeResult;
export function sanitizeSsti(input: string, collectThreats = false): string | SanitizeResult {
  if (typeof input !== 'string') {
    return collectThreats
      ? { value: String(input), wasSanitized: false, threats: [] }
      : String(input);
  }

  const threats: ThreatInfo[] = [];
  let value = input;
  let wasSanitized = false;

  for (const pattern of SSTI_REMOVE_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(value)) {
      pattern.lastIndex = 0;

      if (collectThreats) {
        const matches = value.match(pattern);
        if (matches) {
          for (const match of matches) {
            threats.push({
              type: 'ssti',
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

  if (collectThreats) {
    return { value, wasSanitized, threats };
  }

  return value;
}

/**
 * Checks if a string contains SSTI patterns.
 * Does not sanitize — use sanitizeSsti() for that.
 *
 * @param input - The string to check
 * @returns True if SSTI patterns detected
 */
export function detectSsti(input: string): boolean {
  if (typeof input !== 'string') return false;

  for (const pattern of SSTI_DETECT_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(input)) {
      return true;
    }
  }

  return false;
}
