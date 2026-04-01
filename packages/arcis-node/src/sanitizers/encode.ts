/**
 * @module @arcis/node/sanitizers/encode
 * Context-aware output encoding for XSS prevention.
 *
 * Wrong-context encoding is the #1 cause of XSS bypasses in "protected" apps.
 * A single sanitize() is not enough when output goes to JS, CSS, or attribute contexts.
 */

// HTML entity map — covers the 5 dangerous chars in HTML body context
const HTML_ENTITIES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
};

const HTML_ENCODE_RE = /[&<>"']/g;

/**
 * Encodes for HTML body context. Entity-encodes & < > " '
 *
 * Use when outputting to HTML element content:
 *   `<p>${encodeForHtml(userInput)}</p>`
 */
export function encodeForHtml(value: string): string {
  if (!value) return '';
  return value.replace(HTML_ENCODE_RE, (ch) => HTML_ENTITIES[ch]);
}

/**
 * Encodes for HTML attribute context.
 * All non-alphanumeric characters are encoded as `&#xHH;` hex entities.
 *
 * Use when outputting to HTML attributes:
 *   `<div title="${encodeForAttribute(userInput)}">`
 */
export function encodeForAttribute(value: string): string {
  if (!value) return '';
  let result = '';
  for (let i = 0; i < value.length; i++) {
    const ch = value.charCodeAt(i);
    // Allow a-z A-Z 0-9
    if (
      (ch >= 0x30 && ch <= 0x39) || // 0-9
      (ch >= 0x41 && ch <= 0x5a) || // A-Z
      (ch >= 0x61 && ch <= 0x7a)    // a-z
    ) {
      result += value[i];
    } else {
      result += `&#x${ch.toString(16).toUpperCase()};`;
    }
  }
  return result;
}

/**
 * Encodes for JavaScript string context.
 * Non-alphanumeric characters are escaped as `\xHH` (ASCII) or `\uHHHH` (Unicode).
 *
 * Use when embedding in JS string literals:
 *   `var x = '${encodeForJs(userInput)}';`
 */
export function encodeForJs(value: string): string {
  if (!value) return '';
  let result = '';
  for (let i = 0; i < value.length; i++) {
    const ch = value.charCodeAt(i);
    // Allow a-z A-Z 0-9
    if (
      (ch >= 0x30 && ch <= 0x39) || // 0-9
      (ch >= 0x41 && ch <= 0x5a) || // A-Z
      (ch >= 0x61 && ch <= 0x7a)    // a-z
    ) {
      result += value[i];
    } else if (ch < 0x100) {
      result += `\\x${ch.toString(16).toUpperCase().padStart(2, '0')}`;
    } else {
      result += `\\u${ch.toString(16).toUpperCase().padStart(4, '0')}`;
    }
  }
  return result;
}

/**
 * Encodes for URL parameter context. Percent-encodes all non-unreserved chars.
 *
 * Use when building query strings:
 *   `?q=${encodeForUrl(userInput)}`
 */
export function encodeForUrl(value: string): string {
  if (!value) return '';
  // encodeURIComponent handles most cases but doesn't encode: ! ' ( ) *
  // We encode these additionally for full safety per RFC 3986
  return encodeURIComponent(value).replace(/[!'()*]/g, (ch) => {
    return `%${ch.charCodeAt(0).toString(16).toUpperCase()}`;
  });
}

/**
 * Encodes for CSS value context.
 * Non-alphanumeric characters are hex-escaped as `\HH ` (trailing space per CSS spec).
 *
 * Use when embedding in CSS values:
 *   `content: '${encodeForCss(userInput)}';`
 */
export function encodeForCss(value: string): string {
  if (!value) return '';
  let result = '';
  for (let i = 0; i < value.length; i++) {
    const ch = value.charCodeAt(i);
    // Allow a-z A-Z 0-9
    if (
      (ch >= 0x30 && ch <= 0x39) || // 0-9
      (ch >= 0x41 && ch <= 0x5a) || // A-Z
      (ch >= 0x61 && ch <= 0x7a)    // a-z
    ) {
      result += value[i];
    } else {
      // CSS hex escape: backslash + hex code + trailing space (CSS spec requirement)
      result += `\\${ch.toString(16).toUpperCase()} `;
    }
  }
  return result;
}
