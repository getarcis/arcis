/**
 * @arcis/node/html: parser-backed HTML sanitizer.
 *
 * Cleans HTML that an application intentionally accepts (comments, rich
 * text, CMS content). Output matches DOMPurify 3.4 on jsdom for the same
 * configuration; parsing follows the WHATWG algorithm through parse5, an
 * optional peer dependency (`npm install parse5`). See API_SPEC.md section 11.
 *
 * @example
 * ```ts
 * import { sanitizeHtml } from '@arcis/node/html';
 *
 * sanitizeHtml('<p>Hi<img src=x onerror=alert(1)></p>'); // '<p>Hi<img src="x"></p>'
 * ```
 */
import { type CompiledConfig, type HtmlSanitizerConfig, compileConfig } from './config';
import { type HtmlRemovedItem, sanitizeString } from './sanitize';

export type { HtmlSanitizerConfig, HtmlSanitizerProfiles } from './config';
export type { HtmlRemovedItem } from './sanitize';

/** Result of {@link sanitizeHtmlDetailed}. */
export interface HtmlSanitizeResult {
  /** The sanitized HTML. */
  readonly html: string;
  /**
   * What was dropped, in document order: `{ element }` with the lowercase
   * node name (`#comment` and `#text` included), or `{ attribute, from }`.
   */
  readonly removed: readonly HtmlRemovedItem[];
}

/** A sanitizer with a validated configuration, safe to reuse. */
export interface HtmlSanitizer {
  /** Sanitizes `dirty`. `null` and `undefined` return `""`; other non-strings throw TypeError. */
  sanitize(dirty: string | null | undefined): string;
  /** Like {@link HtmlSanitizer.sanitize}, also listing what was removed. */
  sanitizeDetailed(dirty: string | null | undefined): HtmlSanitizeResult;
}

/** Implicit html, head and body handling is parser-specific, so it is not reported. */
const UNREPORTED_ELEMENTS: ReadonlySet<string> = new Set(['html', 'head', 'body']);

function run(dirty: unknown, config: CompiledConfig): HtmlSanitizeResult {
  if (dirty === null || dirty === undefined) {
    return { html: '', removed: [] };
  }
  if (typeof dirty !== 'string') {
    throw new TypeError(`sanitizeHtml expects a string, got ${typeof dirty}`);
  }
  const { html, removed } = sanitizeString(dirty, config);
  return {
    html,
    removed: removed.filter((item) => !('element' in item && UNREPORTED_ELEMENTS.has(item.element))),
  };
}

/**
 * Validates `config` once and returns a reusable sanitizer.
 *
 * @param config - DOMPurify-style options; unknown keys and options that
 *   only apply to browser DOM objects throw TypeError.
 * @returns A sanitizer that applies `config` to every call.
 */
export function createHtmlSanitizer(config?: HtmlSanitizerConfig): HtmlSanitizer {
  const compiled = compileConfig(config);
  return {
    sanitize: (dirty) => run(dirty, compiled).html,
    sanitizeDetailed: (dirty) => run(dirty, compiled),
  };
}

let defaultSanitizer: HtmlSanitizer | null = null;

function sanitizerFor(config: HtmlSanitizerConfig | undefined): HtmlSanitizer {
  if (config !== undefined) {
    return createHtmlSanitizer(config);
  }
  defaultSanitizer ??= createHtmlSanitizer();
  return defaultSanitizer;
}

/**
 * Sanitizes untrusted HTML.
 *
 * @param dirty - The HTML to clean. `null` and `undefined` return `""`.
 * @param config - Optional DOMPurify-style options.
 * @returns The sanitized HTML.
 */
export function sanitizeHtml(dirty: string | null | undefined, config?: HtmlSanitizerConfig): string {
  return sanitizerFor(config).sanitize(dirty);
}

/**
 * Sanitizes untrusted HTML and lists what was removed.
 *
 * @param dirty - The HTML to clean. `null` and `undefined` return `""`.
 * @param config - Optional DOMPurify-style options.
 * @returns The sanitized HTML and the removed elements and attributes.
 */
export function sanitizeHtmlDetailed(
  dirty: string | null | undefined,
  config?: HtmlSanitizerConfig,
): HtmlSanitizeResult {
  return sanitizerFor(config).sanitizeDetailed(dirty);
}
