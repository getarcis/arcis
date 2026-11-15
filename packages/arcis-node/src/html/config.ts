/**
 * Configuration validation and compilation, ported from DOMPurify's
 * `_parseConfig`. Keys use DOMPurify's exact names and defaults.
 */
import {
  DEFAULT_ALLOWED_ATTR,
  DEFAULT_ALLOWED_TAGS,
  DEFAULT_DATA_URI_TAGS,
  DEFAULT_FORBID_CONTENTS,
  DEFAULT_URI_SAFE_ATTRIBUTES,
  HTML_ATTRS,
  HTML_TAGS,
  IS_ALLOWED_URI,
  MATHML_ATTRS,
  MATHML_TAGS,
  SVG_ATTRS,
  SVG_FILTER_TAGS,
  SVG_TAGS,
  TEXT_TAGS,
  XML_ATTRS,
} from './lists';

/** Element profiles for `USE_PROFILES`. */
export interface HtmlSanitizerProfiles {
  /** Allow HTML elements and attributes. */
  html?: boolean;
  /** Allow SVG elements and attributes. */
  svg?: boolean;
  /** Allow SVG filter elements. */
  svgFilters?: boolean;
  /** Allow MathML elements and attributes. */
  mathMl?: boolean;
}

/**
 * Sanitizer options. Names, meanings and defaults follow DOMPurify, so a
 * `DOMPurify.sanitize(dirty, cfg)` call can pass the same `cfg`.
 */
export interface HtmlSanitizerConfig {
  /** Replace the default element allowlist. */
  ALLOWED_TAGS?: readonly string[];
  /** Replace the default attribute allowlist. */
  ALLOWED_ATTR?: readonly string[];
  /** Add elements to the allowlist. */
  ADD_TAGS?: readonly string[];
  /** Add attributes to the allowlist. */
  ADD_ATTR?: readonly string[];
  /** Elements to remove even when allowlisted. */
  FORBID_TAGS?: readonly string[];
  /** Attributes to remove even when allowlisted. */
  FORBID_ATTR?: readonly string[];
  /** Replace the list of elements whose content is dropped along with them. */
  FORBID_CONTENTS?: readonly string[];
  /** Add elements whose content is dropped along with them. */
  ADD_FORBID_CONTENTS?: readonly string[];
  /** Keep `data-*` attributes. Default true. */
  ALLOW_DATA_ATTR?: boolean;
  /** Keep `aria-*` attributes. Default true. */
  ALLOW_ARIA_ATTR?: boolean;
  /** Keep URLs with protocols outside the allowlist (never script or data). Default false. */
  ALLOW_UNKNOWN_PROTOCOLS?: boolean;
  /** Keep attribute values that contain `/>`. Default true. */
  ALLOW_SELF_CLOSE_IN_ATTR?: boolean;
  /** Replace the pattern that URL-valued attributes must match. */
  ALLOWED_URI_REGEXP?: RegExp;
  /** Add attributes whose values are never treated as URLs. */
  ADD_URI_SAFE_ATTR?: readonly string[];
  /** Add elements whose `src`/`href` may hold `data:` URIs. */
  ADD_DATA_URI_TAGS?: readonly string[];
  /** Allow only the named element profiles (overrides ALLOWED_TAGS and ALLOWED_ATTR). */
  USE_PROFILES?: false | HtmlSanitizerProfiles;
  /** Keep the content of removed elements. Default true. */
  KEEP_CONTENT?: boolean;
  /** Strip `{{ }}`, `<% %>` and `${` template expressions. Default false. */
  SAFE_FOR_TEMPLATES?: boolean;
  /** Remove comments and attribute values that could break out on reparse. Default true. */
  SAFE_FOR_XML?: boolean;
  /** Remove `id`/`name` values that could clobber DOM properties. Default true. */
  SANITIZE_DOM?: boolean;
  /** Prefix `id`/`name` values with `user-content-`. Default false. */
  SANITIZE_NAMED_PROPS?: boolean;
  /** Return the whole document, `<html>` included. Default false. */
  WHOLE_DOCUMENT?: boolean;
  /** Keep leading elements such as `<style>` in the body. Default false. */
  FORCE_BODY?: boolean;
}

/** A validated configuration, resolved into lookup sets. */
export interface CompiledConfig {
  readonly allowedTags: ReadonlySet<string>;
  readonly allowedAttr: ReadonlySet<string>;
  readonly forbidTags: ReadonlySet<string>;
  readonly forbidAttr: ReadonlySet<string>;
  readonly forbidContents: ReadonlySet<string>;
  readonly uriSafeAttributes: ReadonlySet<string>;
  readonly dataUriTags: ReadonlySet<string>;
  readonly allowedUriRegexp: RegExp;
  readonly allowAriaAttr: boolean;
  readonly allowDataAttr: boolean;
  readonly allowUnknownProtocols: boolean;
  readonly allowSelfCloseInAttr: boolean;
  readonly safeForTemplates: boolean;
  readonly safeForXml: boolean;
  readonly sanitizeDom: boolean;
  readonly sanitizeNamedProps: boolean;
  readonly keepContent: boolean;
  readonly wholeDocument: boolean;
  readonly forceBody: boolean;
}

const LIST_KEYS = [
  'ALLOWED_TAGS', 'ALLOWED_ATTR', 'ADD_TAGS', 'ADD_ATTR', 'FORBID_TAGS', 'FORBID_ATTR',
  'FORBID_CONTENTS', 'ADD_FORBID_CONTENTS', 'ADD_URI_SAFE_ATTR', 'ADD_DATA_URI_TAGS',
] as const;

const BOOLEAN_KEYS = [
  'ALLOW_DATA_ATTR', 'ALLOW_ARIA_ATTR', 'ALLOW_UNKNOWN_PROTOCOLS', 'ALLOW_SELF_CLOSE_IN_ATTR',
  'KEEP_CONTENT', 'SAFE_FOR_TEMPLATES', 'SAFE_FOR_XML', 'SANITIZE_DOM', 'SANITIZE_NAMED_PROPS',
  'WHOLE_DOCUMENT', 'FORCE_BODY',
] as const;

const OTHER_KEYS = ['ALLOWED_URI_REGEXP', 'USE_PROFILES'] as const;

const SUPPORTED_KEYS: ReadonlySet<string> = new Set([...LIST_KEYS, ...BOOLEAN_KEYS, ...OTHER_KEYS]);

/** DOMPurify options that only apply to DOM objects, Trusted Types or other parsers. */
const REJECTED_KEYS: ReadonlySet<string> = new Set([
  'IN_PLACE', 'RETURN_DOM', 'RETURN_DOM_FRAGMENT', 'RETURN_TRUSTED_TYPE', 'TRUSTED_TYPES_POLICY',
  'PARSER_MEDIA_TYPE', 'NAMESPACE', 'ALLOWED_NAMESPACES', 'CUSTOM_ELEMENT_HANDLING',
  'HTML_INTEGRATION_POINTS', 'MATHML_TEXT_INTEGRATION_POINTS',
]);

const PROFILE_KEYS: ReadonlySet<string> = new Set(['html', 'svg', 'svgFilters', 'mathMl']);

function lowercaseAll(values: readonly string[]): string[] {
  return values.map((value) => value.toLowerCase());
}

function validate(config: Record<string, unknown>): void {
  for (const key of Object.keys(config)) {
    if (REJECTED_KEYS.has(key)) {
      throw new TypeError(
        `HTML sanitizer option ${key} is not supported: it applies only to browser DOM objects ` +
          'or other parsers.',
      );
    }
    if (!SUPPORTED_KEYS.has(key)) {
      throw new TypeError(`Unknown HTML sanitizer option: ${key}`);
    }
    const value = config[key];
    if (value === undefined) {
      continue;
    }
    if ((LIST_KEYS as readonly string[]).includes(key)) {
      if (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string')) {
        throw new TypeError(`HTML sanitizer option ${key} must be an array of strings`);
      }
    } else if ((BOOLEAN_KEYS as readonly string[]).includes(key)) {
      if (typeof value !== 'boolean') {
        throw new TypeError(`HTML sanitizer option ${key} must be a boolean`);
      }
    } else if (key === 'ALLOWED_URI_REGEXP') {
      if (!(value instanceof RegExp)) {
        throw new TypeError('HTML sanitizer option ALLOWED_URI_REGEXP must be a RegExp');
      }
    } else {
      validateProfiles(value);
    }
  }
}

function validateProfiles(value: unknown): void {
  if (value === false) {
    return;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('HTML sanitizer option USE_PROFILES must be false or an object');
  }
  for (const [profile, enabled] of Object.entries(value)) {
    if (!PROFILE_KEYS.has(profile)) {
      throw new TypeError(`Unknown USE_PROFILES profile: ${profile}`);
    }
    if (enabled !== undefined && typeof enabled !== 'boolean') {
      throw new TypeError(`USE_PROFILES.${profile} must be a boolean`);
    }
  }
}

/**
 * Validates `input` and resolves it into lookup sets, following DOMPurify's
 * `_parseConfig` step by step. Throws TypeError on unknown keys, rejected
 * keys and wrong value types.
 */
export function compileConfig(input: HtmlSanitizerConfig | null | undefined): CompiledConfig {
  if (input === null || input === undefined) {
    input = {};
  }
  if (typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('HTML sanitizer config must be an object');
  }
  // Own enumerable keys only, as DOMPurify's clone() reads them.
  const cfg: HtmlSanitizerConfig = { ...input };
  validate(cfg as Record<string, unknown>);

  let allowedTags = new Set(cfg.ALLOWED_TAGS ? lowercaseAll(cfg.ALLOWED_TAGS) : DEFAULT_ALLOWED_TAGS);
  let allowedAttr = new Set(cfg.ALLOWED_ATTR ? lowercaseAll(cfg.ALLOWED_ATTR) : DEFAULT_ALLOWED_ATTR);
  const uriSafeAttributes = new Set([
    ...DEFAULT_URI_SAFE_ATTRIBUTES,
    ...lowercaseAll(cfg.ADD_URI_SAFE_ATTR ?? []),
  ]);
  const dataUriTags = new Set([...DEFAULT_DATA_URI_TAGS, ...lowercaseAll(cfg.ADD_DATA_URI_TAGS ?? [])]);
  const forbidContents = new Set(
    cfg.FORBID_CONTENTS ? lowercaseAll(cfg.FORBID_CONTENTS) : DEFAULT_FORBID_CONTENTS,
  );
  const forbidTags = new Set(lowercaseAll(cfg.FORBID_TAGS ?? []));
  const forbidAttr = new Set(lowercaseAll(cfg.FORBID_ATTR ?? []));

  const safeForTemplates = cfg.SAFE_FOR_TEMPLATES === true;
  const keepContent = cfg.KEEP_CONTENT !== false;
  const wholeDocument = cfg.WHOLE_DOCUMENT === true;

  const profiles = cfg.USE_PROFILES;
  if (profiles) {
    allowedTags = new Set(TEXT_TAGS);
    allowedAttr = new Set();
    if (profiles.html === true) {
      HTML_TAGS.forEach((tag) => allowedTags.add(tag));
      HTML_ATTRS.forEach((attr) => allowedAttr.add(attr));
    }
    if (profiles.svg === true) {
      SVG_TAGS.forEach((tag) => allowedTags.add(tag));
      [...SVG_ATTRS, ...XML_ATTRS].forEach((attr) => allowedAttr.add(attr));
    }
    if (profiles.svgFilters === true) {
      SVG_FILTER_TAGS.forEach((tag) => allowedTags.add(tag));
      [...SVG_ATTRS, ...XML_ATTRS].forEach((attr) => allowedAttr.add(attr));
    }
    if (profiles.mathMl === true) {
      MATHML_TAGS.forEach((tag) => allowedTags.add(tag));
      [...MATHML_ATTRS, ...XML_ATTRS].forEach((attr) => allowedAttr.add(attr));
    }
  }

  lowercaseAll(cfg.ADD_TAGS ?? []).forEach((tag) => allowedTags.add(tag));
  lowercaseAll(cfg.ADD_ATTR ?? []).forEach((attr) => allowedAttr.add(attr));
  lowercaseAll(cfg.ADD_FORBID_CONTENTS ?? []).forEach((tag) => forbidContents.add(tag));

  if (keepContent) {
    allowedTags.add('#text');
  }
  if (wholeDocument) {
    ['html', 'head', 'body'].forEach((tag) => allowedTags.add(tag));
  }
  // Tables imply tbody, which the parser inserts on its own (DOMPurify #286, #365).
  if (allowedTags.has('table')) {
    allowedTags.add('tbody');
    forbidTags.delete('tbody');
  }

  return {
    allowedTags,
    allowedAttr,
    forbidTags,
    forbidAttr,
    forbidContents,
    uriSafeAttributes,
    dataUriTags,
    // A private copy, so the caller's lastIndex is never touched.
    allowedUriRegexp: cfg.ALLOWED_URI_REGEXP
      ? new RegExp(cfg.ALLOWED_URI_REGEXP.source, cfg.ALLOWED_URI_REGEXP.flags)
      : IS_ALLOWED_URI,
    allowAriaAttr: cfg.ALLOW_ARIA_ATTR !== false,
    // SAFE_FOR_TEMPLATES also removes data attributes.
    allowDataAttr: cfg.ALLOW_DATA_ATTR !== false && !safeForTemplates,
    allowUnknownProtocols: cfg.ALLOW_UNKNOWN_PROTOCOLS === true,
    allowSelfCloseInAttr: cfg.ALLOW_SELF_CLOSE_IN_ATTR !== false,
    safeForTemplates,
    safeForXml: cfg.SAFE_FOR_XML !== false,
    sanitizeDom: cfg.SANITIZE_DOM !== false,
    sanitizeNamedProps: cfg.SANITIZE_NAMED_PROPS === true,
    keepContent,
    wholeDocument,
    forceBody: cfg.FORCE_BODY === true,
  };
}
