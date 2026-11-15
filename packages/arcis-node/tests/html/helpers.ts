/**
 * Shared helpers for the HTML sanitizer suites: the shared fixtures, a
 * reference DOMPurify on jsdom, and a seeded markup fuzzer.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import type { HtmlRemovedItem, HtmlSanitizerConfig } from '../../src/html';

export interface FixtureCase {
  id: string;
  source: string;
  title: string;
  config: Record<string, unknown>;
  input: string;
  expected: string;
  removed: Array<{ element?: string | null; attribute?: string; from?: string | null }>;
}

const here = dirname(fileURLToPath(import.meta.url));

export const VECTORS_PATH = resolve(here, '../../../../spec/html-sanitizer-vectors.json');

export const vectors: { reference: Record<string, string>; cases: FixtureCase[] } = JSON.parse(
  readFileSync(VECTORS_PATH, 'utf-8'),
);

/** Fixture configs store ALLOWED_URI_REGEXP as { source, flags }. */
export function toConfig(config: Record<string, unknown>): HtmlSanitizerConfig {
  const out: Record<string, unknown> = { ...config };
  const regexp = config.ALLOWED_URI_REGEXP as { source: string; flags: string } | undefined;
  if (regexp) {
    out.ALLOWED_URI_REGEXP = new RegExp(regexp.source, regexp.flags);
  }
  return out as HtmlSanitizerConfig;
}

const UNREPORTED = new Set(['html', 'head', 'body']);

/** A DOMPurify removed list, described and filtered the way the spec reports it. */
export function reportable(
  removed: Array<{ element?: string | null; attribute?: string; from?: string | null }>,
): HtmlRemovedItem[] {
  return removed
    .filter((item) => !(item.element !== undefined && UNREPORTED.has(item.element ?? '')))
    .map((item) =>
      item.attribute !== undefined
        ? { attribute: item.attribute, from: item.from ?? '' }
        : { element: item.element ?? '' },
    );
}

// ─── Reference implementation ───────────────────────────────────────────

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window as unknown as Parameters<typeof createDOMPurify>[0]);

interface DomPurifyRemoved {
  element?: { nodeName?: string };
  attribute?: { name: string } | null;
  from?: { nodeName?: string };
}

/** Runs DOMPurify on jsdom and describes `removed` like the fixture generator. */
export function referenceSanitize(
  input: string,
  config: HtmlSanitizerConfig = {},
): { html: string; removed: HtmlRemovedItem[] } {
  const html = DOMPurify.sanitize(input, config as Parameters<typeof DOMPurify.sanitize>[1]);
  const described = (DOMPurify.removed as DomPurifyRemoved[]).map((entry) =>
    entry.attribute
      ? { attribute: entry.attribute.name, from: entry.from?.nodeName?.toLowerCase() ?? null }
      : { element: entry.element?.nodeName?.toLowerCase() ?? null },
  );
  return { html: String(html), removed: reportable(described) };
}

// ─── Seeded fuzzer (same grammar idea as scripts/generate-html-vectors.mjs) ─

export function mulberry32(seed: number): () => number {
  let state = seed;
  return () => {
    state |= 0;
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const TAGS = [
  'div', 'p', 'a', 'img', 'svg', 'math', 'style', 'script', 'template', 'noscript', 'iframe', 'form',
  'input', 'select', 'option', 'table', 'tr', 'td', 'th', 'tbody', 'caption', 'textarea', 'title',
  'xmp', 'noembed', 'noframes', 'foreignObject', 'mglyph', 'malignmark', 'annotation-xml', 'mtext',
  'mi', 'mo', 'desc', 'object', 'embed', 'base', 'meta', 'link', 'button', 'details', 'summary',
  'video', 'source', 'image', 'use', 'animate', 'set', 'b', 'i', 'span', 'custom-el', 'plaintext',
  'listing', 'pre', 'frameset', 'keygen', 'head', 'body', 'html', 'li', 'ul', 'h1', 'font', 'nobr',
  'marquee', 'filter', 'feImage', 'clipPath', 'textPath', 'selectedcontent', 'search', 'dialog',
];

const ATTRS = [
  'onerror=alert(1)', 'onclick="x()"', 'href="javascript:alert(1)"',
  'href="jav&#x09;ascript:alert(1)"', 'href=" javascript:1"', 'href="  https://ok.example  "',
  'src="data:text/html,<script>alert(1)</script>"', 'src="data:image/png;base64,AA"', 'src="x"',
  'xlink:href="javascript:alert(1)"', 'xlink:href=" #a "', 'style="color:red"', 'id="location"',
  'id="ok"', 'name="attributes"', 'name="cookie"', 'name=" x "', 'data-x="1"', 'data-y=" 2 "',
  'aria-label="a"', 'is="x-foo"', 'class="c"', 'class=" c "', 'title="</style><b>"', 'alt="<!--"',
  'value=" --><x> "', 'formaction="javascript:alert(1)"', 'srcdoc="<b>x</b>"', 'action="x"',
  'background="javascript:1"', 'href="https://ok.example/p?a=1&b=2"', 'target="_blank"',
  'rel="noopener"', 'encoding="text/html"', 'encoding="application/xhtml+xml"',
  'xmlns="http://www.w3.org/1999/xhtml"', 'xmlns:xlink="http://www.w3.org/1999/xlink"',
  'title="{{x}}"', 'attributename="href"', 'to="javascript:alert(1)"', 'for="x"', 'patchsrc="#a"',
  'viewBox="0 0 1 1"', 'definitionurl="x"', 'title="a/>b"', 'type="text/css"', 'colspan="2"',
];

const TEXTS = [
  'hello', '<', '>', '&amp;', '&nbsp;', '&lt;b&gt;x&lt;/b&gt;', '{{constructor}}', '${x}',
  '<%= x %>', '<!-- c -->', '<!--<b>-->', '<![CDATA[ x ]]>', '<?xml x?>', '</div>', '</p>', '<br>',
  '&#0;', '\u0000', ' ', '\n', '</style>', '</textarea>', '</title>', '</noscript>', '</table>',
  '<img src=x onerror=alert(1)>', '-->', ']]>', '<!DOCTYPE html>', 'caf\u00e9',
];

function fuzzCase(random: () => number): string {
  const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)];
  const node = (depth: number): string => {
    if (depth > 3 || random() < 0.3) {
      return pick(TEXTS);
    }
    const tag = pick(TAGS);
    const attrs = Array.from({ length: Math.floor(random() * 3) }, () => ' ' + pick(ATTRS)).join('');
    const children = Array.from({ length: Math.floor(random() * 3) }, () => node(depth + 1)).join('');
    const close = random() < 0.8 ? `</${random() < 0.9 ? tag : pick(TAGS)}>` : '';
    return `<${tag}${attrs}>${children}${close}`;
  };
  const prefix = random() < 0.1 ? pick([' ', '\n\t', '  ']) : '';
  return prefix + Array.from({ length: 1 + Math.floor(random() * 3) }, () => node(0)).join('');
}

/** `count` distinct seeded fuzz inputs, none of them in `exclude`. */
export function fuzzInputs(seed: number, count: number, exclude: ReadonlySet<string>): string[] {
  const random = mulberry32(seed);
  const seen = new Set<string>();
  while (seen.size < count) {
    const input = fuzzCase(random);
    if (!exclude.has(input)) {
      seen.add(input);
    }
  }
  return [...seen];
}

/** Configs the fuzz inputs are also run under, to reach option-specific paths. */
export const FUZZ_CONFIGS: HtmlSanitizerConfig[] = [
  {},
  { SAFE_FOR_TEMPLATES: true },
  { SAFE_FOR_XML: false },
  { KEEP_CONTENT: false },
  { WHOLE_DOCUMENT: true },
  { FORCE_BODY: true },
  { SANITIZE_NAMED_PROPS: true },
  { ADD_TAGS: ['noscript', 'iframe', '#comment'], ADD_ATTR: ['srcdoc', 'is'] },
  { USE_PROFILES: { html: true } },
  { USE_PROFILES: { svg: true, svgFilters: true, mathMl: true } },
  { ALLOWED_TAGS: ['b', 'a', 'svg', 'template'], ALLOWED_ATTR: ['href', 'id'] },
];
