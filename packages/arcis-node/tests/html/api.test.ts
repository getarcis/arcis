/**
 * Public API of @arcis/node/html: configuration validation, input rules,
 * reuse of a compiled sanitizer, removed reporting, packaging constraints
 * and idempotence over the fixture corpus.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';
import { describe, expect, it } from 'vitest';
import {
  type HtmlSanitizerConfig,
  createHtmlSanitizer,
  sanitizeHtml,
  sanitizeHtmlDetailed,
} from '../../src/html';
import { CLOBBERABLE_NAMES } from '../../src/html/dom-names';
import { referenceSanitize, toConfig, vectors } from './helpers';

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = resolve(here, '../../src');

describe('configuration', () => {
  it('accepts no config, undefined and null', () => {
    expect(sanitizeHtml('<b onclick="x()">a</b>')).toBe('<b>a</b>');
    expect(sanitizeHtml('<b>a</b>', undefined)).toBe('<b>a</b>');
    expect(createHtmlSanitizer(null as unknown as HtmlSanitizerConfig).sanitize('<i>x</i>')).toBe('<i>x</i>');
    expect(createHtmlSanitizer({ ALLOWED_TAGS: undefined }).sanitize('<i>x</i>')).toBe('<i>x</i>');
  });

  it('rejects unknown keys by name', () => {
    expect(() => createHtmlSanitizer({ ALLOWED_TAG: ['b'] } as HtmlSanitizerConfig)).toThrow(
      /Unknown HTML sanitizer option: ALLOWED_TAG/,
    );
    expect(() => sanitizeHtml('x', { allowed_tags: ['b'] } as HtmlSanitizerConfig)).toThrow(TypeError);
    expect(() => createHtmlSanitizer(JSON.parse('{"__proto__": {"ALLOWED_TAGS": []}}'))).toThrow(
      /__proto__/,
    );
  });

  it.each([
    'IN_PLACE',
    'RETURN_DOM',
    'RETURN_DOM_FRAGMENT',
    'RETURN_TRUSTED_TYPE',
    'TRUSTED_TYPES_POLICY',
    'PARSER_MEDIA_TYPE',
    'NAMESPACE',
    'ALLOWED_NAMESPACES',
    'CUSTOM_ELEMENT_HANDLING',
    'HTML_INTEGRATION_POINTS',
    'MATHML_TEXT_INTEGRATION_POINTS',
  ])('rejects the DOM-only option %s by name', (key) => {
    const config = { [key]: false } as unknown as HtmlSanitizerConfig;
    expect(() => createHtmlSanitizer(config)).toThrow(new RegExp(`option ${key} is not supported`));
  });

  it.each([
    [{ ALLOWED_TAGS: 'b' }, /ALLOWED_TAGS must be an array of strings/],
    [{ ADD_ATTR: ['ok', 1] }, /ADD_ATTR must be an array of strings/],
    [{ ADD_TAGS: (name: string) => name === 'x' }, /ADD_TAGS must be an array of strings/],
    [{ KEEP_CONTENT: 'no' }, /KEEP_CONTENT must be a boolean/],
    [{ SAFE_FOR_TEMPLATES: 1 }, /SAFE_FOR_TEMPLATES must be a boolean/],
    [{ ALLOWED_URI_REGEXP: '^https:' }, /ALLOWED_URI_REGEXP must be a RegExp/],
    [{ ALLOWED_URI_REGEXP: { source: '^https:', flags: 'i' } }, /ALLOWED_URI_REGEXP must be a RegExp/],
    [{ USE_PROFILES: true }, /USE_PROFILES must be false or an object/],
    [{ USE_PROFILES: { svg: 'yes' } }, /USE_PROFILES.svg must be a boolean/],
    [{ USE_PROFILES: { mathml: true } }, /Unknown USE_PROFILES profile: mathml/],
  ])('rejects wrong value types: %j', (config, message) => {
    expect(() => createHtmlSanitizer(config as unknown as HtmlSanitizerConfig)).toThrow(TypeError);
    expect(() => createHtmlSanitizer(config as unknown as HtmlSanitizerConfig)).toThrow(message);
  });

  it('rejects a config that is not an object', () => {
    expect(() => createHtmlSanitizer([] as unknown as HtmlSanitizerConfig)).toThrow(TypeError);
    expect(() => createHtmlSanitizer('cfg' as unknown as HtmlSanitizerConfig)).toThrow(TypeError);
  });

  it('ignores inherited keys, as DOMPurify does', () => {
    const config = Object.create({ ALLOWED_TAGS: ['i'] }) as HtmlSanitizerConfig;
    expect(sanitizeHtml('<b>x</b>', config)).toBe('<b>x</b>');
  });

  it('does not mutate the caller config or regular expression', () => {
    const tags = ['B', 'I'];
    const regexp = /^https:/gi;
    regexp.lastIndex = 3;
    const sanitizer = createHtmlSanitizer({ ALLOWED_TAGS: tags, ALLOWED_ATTR: ['href'], ALLOWED_URI_REGEXP: regexp });
    expect(sanitizer.sanitize('<b><a href="https://a.example">x</a></b><i>y</i>')).toBe('<b>x</b><i>y</i>');
    expect(tags).toEqual(['B', 'I']);
    expect(regexp.lastIndex).toBe(3);
  });

  it('applies a global ALLOWED_URI_REGEXP the same way on every attribute', () => {
    const config = { ALLOWED_URI_REGEXP: /^https:/g };
    const input = '<a href="https://a.example">a</a><a href="https://b.example">b</a>';
    expect(sanitizeHtml(input, config)).toBe(referenceSanitize(input, config).html);
    expect(sanitizeHtml(input, config)).toBe(input);
  });
});

describe('input rules', () => {
  const sanitizer = createHtmlSanitizer();

  it('returns an empty string for null and undefined', () => {
    expect(sanitizeHtml(null)).toBe('');
    expect(sanitizeHtml(undefined)).toBe('');
    expect(sanitizeHtmlDetailed(null)).toEqual({ html: '', removed: [] });
    expect(sanitizer.sanitize(null)).toBe('');
    expect(sanitizer.sanitizeDetailed(undefined)).toEqual({ html: '', removed: [] });
    expect(createHtmlSanitizer({ WHOLE_DOCUMENT: true }).sanitize(null)).toBe('');
  });

  it.each([[42], [true], [{ toString: () => '<b>x</b>' }], [['<b>x</b>']], [Symbol('x')]])(
    'throws TypeError for %s',
    (value) => {
      expect(() => sanitizeHtml(value as unknown as string)).toThrow(TypeError);
      expect(() => sanitizeHtmlDetailed(value as unknown as string)).toThrow(TypeError);
      expect(() => sanitizer.sanitize(value as unknown as string)).toThrow(TypeError);
    },
  );

  it('handles the empty string like DOMPurify', () => {
    expect(sanitizeHtml('')).toBe('');
    expect(sanitizeHtml('', { WHOLE_DOCUMENT: true })).toBe(
      referenceSanitize('', { WHOLE_DOCUMENT: true }).html,
    );
  });

  it('returns text without markup unchanged, like DOMPurify', () => {
    expect(sanitizeHtml('a & b " c')).toBe('a & b " c');
    // A "<" means the input is parsed, so the text comes back escaped.
    expect(sanitizeHtml('a & b < c')).toBe('a &amp; b &lt; c');
    expect(sanitizeHtml('a & b < c')).toBe(referenceSanitize('a & b < c').html);
  });

  it('survives deeply nested input without overflowing the stack', () => {
    const depth = 20000;
    const input = '<div>'.repeat(depth) + 'x' + '<span onclick=1>'.repeat(10);
    const html = sanitizeHtml(input);
    expect(html.startsWith('<div><div>')).toBe(true);
    expect(html).not.toContain('onclick');
  });
});

describe('reuse', () => {
  it('gives the same result on every call of a compiled sanitizer', () => {
    const sanitizer = createHtmlSanitizer({ SAFE_FOR_TEMPLATES: true, SANITIZE_NAMED_PROPS: true });
    const input = '<p id="x" title="{{a}}">{{b}}<script>1</script></p>';
    const first = sanitizer.sanitizeDetailed(input);
    for (let round = 0; round < 50; round++) {
      expect(sanitizer.sanitizeDetailed(input)).toEqual(first);
    }
    expect(first).toEqual(referenceSanitize(input, { SAFE_FOR_TEMPLATES: true, SANITIZE_NAMED_PROPS: true }));
  });

  it('keeps sanitizers with different configs independent when interleaved', () => {
    const strict = createHtmlSanitizer({ ALLOWED_TAGS: ['b'] });
    const loose = createHtmlSanitizer({ ADD_TAGS: ['iframe'] });
    const input = '<b>a</b><iframe src="https://x.example"></iframe><i>c</i>';
    for (let round = 0; round < 10; round++) {
      expect(strict.sanitize(input)).toBe('<b>a</b>c');
      expect(loose.sanitize(input)).toBe('<b>a</b><iframe src="https://x.example"></iframe><i>c</i>');
      expect(sanitizeHtml(input)).toBe('<b>a</b><i>c</i>');
    }
  });

  it('is safe to share across concurrent async callers', async () => {
    const sanitizer = createHtmlSanitizer();
    const inputs = vectors.cases.slice(0, 50).map((c) => c.input);
    const results = await Promise.all(inputs.map(async (input) => sanitizer.sanitize(input)));
    expect(results).toEqual(inputs.map((input) => sanitizeHtml(input)));
  });
});

describe('removed reporting', () => {
  it('lists elements and attributes in document order', () => {
    const result = sanitizeHtmlDetailed('<p onclick="x()">a<!--c--><img src=x onerror=1><script>s</script></p>');
    expect(result.html).toBe('<p>a<img src="x"></p>');
    expect(result.removed).toEqual([
      { attribute: 'onclick', from: 'p' },
      { element: '#comment' },
      { attribute: 'onerror', from: 'img' },
      { element: 'script' },
    ]);
  });

  it('drops html, head and body entries that DOMPurify reports', () => {
    const reference = referenceSanitize('<b>x</b>', { ALLOWED_TAGS: ['b'] });
    const result = sanitizeHtmlDetailed('<b>x</b>', { ALLOWED_TAGS: ['b'] });
    expect(result).toEqual({ html: '<b>x</b>', removed: [] });
    expect(result).toEqual(reference);
  });

  it('reports scrubbed template text as #text', () => {
    expect(sanitizeHtmlDetailed('<p>{{x}}</p>', { SAFE_FOR_TEMPLATES: true })).toEqual({
      html: '<p> </p>',
      removed: [{ element: '#text' }],
    });
  });

  it('matches the module documentation example', () => {
    expect(sanitizeHtml('<p>Hi<img src=x onerror=alert(1)></p>')).toBe('<p>Hi<img src="x"></p>');
  });
});

describe('DOMPurify edge behavior', () => {
  it.each([
    // Template content serializes with scripting on, the main tree with it off.
    ['<p>a</p><template><noscript>&lt;/noscript&gt;</noscript></template>', { ADD_TAGS: ['noscript'], SAFE_FOR_XML: false }],
    ['<p>a</p><noscript>&lt;/noscript&gt;</noscript>', { ADD_TAGS: ['noscript'], SAFE_FOR_XML: false }],
    // jsdom lets a repeated <body> tag overwrite attribute values.
    ['<frameset><frame src=x></frameset>', {}],
    [String.fromCharCode(10, 9, 32) + '<p>x</p>', {}],
    ['  {{a}}<b>x</b>', { SAFE_FOR_TEMPLATES: true }],
    ['<body title="a"><p>x</p><body title="b" class="c">', { WHOLE_DOCUMENT: true }],
    ['<p id="--></p>" name="n">x</p>', { SANITIZE_NAMED_PROPS: true }],
    ['<p id="location" name=" user-content-x ">x</p>', { SANITIZE_NAMED_PROPS: true }],
    ['<svg><a xlink:href=" #x " href=" #y "><text>t</text></a></svg>', {}],
    ['<p data-x=" a " title=" t " value=" v ">x</p>', {}],
    ['<p is="x-foo" class="a" title="b">x</p>', {}],
    ['<x><y><z><b>deep</b></z></y></x>'.repeat(3), {}],
    ['<a href="&#x6A;avascript:1">a</a><a href="  https://ok.example  ">b</a>', {}],
    ['<style>p{}</style><p>x</p>', { WHOLE_DOCUMENT: true, FORCE_BODY: true }],
    ['<!DOCTYPE html><p>x</p>', { WHOLE_DOCUMENT: true, ADD_TAGS: ['!doctype'] }],
    ['<math><mi><svg><foreignObject><b>x</b></foreignObject></svg></mi></math>', {}],
    ['<template>{{a}}<b></b>}}</template><p>{{</p>x<i></i>}}', { SAFE_FOR_TEMPLATES: true }],
    ['<table><td>x</td></table><table><tbody></tbody></table>', { FORBID_TAGS: ['tbody'] }],
    ['<select><option>a<svg><b>c</b></svg></option></select>', {}],
    ['<form><input name="attributes"><input id="submit"></form>', {}],
    ['<p name="__proto__" id="toString">x</p>', {}],
  ] as Array<[string, HtmlSanitizerConfig]>)('matches DOMPurify on %j with %j', (input, config) => {
    expect(sanitizeHtmlDetailed(input, config)).toEqual(referenceSanitize(input, config));
  });

  it('throws like DOMPurify when the document element is forbidden but its content kept', () => {
    const config = { WHOLE_DOCUMENT: true, FORBID_TAGS: ['html'] };
    expect(() => referenceSanitize('<p>x</p>', config)).toThrow();
    expect(() => sanitizeHtml('<p>x</p>', config)).toThrow(/HierarchyRequestError/);
    const dropContent = { ...config, KEEP_CONTENT: false };
    expect(sanitizeHtml('<p>x</p>', dropContent)).toBe(referenceSanitize('<p>x</p>', dropContent).html);
  });

  it('keeps the clobbering name list in sync with jsdom', () => {
    const { window } = new JSDOM('');
    const document = window.document.createElement('template').content.ownerDocument;
    const form = document.createElement('form');
    const names = new Set<string>();
    for (const start of [document, form]) {
      for (let proto: object | null = start; proto !== null; proto = Object.getPrototypeOf(proto)) {
        for (const key of Reflect.ownKeys(proto)) {
          if (typeof key === 'string') {
            names.add(key);
          }
        }
      }
    }
    expect([...CLOBBERABLE_NAMES].sort()).toEqual([...names].sort());
  });
});

describe('packaging', () => {
  const htmlDir = resolve(srcDir, 'html');
  const files = readdirSync(htmlDir).filter((name) => name.endsWith('.ts'));

  function specifiers(source: string): string[] {
    const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
    const found: string[] = [];
    const patterns = [
      /\b(?:import|export)\b[^'"`;]*?\bfrom\s*['"]([^'"]+)['"]/g,
      /\bimport\s*['"]([^'"]+)['"]/g,
      /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
      /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    ];
    for (const pattern of patterns) {
      for (const match of code.matchAll(pattern)) {
        found.push(match[1]);
      }
    }
    return found;
  }

  it('src/html imports nothing but parse5 and local files', () => {
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const source = readFileSync(resolve(htmlDir, file), 'utf-8');
      for (const specifier of specifiers(source)) {
        expect({ file, specifier, ok: specifier === 'parse5' || specifier.startsWith('./') }).toEqual({
          file,
          specifier,
          ok: true,
        });
      }
      expect(source).not.toMatch(/\bprocess\.|\bBuffer\b|\b__dirname\b/);
    }
  });

  it('only the parse5 loaders reference parse5 at runtime', () => {
    const runtimeImporters = files.filter((file) => {
      const source = readFileSync(resolve(htmlDir, file), 'utf-8');
      return /(?:^|\n)\s*(?:import|export)\s+(?!type\b)[^;]*from\s*'parse5'|require\('parse5'\)/.test(source);
    });
    expect(runtimeImporters.sort()).toEqual(['load-parse5.cjs.ts', 'load-parse5.ts']);
  });

  it('the core entry does not reach the HTML module or parse5', () => {
    const index = readFileSync(resolve(srcDir, 'index.ts'), 'utf-8');
    expect(specifiers(index).filter((s) => s.includes('html') || s === 'parse5')).toEqual([]);
    const others = readdirSync(srcDir, { recursive: true, encoding: 'utf-8' })
      .filter((name) => name.endsWith('.ts') && !name.replace(/\\/g, '/').startsWith('html/'))
      .filter((name) => specifiers(readFileSync(resolve(srcDir, name), 'utf-8')).includes('parse5'));
    expect(others).toEqual([]);
  });
});

describe('idempotence', () => {
  it('sanitizing twice equals sanitizing once, wherever DOMPurify is idempotent', () => {
    const notIdempotentInDomPurify: string[] = [];
    const failures: Array<{ id: string; once: string; twice: string }> = [];
    for (const fixture of vectors.cases) {
      const config = toConfig(fixture.config);
      const once = sanitizeHtml(fixture.input, config);
      const twice = sanitizeHtml(once, config);
      const reference = referenceSanitize(fixture.expected, config).html;
      if (reference !== fixture.expected) {
        notIdempotentInDomPurify.push(fixture.id);
        // Not asserted as idempotent; the second pass must still match DOMPurify.
        expect(twice).toBe(reference);
        continue;
      }
      if (twice !== once) {
        failures.push({ id: fixture.id, once, twice });
      }
    }
    expect(failures).toEqual([]);
    expect(notIdempotentInDomPurify).toEqual(KNOWN_NOT_IDEMPOTENT_IN_DOMPURIFY);
  });
});

/**
 * Fixture cases where DOMPurify's own output changes when sanitized again,
 * kept explicit so a change is noticed:
 * - output that starts with <template> or <title> reparses into <head>, which
 *   the second pass drops (dompurify-040, fuzz-044, fuzz-261, fuzz-331, fuzz-374);
 * - nested form, option and heading structures inside MathML text that
 *   reparse into a different tree (dompurify-206, -209, -211, -214);
 * - SAFE_FOR_TEMPLATES leaves title=" ", which the second pass trims to "".
 */
const KNOWN_NOT_IDEMPOTENT_IN_DOMPURIFY: string[] = [
  'dompurify-040',
  'dompurify-206',
  'dompurify-209',
  'dompurify-211',
  'dompurify-214',
  'config-safe_for_templates',
  'fuzz-044',
  'fuzz-261',
  'fuzz-331',
  'fuzz-374',
];
