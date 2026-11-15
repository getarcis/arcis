#!/usr/bin/env node
/**
 * Generates spec/html-sanitizer-vectors.json: the shared HTML sanitizer
 * fixtures every Arcis SDK must pass.
 *
 * Expected outputs come from running DOMPurify (pinned devDependency) on
 * jsdom, never from Arcis itself. Corpora:
 *   - dompurify: DOMPurify's published test payloads (test/fixtures/expect.mjs)
 *   - config:    one case per supported configuration option
 *   - benign:    rich-text markup that must survive unchanged or nearly so
 *   - fuzz:      seeded, grammar-generated markup around known breakout shapes
 *
 * Usage: node scripts/generate-html-vectors.mjs <path-to-DOMPurify-checkout>
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { JSDOM } from 'jsdom';
import createDOMPurify from 'dompurify';

const here = dirname(fileURLToPath(import.meta.url));
const checkout = process.argv[2];
if (!checkout) {
  console.error('usage: generate-html-vectors.mjs <path-to-DOMPurify-checkout>');
  process.exit(1);
}

// Some of these packages do not export package.json, so read it from disk.
const versionOf = (name) =>
  JSON.parse(readFileSync(resolve(here, '../node_modules', name, 'package.json'), 'utf-8')).version;
const versions = {
  dompurify: versionOf('dompurify'),
  jsdom: versionOf('jsdom'),
  parse5: versionOf('parse5'),
};

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

/** Config as stored in JSON; ALLOWED_URI_REGEXP is { source, flags }. */
function toDomPurifyConfig(config) {
  const out = { ...config };
  if (config.ALLOWED_URI_REGEXP) {
    out.ALLOWED_URI_REGEXP = new RegExp(config.ALLOWED_URI_REGEXP.source, config.ALLOWED_URI_REGEXP.flags);
  }
  return out;
}

function describeRemoved(entry) {
  if (entry.attribute) {
    return { attribute: entry.attribute.name, from: entry.from?.nodeName?.toLowerCase() ?? null };
  }
  return { element: entry.element?.nodeName?.toLowerCase() ?? null };
}

function run(input, config = {}) {
  const expected = DOMPurify.sanitize(input, toDomPurifyConfig(config));
  const removed = DOMPurify.removed.map(describeRemoved);
  return { expected, removed };
}

// ─── Corpus: DOMPurify's published payloads ─────────────────────────────

const { default: published } = await import(pathToFileURL(resolve(checkout, 'test/fixtures/expect.mjs')).href);
const dompurifyCases = published.map((test, index) => ({
  id: `dompurify-${String(index + 1).padStart(3, '0')}`,
  source: 'dompurify',
  title: test.title,
  config: {},
  input: test.payload,
}));

// ─── Corpus: configuration options ──────────────────────────────────────

const MIXED = '<p class="c" style="color:red" data-x="1" aria-label="a" title="t">Hi <b>bold</b> <a href="https://example.com/a" target="_blank" rel="noopener">link</a> <img src="x.png" onerror="alert(1)" alt="i"><script>alert(1)</script><custom-el>c</custom-el></p>';
const configCases = [
  ['allowed_tags_only', { ALLOWED_TAGS: ['b', 'i'] }, '<b>x</b><i>y</i><a href="x">z</a><script>1</script><p>keep text</p>'],
  ['allowed_attr_only', { ALLOWED_ATTR: ['href'] }, MIXED],
  ['add_tags_iframe', { ADD_TAGS: ['iframe'] }, '<iframe src="https://example.com/embed" srcdoc="<script>1</script>"></iframe>'],
  ['add_attr_target', { ADD_ATTR: ['target'] }, MIXED],
  ['forbid_tags', { FORBID_TAGS: ['style', 'b'] }, '<style>p{}</style><b>bold</b><i>it</i>'],
  ['forbid_attr', { FORBID_ATTR: ['style', 'class'] }, MIXED],
  ['no_data_attributes', { ALLOW_DATA_ATTR: false }, MIXED],
  ['no_aria_attributes', { ALLOW_ARIA_ATTR: false }, MIXED],
  ['keep_content_false', { KEEP_CONTENT: false }, '<p>a<foo>dropped text</foo><bar><b>b</b></bar></p>'],
  ['forbid_contents', { FORBID_CONTENTS: ['b'], FORBID_TAGS: ['b'] }, '<p>a<b>gone</b><i>kept</i></p>'],
  ['add_forbid_contents', { ADD_FORBID_CONTENTS: ['foo'] }, '<p>a<foo>gone</foo><bar>kept</bar></p>'],
  ['allow_unknown_protocols', { ALLOW_UNKNOWN_PROTOCOLS: true }, '<a href="foo:bar">x</a><a href="javascript:alert(1)">y</a><a href="ftp://h">z</a>'],
  ['allowed_uri_regexp_https_only', { ALLOWED_URI_REGEXP: { source: '^https:', flags: 'i' } }, '<a href="https://a.example">a</a><a href="http://b.example">b</a><a href="/c">c</a><img src="data:image/png;base64,AA">'],
  ['add_uri_safe_attr', { ADD_ATTR: ['my-link'], ADD_URI_SAFE_ATTR: ['my-link'] }, '<a my-link="javascript:alert(1)" href="javascript:alert(1)">x</a>'],
  ['add_data_uri_tags', { ADD_DATA_URI_TAGS: ['a'] }, '<a href="data:text/plain,hi">x</a><img src="data:image/png;base64,AA">'],
  ['profile_html', { USE_PROFILES: { html: true } }, '<p>x</p><svg><rect width="1"></rect></svg><math><mi>x</mi></math>'],
  ['profile_svg', { USE_PROFILES: { svg: true } }, '<p>x</p><svg><rect width="1"></rect><filter><feBlend></feBlend></filter></svg>'],
  ['profile_svg_filters', { USE_PROFILES: { svg: true, svgFilters: true } }, '<svg><filter id="f"><feGaussianBlur stdDeviation="1"></feGaussianBlur></filter></svg>'],
  ['profile_mathml', { USE_PROFILES: { mathMl: true } }, '<p>x</p><math><mi>x</mi><mo>+</mo></math>'],
  ['safe_for_templates', { SAFE_FOR_TEMPLATES: true }, '<p title="{{x}}">{{constructor.constructor}} ${alert(1)} <%= y %></p>'],
  ['safe_for_xml_false', { SAFE_FOR_XML: false }, '<p>a<!-- <img src=x> -->b</p><p title="--><b>">c</p>'],
  ['sanitize_dom_false', { SANITIZE_DOM: false }, '<img id="location" name="attributes"><form name="body"></form>'],
  ['sanitize_named_props', { SANITIZE_NAMED_PROPS: true }, '<p id="intro" name="x">a</p><a name="top">b</a>'],
  ['whole_document', { WHOLE_DOCUMENT: true }, '<html><head><title>t</title></head><body><p>x</p></body></html>'],
  ['force_body', { FORCE_BODY: true }, '<style>p{color:red}</style><p>x</p>'],
  ['no_self_close_in_attr', { ALLOW_SELF_CLOSE_IN_ATTR: false }, '<p title="/>">a</p><a href="x" title="ok">b</a>'],
  ['combined_rich_text', { ALLOWED_TAGS: ['p', 'a', 'b', 'i', 'ul', 'li', 'br'], ALLOWED_ATTR: ['href'] }, '<ul><li><a href="https://x.example" onclick="x()">l</a></li></ul><p>t<br><b>b</b><span>s</span></p>'],
].map(([name, config, input]) => ({ id: `config-${name}`, source: 'config', title: name, config, input }));

// ─── Corpus: benign rich text ───────────────────────────────────────────

const benign = [
  '<h1>Title</h1><p>Paragraph with <strong>strong</strong>, <em>em</em>, <code>code</code> and <a href="https://example.com/?q=1&amp;r=2">a link</a>.</p>',
  '<ul><li>one</li><li>two<ul><li>nested</li></ul></li></ul><ol start="3"><li>three</li></ol>',
  '<table><thead><tr><th scope="col">A</th></tr></thead><tbody><tr><td colspan="2">1</td></tr></tbody></table>',
  '<blockquote cite="https://example.com">quote</blockquote><pre><code class="language-js">const a = 1 &lt; 2;</code></pre>',
  '<img src="https://example.com/a.png" alt="A" width="10" height="10" loading="lazy"><figure><figcaption>Cap</figcaption></figure>',
  '<p>Unicode: café, 日本語, مرحبا, emoji 😀, nbsp here</p>',
  '<p>Invoice #1029: 3 &times; widgets @ $4.50 &mdash; total $13.50 (tax 7.5%)</p>',
  '<a href="mailto:a@example.com">mail</a> <a href="tel:+15551234567">call</a> <a href="#section">anchor</a> <a href="/relative/path">rel</a>',
  '<details><summary>More</summary><p>Hidden</p></details><hr><br><sub>2</sub><sup>3</sup><mark>m</mark>',
  '<svg viewBox="0 0 10 10" width="10" height="10"><circle cx="5" cy="5" r="4" fill="red"></circle><path d="M0 0L10 10"></path></svg>',
  '<math><mrow><mi>x</mi><mo>=</mo><mfrac><mn>1</mn><mn>2</mn></mfrac></mrow></math>',
  '<p dir="rtl" lang="ar">نص</p><span class="badge" data-id="42" aria-hidden="true">x</span>',
  '<p>Text with <br> line break and &lt;not a tag&gt; and 5 &lt; 6 &amp;&amp; 7 &gt; 3</p>',
  '<input type="checkbox" checked disabled> <label for="x">Label</label> <button type="button">Click</button>',
  '<video controls src="https://example.com/v.mp4"><track kind="captions" src="c.vtt"></video><audio src="a.mp3"></audio>',
  'Plain text with no markup at all, but quotes " and \' and ampersand &.',
  '',
  '   leading and trailing whitespace   ',
].map((input, index) => ({ id: `benign-${String(index + 1).padStart(3, '0')}`, source: 'benign', title: `benign ${index + 1}`, config: {}, input }));

// ─── Corpus: seeded fuzz ────────────────────────────────────────────────

function mulberry32(seed) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const TAGS = ['div', 'p', 'a', 'img', 'svg', 'math', 'style', 'script', 'template', 'noscript', 'iframe', 'form', 'input', 'select', 'option', 'table', 'tr', 'td', 'textarea', 'title', 'xmp', 'noembed', 'noframes', 'foreignObject', 'mglyph', 'malignmark', 'annotation-xml', 'mtext', 'mi', 'desc', 'object', 'embed', 'base', 'meta', 'link', 'button', 'details', 'video', 'source', 'image', 'use', 'animate', 'set', 'b', 'span', 'custom-el', 'plaintext', 'listing', 'iframe', 'frameset', 'keygen', 'head', 'body', 'html'];
const ATTRS = ['onerror=alert(1)', 'onclick="x()"', 'href="javascript:alert(1)"', 'href="jav&#x09;ascript:alert(1)"', 'href=" javascript:1"', 'src="data:text/html,<script>alert(1)</script>"', 'src="x"', 'xlink:href="javascript:alert(1)"', 'style="color:red;background:url(javascript:1)"', 'id="location"', 'name="attributes"', 'name="cookie"', 'data-x="1"', 'aria-label="a"', 'is="x-foo"', 'class="c"', 'title="</style><img src=x onerror=alert(1)>"', 'alt="<!--"', 'value="--><script>alert(1)</script>"', 'formaction="javascript:alert(1)"', 'srcdoc="<script>alert(1)</script>"', 'action="javascript:x"', 'background="javascript:1"', 'href="https://ok.example/p?a=1&b=2"', 'target="_blank"', 'rel="noopener"', 'shadowrootmode="open"', 'encoding="text/html"', 'xmlns="http://www.w3.org/1999/xhtml"', 'title="{{x}}"', 'attributename="href"', 'to="javascript:alert(1)"', 'values="javascript:alert(1)"'];
const TEXTS = ['hello', '<', '>', '&amp;', '&lt;script&gt;alert(1)&lt;/script&gt;', '{{constructor}}', '${x}', '<%= x %>', '<!-- c -->', '<![CDATA[ x ]]>', '<?xml x?>', '</div>', '</p>', '<br>', '&#0;', '\u0000', ' ', '</style>', '</textarea>', '</title>', '</noscript>', '<img src=x onerror=alert(1)>', '-->', ']]>'];

function fuzzCase(random) {
  const pick = (list) => list[Math.floor(random() * list.length)];
  const node = (depth) => {
    if (depth > 3 || random() < 0.3) return pick(TEXTS);
    const tag = pick(TAGS);
    const attrs = Array.from({ length: Math.floor(random() * 3) }, () => ' ' + pick(ATTRS)).join('');
    const children = Array.from({ length: Math.floor(random() * 3) }, () => node(depth + 1)).join('');
    const close = random() < 0.8 ? `</${random() < 0.9 ? tag : pick(TAGS)}>` : '';
    return `<${tag}${attrs}>${children}${close}`;
  };
  return Array.from({ length: 1 + Math.floor(random() * 3) }, () => node(0)).join('');
}

const random = mulberry32(20261115);
const seen = new Set();
const fuzzCases = [];
while (fuzzCases.length < 400) {
  const input = fuzzCase(random);
  if (seen.has(input)) continue;
  seen.add(input);
  fuzzCases.push({ id: `fuzz-${String(fuzzCases.length + 1).padStart(3, '0')}`, source: 'fuzz', title: 'seeded fuzz', config: {}, input });
}

// ─── Emit ───────────────────────────────────────────────────────────────

const cases = [...dompurifyCases, ...configCases, ...benign, ...fuzzCases].map((c) => ({ ...c, ...run(c.input, c.config) }));

const vectors = {
  version: '1.0',
  description:
    'Shared HTML sanitizer fixtures. Expected output and removed items come from running DOMPurify on jsdom with each case config. Every Arcis SDK must produce the same html for every case. Regenerate with packages/arcis-node/scripts/generate-html-vectors.mjs.',
  reference: versions,
  attribution:
    'Cases with source "dompurify" are DOMPurify test payloads (test/fixtures/expect.mjs), (c) Cure53 and other contributors, used under the Apache License 2.0. See THIRDPARTY-LICENSES.md.',
  counts: {
    dompurify: dompurifyCases.length,
    config: configCases.length,
    benign: benign.length,
    fuzz: fuzzCases.length,
  },
  cases,
};

const target = resolve(here, '../../../spec/html-sanitizer-vectors.json');
writeFileSync(target, JSON.stringify(vectors, null, 2) + '\n');
console.log(`wrote ${cases.length} cases to ${target}`, vectors.counts, versions);
