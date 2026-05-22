/**
 * Mutation resistance tests for `sanitizeString` (improvements.md §1.1.d).
 *
 * Generates encoding / case / unicode variants of every base attack
 * payload and asserts that `sanitizeString` still strips the threat
 * from each variant. Structural safeguard against future regex /
 * normalization regressions silently re-opening a bypass class.
 *
 * Coverage: ~140 mutation checks (XSS / SQL / path × 8 mutators).
 *
 * Mirrors `tests/sanitizers/test_mutation_resistance.py` in the
 * Python SDK; the two suites should accept the same base corpus
 * (cross-SDK parity contract per Pattern 7).
 */
import { describe, it, expect } from 'vitest';
import { sanitizeString } from '../../src/sanitizers/sanitize';

// ─── Mutators ──────────────────────────────────────────────────────────

function alternatingCase(s: string): string {
  return s
    .split('')
    .map((c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase()))
    .join('');
}

function uppercase(s: string): string {
  return s.toUpperCase();
}

function urlEncodeOnce(s: string): string {
  // encodeURIComponent leaves a few chars (e.g. ! * ' ( ) ~) unescaped.
  // Force-encode them so the mutation is real.
  return encodeURIComponent(s).replace(
    /[!*'()~]/g,
    (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase(),
  );
}

function urlEncodeTwice(s: string): string {
  return urlEncodeOnce(urlEncodeOnce(s));
}

function htmlEntityHex(s: string): string {
  return s
    .split('')
    .map((c) =>
      /[a-zA-Z0-9]/.test(c) ? c : `&#x${c.charCodeAt(0).toString(16)};`,
    )
    .join('');
}

function htmlEntityDecimal(s: string): string {
  return s
    .split('')
    .map((c) => (/[a-zA-Z0-9]/.test(c) ? c : `&#${c.charCodeAt(0)};`))
    .join('');
}

function htmlEntityNamed(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function fullwidthAscii(s: string): string {
  // ASCII printable (0x21–0x7E) → fullwidth (U+FF01–U+FF5E). NFKC in
  // sanitizeString folds them back to ASCII, so the mutated payload
  // hits the same regex path as the original.
  return s
    .split('')
    .map((c) => {
      const code = c.charCodeAt(0);
      if (code >= 0x21 && code <= 0x7e) {
        return String.fromCodePoint(code + 0xfee0);
      }
      return c;
    })
    .join('');
}

const MUTATORS: Record<string, (s: string) => string> = {
  alternating_case: alternatingCase,
  uppercase: uppercase,
  url_encode_once: urlEncodeOnce,
  url_encode_twice: urlEncodeTwice,
  html_entity_hex: htmlEntityHex,
  html_entity_decimal: htmlEntityDecimal,
  html_entity_named: htmlEntityNamed,
  fullwidth_ascii: fullwidthAscii,
};

// ─── Category corpora ──────────────────────────────────────────────────

type Case = readonly [string, readonly string[]];

const XSS_CASES: readonly Case[] = [
  ['<script>alert(1)</script>', ['<script', '</script']],
  ['<img onerror=alert(1) src=x>', ['onerror=']],
  ['javascript:alert(1)', ['javascript:']],
  ['<iframe src=evil.com>', ['<iframe']],
  ['<svg onload=alert(1)>', ['onload=']],
  ['<object data=evil>', ['<object']],
  ['<embed src=evil>', ['<embed']],
  ['<style>body{x:expression(alert(1))}</style>', ['<style']],
];

const SQL_CASES: readonly Case[] = [
  ["' OR 1=1--", ['or 1=1']],
  ["'; DROP TABLE users--", ['drop']],
  ['UNION SELECT * FROM users', ['union', 'select']],
  ["admin'--", ['--']],
  ['1; DELETE FROM users', ['delete']],
  ['SLEEP(5)', ['sleep(']],
  // improvements.md §1.1.e Q3: Oracle DBMS_* packages.
  ['foo; DBMS_LOCK.SLEEP(5)', ['dbms_']],
  ['foo; DBMS_PIPE.RECEIVE_MESSAGE(x,5)', ['dbms_']],
  ["foo; DBMS_JAVA.RUNJAVA('...')", ['dbms_']],
];

const PATH_CASES: readonly Case[] = [
  ['../../etc/passwd', ['../']],
  ['..\\..\\windows\\system32', ['..\\']],
  ['/var/www/../../etc/shadow', ['../']],
  ['../'.repeat(5) + 'etc/passwd', ['../']],
];

// SQL has no HTML-entity / named-entity bypass class in the wild —
// trim the matrix accordingly. Mirrors the Python suite.
const SQL_MUTATORS = Object.fromEntries(
  Object.entries(MUTATORS).filter(([n]) => n !== 'html_entity_named'),
);

// ─── Mutation harness ──────────────────────────────────────────────────

function runCheck(
  category: string,
  base: string,
  tokens: readonly string[],
  mutatorName: string,
  mutator: (s: string) => string,
) {
  let mutated: string;
  try {
    mutated = mutator(base);
  } catch (e) {
    throw new Error(
      `mutator ${mutatorName} threw on input ${JSON.stringify(base)}: ${String(e)}`,
    );
  }
  const output = sanitizeString(mutated).toLowerCase();
  for (const token of tokens) {
    expect(
      output.includes(token.toLowerCase()),
      `BYPASS: ${category} payload ${JSON.stringify(base)} survived ` +
        `mutation ${mutatorName} as ${JSON.stringify(mutated)} → output ` +
        `${JSON.stringify(output)} still contains ${JSON.stringify(token)}`,
    ).toBe(false);
  }
}

// ─── Test matrix ───────────────────────────────────────────────────────

describe('XSS mutation resistance (improvements.md §1.1.d)', () => {
  for (const [base, tokens] of XSS_CASES) {
    for (const [mutName, mutator] of Object.entries(MUTATORS)) {
      it(`${mutName}: ${base.slice(0, 30)}...`, () => {
        runCheck('xss', base, tokens, mutName, mutator);
      });
    }
  }
});

describe('SQL mutation resistance', () => {
  for (const [base, tokens] of SQL_CASES) {
    for (const [mutName, mutator] of Object.entries(SQL_MUTATORS)) {
      it(`${mutName}: ${base.slice(0, 30)}`, () => {
        runCheck('sql', base, tokens, mutName, mutator);
      });
    }
  }
});

describe('Path traversal mutation resistance', () => {
  for (const [base, tokens] of PATH_CASES) {
    for (const [mutName, mutator] of Object.entries(MUTATORS)) {
      it(`${mutName}: ${base.slice(0, 30)}`, () => {
        runCheck('path_traversal', base, tokens, mutName, mutator);
      });
    }
  }
});

// ─── Mutator sanity checks ─────────────────────────────────────────────
// Catches a future refactor that turns a mutator into the identity
// function (which would make every other test pass vacuously).

describe('mutators actually mutate', () => {
  it('alternating_case changes input', () => {
    expect(alternatingCase('abcdef')).not.toBe('abcdef');
  });

  it('url_encode_twice doubles percent signs', () => {
    const twice = urlEncodeTwice('<x>');
    const matches = twice.match(/%25/g) ?? [];
    expect(matches.length).toBeGreaterThanOrEqual(2);
  });

  it('fullwidth_ascii actually uses fullwidth codepoints', () => {
    const out = fullwidthAscii('abc');
    for (const c of out) {
      const code = c.codePointAt(0)!;
      expect(code).toBeGreaterThanOrEqual(0xff21);
      expect(code).toBeLessThanOrEqual(0xff7a);
    }
  });

  it('html_entity_hex encodes brackets', () => {
    expect(htmlEntityHex('<')).toContain('&#x3c;');
  });
});
