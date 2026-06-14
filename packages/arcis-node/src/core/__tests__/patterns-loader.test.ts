/**
 * Tests for the patterns.json loader and the runtime-patterns migration.
 *
 * Guards two things now that Node sources its detection patterns from
 * patterns.json instead of hardcoded literals:
 *   1. The loader compiles every rule in every category it consumes (a silent
 *      skip would mean a dropped detector).
 *   2. A benign corpus is never flagged by any detector (the 0% false-positive
 *      promise). This is the regression net for future patterns.json edits.
 */

import { describe, it, expect } from 'vitest';
import {
  compileCategory,
  compileRule,
  dangerousKeysFor,
  PATTERNS_VERSION,
} from '../patterns-loader';
import { detectXss, detectSql, detectPathTraversal, detectCommandInjection } from '../../sanitizers';

describe('patterns.json loader', () => {
  it('compiles every rule in each detection category', () => {
    for (const category of ['xss', 'sql_injection', 'path_traversal', 'command_injection']) {
      const compiled = compileCategory(category);
      expect(compiled.length, `${category} compiled to zero patterns`).toBeGreaterThan(0);
      for (const re of compiled) expect(re).toBeInstanceOf(RegExp);
    }
  });

  it('resolves the nosql-operators string rule', () => {
    const rule = compileRule('nosql_injection', 'nosql-operators');
    expect(rule).toBeInstanceOf(RegExp);
    expect(rule!.test('$ne')).toBe(true);
    expect(rule!.test('$invoice')).toBe(false); // word-boundary guard
  });

  it('exposes dangerous-key lists', () => {
    expect(dangerousKeysFor('prototype_pollution')).toContain('__proto__');
    expect(dangerousKeysFor('nosql_injection')).toContain('$where');
    expect(dangerousKeysFor('does-not-exist')).toEqual([]);
  });

  it('reports the bundled spec version', () => {
    expect(typeof PATTERNS_VERSION).toBe('string');
    expect(PATTERNS_VERSION.length).toBeGreaterThan(0);
  });
});

describe('detection false-positive guard (benign corpus stays unflagged)', () => {
  const benign = [
    'Hello World',
    "O'Brien",
    "it's a test",
    "Sam's OR Jill's",
    "author='John'",
    'select an option from the menu',
    "I'll update you tomorrow",
    'delete this file please',
    'please update your profile',
    '#FF5300',
    '#trending',
    'issue #123',
    '# Heading',
    'metadata: value',
    'JavaScript: The Good Parts',
    'npm install',
    'const x = 1;',
    'a=1&b=2',
    '5 > 3',
    '3 < 5 && 5 > 3',
    '<!-- TODO -->',
    'https://www.instagram.com/foo',
    '<styled component>',
    '<StyledButton>',
    'user@example.com',
    '/static/img/logo.png',
    'The quick brown fox',
    'price: $5.00',
    'union of two sets',
    'I would like to create a function',
    // Benign inline-image data URI: clean for XSS (the broad-`data:` FP was
    // fixed in the patterns migration) AND for command injection (the
    // cmdi-shell-chars `base64` token now requires a trailing space / EOL, so
    // the `;base64,` MIME parameter no longer matches while `;base64 -d` does).
    // NB: data:image/svg+xml is intentionally excluded — SVG data URIs can
    // carry inline scripts and are correctly flagged as XSS.
    'src="data:image/png;base64,iVBORw0KGgo="',
  ];

  for (const input of benign) {
    it(`does not flag ${JSON.stringify(input)}`, () => {
      expect(detectXss(input), 'xss').toBe(false);
      expect(detectSql(input), 'sql').toBe(false);
      expect(detectPathTraversal(input), 'path').toBe(false);
      expect(detectCommandInjection(input), 'command').toBe(false);
    });
  }
});
