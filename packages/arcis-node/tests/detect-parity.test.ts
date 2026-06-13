/**
 * Cross-SDK detection-parity conformance tests for Node.
 *
 * Loads `spec/TEST_VECTORS.json` and asserts every payload in the
 * `detect_parity` block classifies under the right vector when fed
 * through Node's `detectXss / detectSql / detectPathTraversal /
 * detectCommandInjection / detectSsti / detectXxe`.
 *
 * The same test vectors are run by the Python and Go SDKs (see their
 * respective conformance tests). If a payload is caught by one SDK but
 * missed by another, that's a Pattern 7 (Cross-SDK Parity Contract)
 * violation and the failing assertion points at the SDK that diverged.
 *
 * Why this matters: Node uses hardcoded `XSS_PATTERNS` arrays; Python
 * loads from `packages/core/patterns.json`; Go has its own list.
 * Without a shared parity test the three lists drift silently.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  detectXss,
  detectSql,
  detectPathTraversal,
  detectCommandInjection,
  detectSsti,
  detectXxe,
  detectNoSqlString,
} from '../src/index';

interface ParityCase {
  input: string;
  expected: boolean;
}

interface ParityBlock {
  xss_positive?: ParityCase[];
  xss_negative?: ParityCase[];
  sql_positive?: ParityCase[];
  sql_negative?: ParityCase[];
  path_positive?: ParityCase[];
  path_negative?: ParityCase[];
  command_positive?: ParityCase[];
  command_negative?: ParityCase[];
  ssti_positive?: ParityCase[];
  ssti_negative?: ParityCase[];
  xxe_positive?: ParityCase[];
  xxe_negative?: ParityCase[];
  nosql_positive?: ParityCase[];
  nosql_negative?: ParityCase[];
}

function loadParity(): ParityBlock {
  // Walk up from this test file until we find a `spec/` sibling. Lets
  // the test work whether vitest is invoked from the package root or
  // the repo root.
  const here = fileURLToPath(import.meta.url);
  let dir = resolve(here, '..');
  for (let i = 0; i < 8; i++) {
    try {
      const path = resolve(dir, 'spec', 'TEST_VECTORS.json');
      const raw = readFileSync(path, 'utf-8');
      const parsed = JSON.parse(raw) as { detect_parity?: ParityBlock };
      if (parsed.detect_parity) return parsed.detect_parity;
    } catch {
      // continue walking up
    }
    const parent = resolve(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('Could not locate spec/TEST_VECTORS.json with detect_parity');
}

const parity = loadParity();

const DETECTORS: Array<{
  name: string;
  fn: (input: string) => boolean;
  pos: keyof ParityBlock;
  neg: keyof ParityBlock;
}> = [
  { name: 'xss', fn: detectXss, pos: 'xss_positive', neg: 'xss_negative' },
  { name: 'sql', fn: detectSql, pos: 'sql_positive', neg: 'sql_negative' },
  { name: 'path', fn: detectPathTraversal, pos: 'path_positive', neg: 'path_negative' },
  { name: 'command', fn: detectCommandInjection, pos: 'command_positive', neg: 'command_negative' },
  { name: 'ssti', fn: detectSsti, pos: 'ssti_positive', neg: 'ssti_negative' },
  { name: 'xxe', fn: detectXxe, pos: 'xxe_positive', neg: 'xxe_negative' },
  { name: 'nosql', fn: detectNoSqlString, pos: 'nosql_positive', neg: 'nosql_negative' },
];

describe('Cross-SDK detect parity (TEST_VECTORS.json detect_parity block)', () => {
  for (const { name, fn, pos, neg } of DETECTORS) {
    describe(`detect_${name}`, () => {
      const positives = parity[pos] ?? [];
      const negatives = parity[neg] ?? [];

      for (const c of positives) {
        it(`positive: ${JSON.stringify(c.input).slice(0, 60)}`, () => {
          expect(fn(c.input)).toBe(true);
        });
      }
      for (const c of negatives) {
        it(`negative: ${JSON.stringify(c.input).slice(0, 60)}`, () => {
          expect(fn(c.input)).toBe(false);
        });
      }
    });
  }
});
