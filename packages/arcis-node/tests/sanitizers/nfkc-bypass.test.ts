/**
 * NFKC bypass regression suite — improvements.md §1.1.a.
 *
 * Before v1.6, only the Python SDK applied NFKC normalization, and only
 * to the path-traversal detector. Node had no normalization at all. That
 * left a whole bypass class open: fullwidth glyphs (＜script＞, ．．／,
 * javaｓcript：) that don't match ASCII regexes but render identically
 * in the browser after the host normalizes them.
 *
 * Fix: `sanitizeString` now calls `value.normalize('NFKC')` before any
 * detector runs. These tests pin that behavior so a future refactor
 * can't quietly drop the NFKC pass.
 */
import { describe, it, expect } from 'vitest';
import { sanitizeString } from '../../src/sanitizers/sanitize';

describe('NFKC bypass class (improvements.md §1.1.a)', () => {
  it('strips fullwidth <script> tag after NFKC normalization', () => {
    const payload = '＜script＞alert(1)＜/script＞';
    const result = sanitizeString(payload);
    expect(result.toLowerCase()).not.toContain('<script');
  });

  it('strips fullwidth javascript: protocol', () => {
    // Fullwidth lowercase s + fullwidth colon in `javaｓcript：`.
    const payload = 'javaｓcript：alert(1)';
    const result = sanitizeString(payload);
    expect(result.toLowerCase()).not.toContain('javascript:');
  });

  it('strips fullwidth path traversal `．．／`', () => {
    const payload = '．．／etc／passwd';
    const result = sanitizeString(payload);
    expect(result).not.toContain('../');
  });

  it('strips fullwidth iframe', () => {
    const payload = '＜iframe src="evil.com"＞';
    const result = sanitizeString(payload);
    expect(result.toLowerCase()).not.toContain('<iframe');
  });

  it('passes safe non-ASCII text through unchanged', () => {
    // Greek letters that NFKC leaves alone.
    expect(sanitizeString('αβγ hello')).toBe('αβγ hello');
  });

  it('decomposes ligatures but does not introduce threats', () => {
    // NFKC turns `ﬃ` into `ffi` — that's intentional, so detection
    // regexes can match ASCII forms. The output is still safe.
    expect(sanitizeString('oﬃce.txt')).toBe('office.txt');
  });

  it('cross-SDK parity: matches Python sanitize_string output for the bypass cases', () => {
    // Pin the exact strings the conformance script verifies against
    // the Python SDK. If these expected outputs change, the
    // `spec/TEST_VECTORS.json nfkc_bypass` section needs updating in
    // lockstep.
    expect(sanitizeString('＜script＞alert(1)＜/script＞')).toBe('');
    expect(sanitizeString('．．／etc／passwd')).toBe('etc/passwd');
  });
});
