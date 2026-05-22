/**
 * Encoding-chain bypass regression suite — improvements.md §1.1.b.
 *
 * Before v1.6 Node only saw the input string as the caller provided
 * it. A payload wrapped in N layers of URL or HTML entity encoding
 * never matched the XSS regex because the literal `<script>` shape
 * was hidden behind the wrappers.
 *
 * Fix: `sanitizeString` now runs `multiDecode()` (bounded at 4
 * passes of URL + HTML entity decode) AFTER NFKC normalization and
 * BEFORE the XSS / SQL / path / command detectors. These tests pin
 * that behaviour.
 */
import { describe, it, expect } from 'vitest';
import { sanitizeString } from '../../src/sanitizers/sanitize';

describe('Encoding-chain bypass class (improvements.md §1.1.b)', () => {
  it('strips URL-encoded <script>', () => {
    const result = sanitizeString('%3Cscript%3Ealert(1)%3C/script%3E');
    expect(result.toLowerCase()).not.toContain('<script');
    expect(result.toLowerCase()).not.toContain('%3c');
  });

  it('strips double-URL-encoded <script>', () => {
    const result = sanitizeString('%253Cscript%253Ealert(1)%253C/script%253E');
    expect(result.toLowerCase()).not.toContain('<script');
    expect(result.toLowerCase()).not.toContain('%253c');
  });

  it('strips triple-encoded (URL+URL+HTML) <script> opener', () => {
    const result = sanitizeString('%2526%2523x3c%253bscript%2526%2523x3e%253b');
    expect(result.toLowerCase()).not.toContain('<script');
    expect(result).not.toContain('%2526');
  });

  it('strips HTML hex-entity <script>', () => {
    const result = sanitizeString('&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;');
    expect(result.toLowerCase()).not.toContain('<script');
    expect(result.toLowerCase()).not.toContain('&#x3c');
  });

  it('strips HTML named-entity <script>', () => {
    const result = sanitizeString('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(result.toLowerCase()).not.toContain('<script');
    expect(result.toLowerCase()).not.toContain('&lt;');
  });

  it('decodes safe URL-encoded text through unchanged', () => {
    expect(sanitizeString('John%20Doe')).toBe('John Doe');
  });

  it('terminates on pathological deeply-encoded input', () => {
    // Five layers of URL-encoding the `<` character. With max 4
    // decode passes, the helper must not loop indefinitely. We
    // just assert it returns a string.
    const payload = '%' + '25'.repeat(8) + '3Cscript%' + '25'.repeat(8) + '3E';
    const result = sanitizeString(payload);
    expect(typeof result).toBe('string');
  });

  it('cross-SDK parity: matches Python sanitize_string output for these bypass cases', () => {
    // Pin the exact strings the conformance script verifies against
    // Python. Drift here = Pattern 7 violation; rebuild the
    // conformance harness from documents/attacks/cross_sdk_conformance.py.
    // After NFKC + multi-decode + XSS strip + command strip, the
    // `<script>...<\/script>` block fully decodes and is fully removed.
    expect(sanitizeString('%3Cscript%3Ealert(1)%3C/script%3E')).toBe('');
    expect(sanitizeString('&lt;script&gt;alert(1)&lt;/script&gt;')).toBe('');
  });
});
