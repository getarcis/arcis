/**
 * Shared fixtures (spec/html-sanitizer-vectors.json): every case must give
 * DOMPurify's exact html, and the removed list DOMPurify reported minus the
 * html, head and body element entries (API_SPEC.md section 11).
 */
import { describe, expect, it } from 'vitest';
import { sanitizeHtmlDetailed } from '../../src/html';
import { reportable, toConfig, vectors } from './helpers';

describe('HTML sanitizer fixtures', () => {
  it('pins the reference versions the fixtures were generated with', () => {
    expect(vectors.reference).toEqual({ dompurify: '3.4.18', jsdom: '31.0.1', parse5: '8.1.1' });
    expect(vectors.cases).toHaveLength(668);
  });

  describe.each(['dompurify', 'config', 'benign', 'fuzz'])('%s corpus', (source) => {
    const cases = vectors.cases.filter((c) => c.source === source);

    it.each(cases.map((c) => [c.id, c] as const))('%s', (_id, fixture) => {
      const result = sanitizeHtmlDetailed(fixture.input, toConfig(fixture.config));
      expect(result.html).toBe(fixture.expected);
      expect(result.removed).toEqual(reportable(fixture.removed));
    });
  });
});
