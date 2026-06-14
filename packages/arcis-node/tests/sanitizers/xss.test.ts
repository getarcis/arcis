/**
 * XSS Sanitizer Tests
 * Tests for src/sanitizers/xss.ts
 */

import { describe, it, expect } from 'vitest';
import { sanitizeXss, detectXss } from '../../src/sanitizers/xss';

describe('sanitizeXss', () => {
  describe('Script Tag Removal', () => {
    it('should remove script tags', () => {
      const result = sanitizeXss('<script>alert("xss")</script>');
      expect(result).not.toContain('<script>');
    });

    it('should handle script tags with attributes', () => {
      const result = sanitizeXss('<script src="evil.js"></script>');
      expect(result).not.toContain('<script');
    });

    it('should handle nested script tags', () => {
      const result = sanitizeXss('<script><script>nested</script></script>');
      expect(result).not.toContain('<script>');
    });
  });

  describe('Event Handler Removal', () => {
    it('should remove onerror handlers', () => {
      const result = sanitizeXss('<img onerror="alert(1)">');
      expect(result).not.toContain('onerror');
    });

    it('should remove onclick handlers', () => {
      const result = sanitizeXss('<div onclick="evil()">click me</div>');
      expect(result).not.toContain('onclick');
    });

    it('should remove onload handlers', () => {
      const result = sanitizeXss('<svg onload="alert(1)">');
      expect(result).not.toContain('onload');
    });

    it('should remove onmouseover handlers', () => {
      const result = sanitizeXss('<a onmouseover="evil()">hover</a>');
      expect(result).not.toContain('onmouseover');
    });

    it('should handle event handlers with single quotes', () => {
      const result = sanitizeXss("<img onerror='alert(1)'>");
      expect(result).not.toContain('onerror');
    });

    it('should handle event handlers without quotes', () => {
      const result = sanitizeXss('<img onerror=alert(1)>');
      expect(result).not.toContain('onerror');
    });
  });

  describe('Dangerous Protocol Removal', () => {
    it('should remove javascript: protocol', () => {
      const result = sanitizeXss('javascript:alert(1)');
      expect(result.toLowerCase()).not.toContain('javascript:');
    });

    it('should handle javascript: with mixed case', () => {
      const result = sanitizeXss('JaVaScRiPt:alert(1)');
      expect(result.toLowerCase()).not.toContain('javascript:');
    });

    it('should remove vbscript: protocol', () => {
      const result = sanitizeXss('vbscript:msgbox("xss")');
      expect(result.toLowerCase()).not.toContain('vbscript:');
    });

    it('should remove data: text/html URIs', () => {
      const result = sanitizeXss('data:text/html,<script>alert(1)</script>');
      expect(result).not.toContain('data:');
    });
  });

  describe('HTML Entity Encoding', () => {
    // HTML encoding is opt-in via the htmlEncode parameter (3rd arg).
    // Default is false — REST APIs should not encode entities into stored data.
    it('should encode < character when htmlEncode=true', () => {
      const result = sanitizeXss('<div>', false, true);
      expect(result).toContain('&lt;');
    });

    it('should encode > character when htmlEncode=true', () => {
      const result = sanitizeXss('>test<', false, true);
      expect(result).toContain('&gt;');
    });

    it('should encode " character when htmlEncode=true', () => {
      const result = sanitizeXss('"quoted"', false, true);
      expect(result).toContain('&quot;');
    });

    it("should encode ' character when htmlEncode=true", () => {
      const result = sanitizeXss("'single'", false, true);
      expect(result).toContain('&#x27;');
    });

    it('should encode & character when htmlEncode=true', () => {
      const result = sanitizeXss('a & b', false, true);
      expect(result).toContain('&amp;');
    });

    it('should NOT encode entities by default (REST API mode)', () => {
      const result = sanitizeXss('a & b');
      expect(result).toBe('a & b');
    });
  });

  describe('Threat Collection', () => {
    it('should collect threat info when requested', () => {
      const result = sanitizeXss('<script>alert(1)</script>', true);
      expect(result.wasSanitized).toBe(true);
      expect(result.threats.length).toBeGreaterThan(0);
      const threat = result.threats[0];
      expect(threat.type).toBe('xss');
      // Each threat must carry the matched text and the pattern that caught it
      expect(typeof threat.original).toBe('string');
      expect(threat.original.length).toBeGreaterThan(0);
      expect(typeof threat.pattern).toBe('string');
      expect(threat.pattern.length).toBeGreaterThan(0);
    });

    it('should capture the exact matched content in original', () => {
      const result = sanitizeXss('<script>evil()</script>', true);
      const scriptThreat = result.threats.find(t => t.original.includes('script'));
      expect(scriptThreat).toBeDefined();
      expect(scriptThreat!.original).toContain('script');
    });

    it('should return no threats for safe input', () => {
      const result = sanitizeXss('Hello World', true);
      expect(result.value).toBeDefined();
      expect(result.threats.length).toBe(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string', () => {
      const result = sanitizeXss('');
      expect(result).toBe('');
    });

    it('should handle non-string input', () => {
      const result = sanitizeXss(123 as unknown as string);
      expect(result).toBe('123');
    });

    it('should handle null-like values', () => {
      const result = sanitizeXss(null as unknown as string);
      expect(result).toBeDefined();
    });

    it('should preserve safe content', () => {
      const result = sanitizeXss('Hello World 123');
      expect(result).toContain('Hello');
      expect(result).toContain('World');
      expect(result).toContain('123');
    });
  });
});

describe('detectXss', () => {
  it('should detect script tags', () => {
    expect(detectXss('<script>alert(1)</script>')).toBe(true);
  });

  it('should detect event handlers', () => {
    expect(detectXss('<img onerror="alert(1)">')).toBe(true);
  });

  it('should detect javascript: protocol', () => {
    expect(detectXss('javascript:alert(1)')).toBe(true);
    expect(detectXss('JAVASCRIPT:alert(1)')).toBe(true);
    expect(detectXss('javascript :alert(1)')).toBe(true);
  });

  it('should not flag prose that merely contains "javascript:"', () => {
    // The colon must be followed by a non-space char. Common benign titles
    // and labels like "JavaScript: The Good Parts" are not XSS.
    expect(detectXss('JavaScript: Basics of JavaScript Language')).toBe(false);
    expect(detectXss('JavaScript: The Good Parts')).toBe(false);
  });

  it('should detect dangerous HTML tags', () => {
    // <div> is not XSS — only actually dangerous patterns like <script>, <iframe> etc.
    expect(detectXss('<script>alert(1)</script>')).toBe(true);
    expect(detectXss('<iframe src="evil.com">')).toBe(true);
    // Plain tags without dangerous attributes are not XSS
    expect(detectXss('<div>test</div>')).toBe(false);
  });

  it('should return false for safe input', () => {
    expect(detectXss('Hello World')).toBe(false);
  });

  it('should handle non-string input', () => {
    expect(detectXss(123 as unknown as string)).toBe(false);
  });
});
