/**
 * JSONP Callback Sanitizer Tests
 * Tests for src/sanitizers/jsonp.ts
 */

import { describe, it, expect } from 'vitest';
import { sanitizeJsonpCallback, detectJsonpInjection } from '../../src/sanitizers/jsonp';

describe('sanitizeJsonpCallback', () => {
  describe('Valid callbacks', () => {
    it('should accept simple function name', () => {
      expect(sanitizeJsonpCallback('callback')).toBe('callback');
    });

    it('should accept function with underscore', () => {
      expect(sanitizeJsonpCallback('my_callback')).toBe('my_callback');
    });

    it('should accept namespaced callback', () => {
      expect(sanitizeJsonpCallback('jQuery.ajax.callback')).toBe('jQuery.ajax.callback');
    });

    it('should accept callback starting with $', () => {
      expect(sanitizeJsonpCallback('$callback')).toBe('$callback');
    });

    it('should accept callback starting with _', () => {
      expect(sanitizeJsonpCallback('_cb')).toBe('_cb');
    });

    it('should accept callback with bracket notation', () => {
      expect(sanitizeJsonpCallback('obj[0]')).toBe('obj[0]');
    });

    it('should accept jQuery-style callback', () => {
      expect(sanitizeJsonpCallback('jQuery110209547534')).toBe('jQuery110209547534');
    });
  });

  describe('XSS injection attempts', () => {
    it('should reject alert(1)', () => {
      expect(sanitizeJsonpCallback('alert(1)')).toBeNull();
    });

    it('should reject callback with semicolon', () => {
      expect(sanitizeJsonpCallback('foo;alert(1)//')).toBeNull();
    });

    it('should reject callback with angle brackets', () => {
      expect(sanitizeJsonpCallback('<script>alert(1)</script>')).toBeNull();
    });

    it('should reject callback with parentheses', () => {
      expect(sanitizeJsonpCallback('eval(name)')).toBeNull();
    });

    it('should reject callback with curly braces', () => {
      expect(sanitizeJsonpCallback('{alert(1)}')).toBeNull();
    });

    it('should reject callback with equals', () => {
      expect(sanitizeJsonpCallback('x=1')).toBeNull();
    });

    it('should reject callback with backtick', () => {
      expect(sanitizeJsonpCallback('`alert`')).toBeNull();
    });

    it('should reject callback with single quotes', () => {
      expect(sanitizeJsonpCallback("foo'bar")).toBeNull();
    });

    it('should reject callback with double quotes', () => {
      expect(sanitizeJsonpCallback('foo"bar')).toBeNull();
    });

    it('should reject callback with slash', () => {
      expect(sanitizeJsonpCallback('foo/bar')).toBeNull();
    });

    it('should reject callback with newline', () => {
      expect(sanitizeJsonpCallback('foo\nbar')).toBeNull();
    });

    it('should reject callback with CRLF', () => {
      expect(sanitizeJsonpCallback('foo\r\nbar')).toBeNull();
    });

    it('should reject prototype chain traversal (..)', () => {
      expect(sanitizeJsonpCallback('obj..constructor')).toBeNull();
    });
  });

  describe('Edge cases', () => {
    it('should reject empty string', () => {
      expect(sanitizeJsonpCallback('')).toBeNull();
    });

    it('should reject non-string input', () => {
      expect(sanitizeJsonpCallback(123 as any)).toBeNull();
      expect(sanitizeJsonpCallback(null as any)).toBeNull();
    });

    it('should reject callback starting with number', () => {
      expect(sanitizeJsonpCallback('123callback')).toBeNull();
    });

    it('should reject callback exceeding max length', () => {
      expect(sanitizeJsonpCallback('a'.repeat(200))).toBeNull();
    });

    it('should accept callback at max length boundary', () => {
      expect(sanitizeJsonpCallback('a'.repeat(128))).toBe('a'.repeat(128));
    });

    it('should respect custom max length', () => {
      expect(sanitizeJsonpCallback('abcdef', 5)).toBeNull();
      expect(sanitizeJsonpCallback('abcde', 5)).toBe('abcde');
    });
  });
});

describe('detectJsonpInjection', () => {
  describe('Detects dangerous callbacks', () => {
    it('should detect alert(1)', () => {
      expect(detectJsonpInjection('alert(1)')).toBe(true);
    });

    it('should detect semicolon injection', () => {
      expect(detectJsonpInjection('foo;alert(1)//')).toBe(true);
    });

    it('should detect script tag', () => {
      expect(detectJsonpInjection('<script>alert(1)</script>')).toBe(true);
    });

    it('should detect prototype traversal', () => {
      expect(detectJsonpInjection('obj..constructor')).toBe(true);
    });
  });

  describe('Allows safe callbacks', () => {
    it('should not flag simple callback', () => {
      expect(detectJsonpInjection('callback')).toBe(false);
    });

    it('should not flag namespaced callback', () => {
      expect(detectJsonpInjection('jQuery.ajax.cb')).toBe(false);
    });
  });

  describe('Edge cases', () => {
    it('should return false for empty string', () => {
      expect(detectJsonpInjection('')).toBe(false);
    });

    it('should return false for non-string', () => {
      expect(detectJsonpInjection(123 as any)).toBe(false);
    });
  });
});
