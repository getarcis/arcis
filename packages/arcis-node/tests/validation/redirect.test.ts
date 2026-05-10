/**
 * Open Redirect Prevention Tests
 * Tests for src/validation/redirect.ts
 */

import { describe, it, expect } from 'vitest';
import { validateRedirect, isRedirectSafe } from '../../src/validation/redirect';

describe('validateRedirect', () => {
  describe('Safe Relative Paths', () => {
    it('should allow simple relative path', () => {
      expect(validateRedirect('/dashboard').safe).toBe(true);
    });

    it('should allow relative path with query params', () => {
      expect(validateRedirect('/users?page=2&sort=name').safe).toBe(true);
    });

    it('should allow relative path with fragment', () => {
      expect(validateRedirect('/page#section').safe).toBe(true);
    });

    it('should allow relative path without leading slash', () => {
      expect(validateRedirect('settings/profile').safe).toBe(true);
    });

    it('should allow parent-relative path', () => {
      expect(validateRedirect('../settings').safe).toBe(true);
    });

    it('should allow root path', () => {
      expect(validateRedirect('/').safe).toBe(true);
    });
  });

  describe('Absolute URLs (no allowed hosts)', () => {
    it('should block absolute http URL', () => {
      const result = validateRedirect('http://evil.com/phishing');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('absolute URL not in allowed hosts');
    });

    it('should block absolute https URL', () => {
      const result = validateRedirect('https://evil.com/phishing');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('absolute URL not in allowed hosts');
    });
  });

  describe('Absolute URLs (with allowed hosts)', () => {
    it('should allow absolute URL to allowed host', () => {
      const result = validateRedirect('https://myapp.com/home', {
        allowedHosts: ['myapp.com'],
      });
      expect(result.safe).toBe(true);
    });

    it('should block absolute URL to non-allowed host', () => {
      const result = validateRedirect('https://evil.com/home', {
        allowedHosts: ['myapp.com'],
      });
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('host not allowed');
    });

    it('should be case-insensitive for allowed hosts', () => {
      const result = validateRedirect('https://MYAPP.COM/home', {
        allowedHosts: ['myapp.com'],
      });
      expect(result.safe).toBe(true);
    });

    it('should support multiple allowed hosts', () => {
      const opts = { allowedHosts: ['myapp.com', 'cdn.myapp.com', 'api.myapp.com'] };
      expect(validateRedirect('https://cdn.myapp.com/img.png', opts).safe).toBe(true);
      expect(validateRedirect('https://evil.com', opts).safe).toBe(false);
    });

    // Regression: a bare 'myapp.com' entry used to allow any port. An
    // attacker could redirect to myapp.com:9999/admin or an internal
    // service on a non-standard port and bypass the allowlist.
    it('should reject non-default port when allowedHosts has only the bare hostname', () => {
      const result = validateRedirect('https://myapp.com:9999/admin', {
        allowedHosts: ['myapp.com'],
      });
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('host not allowed');
    });

    it('should accept default ports against bare-hostname allowlist entry', () => {
      // Default ports omit parsed.port, so hostWithPort equals hostname.
      expect(
        validateRedirect('https://myapp.com:443/path', { allowedHosts: ['myapp.com'] }).safe,
      ).toBe(true);
      expect(
        validateRedirect('http://myapp.com:80/path', { allowedHosts: ['myapp.com'] }).safe,
      ).toBe(true);
    });

    it('should accept explicit non-default port when allowlist names it', () => {
      const result = validateRedirect('https://myapp.com:9999/admin', {
        allowedHosts: ['myapp.com:9999'],
      });
      expect(result.safe).toBe(true);
    });

    it('should reject port mismatch even when hostname is in allowlist', () => {
      const result = validateRedirect('https://myapp.com:8443/admin', {
        allowedHosts: ['myapp.com', 'myapp.com:9999'],
      });
      expect(result.safe).toBe(false);
    });
  });

  describe('Protocol-Relative URLs', () => {
    it('should block protocol-relative URL by default', () => {
      const result = validateRedirect('//evil.com/path');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('protocol-relative');
    });

    it('should allow protocol-relative URL to allowed host', () => {
      const result = validateRedirect('//myapp.com/path', {
        allowedHosts: ['myapp.com'],
      });
      expect(result.safe).toBe(true);
    });

    it('should block protocol-relative URL to non-allowed host even when enabled', () => {
      const result = validateRedirect('//evil.com/path', {
        allowProtocolRelative: true,
        allowedHosts: ['myapp.com'],
      });
      expect(result.safe).toBe(false);
    });

    it('should allow protocol-relative URL when enabled with no host restriction', () => {
      const result = validateRedirect('//cdn.example.com/path', {
        allowProtocolRelative: true,
      });
      expect(result.safe).toBe(true);
    });
  });

  describe('Dangerous Protocols', () => {
    it('should block javascript: protocol', () => {
      const result = validateRedirect('javascript:alert(1)');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('dangerous protocol');
      expect(result.reason).toContain('javascript:');
    });

    it('should block JavaScript: (case-insensitive)', () => {
      const result = validateRedirect('JavaScript:alert(1)');
      expect(result.safe).toBe(false);
    });

    it('should block data: protocol', () => {
      const result = validateRedirect('data:text/html,<script>alert(1)</script>');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('dangerous protocol');
    });

    it('should block vbscript: protocol', () => {
      const result = validateRedirect('vbscript:MsgBox("xss")');
      expect(result.safe).toBe(false);
    });

    it('should block blob: protocol', () => {
      const result = validateRedirect('blob:http://example.com/file');
      expect(result.safe).toBe(false);
    });
  });

  describe('Backslash Bypass', () => {
    it('should block backslash-prefixed URL', () => {
      const result = validateRedirect('\\evil.com');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('backslash');
    });

    it('should block double backslash', () => {
      const result = validateRedirect('\\\\evil.com');
      expect(result.safe).toBe(false);
    });
  });

  describe('Control Character Bypass', () => {
    it('should strip tabs and still detect javascript:', () => {
      const result = validateRedirect('java\tscript:alert(1)');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('dangerous protocol');
    });

    it('should strip newlines and still detect javascript:', () => {
      const result = validateRedirect('java\nscript:alert(1)');
      expect(result.safe).toBe(false);
    });

    it('should strip carriage returns and still detect javascript:', () => {
      const result = validateRedirect('java\rscript:alert(1)');
      expect(result.safe).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should reject empty string', () => {
      const result = validateRedirect('');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('empty');
    });

    it('should reject whitespace-only string', () => {
      const result = validateRedirect('   ');
      expect(result.safe).toBe(false);
    });

    it('should reject non-string input', () => {
      const result = validateRedirect(123 as unknown as string);
      expect(result.safe).toBe(false);
    });

    it('should reject null input', () => {
      const result = validateRedirect(null as unknown as string);
      expect(result.safe).toBe(false);
    });

    it('should handle URL-encoded paths as relative', () => {
      const result = validateRedirect('/path%20with%20spaces');
      expect(result.safe).toBe(true);
    });

    it('should block ftp: protocol by default', () => {
      const result = validateRedirect('ftp://files.example.com/data');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('disallowed protocol');
    });
  });
});

describe('isRedirectSafe', () => {
  it('should return true for relative paths', () => {
    expect(isRedirectSafe('/dashboard')).toBe(true);
  });

  it('should return false for absolute URLs without allowed hosts', () => {
    expect(isRedirectSafe('https://evil.com')).toBe(false);
  });

  it('should return false for javascript:', () => {
    expect(isRedirectSafe('javascript:alert(1)')).toBe(false);
  });

  it('should pass options through', () => {
    expect(
      isRedirectSafe('https://myapp.com/home', { allowedHosts: ['myapp.com'] })
    ).toBe(true);
  });
});
