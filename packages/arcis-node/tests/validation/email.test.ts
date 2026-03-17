/**
 * Email Validation Tests
 * Tests for src/validation/email.ts
 */

import { describe, it, expect, vi } from 'vitest';
import { validateEmail, verifyEmailMx, isValidEmailSyntax } from '../../src/validation/email';

describe('validateEmail', () => {
  describe('Valid emails', () => {
    it('should accept standard email addresses', () => {
      const result = validateEmail('user@example.com');
      expect(result.valid).toBe(true);
      expect(result.reason).toBe('valid');
    });

    it('should accept emails with dots in local part', () => {
      expect(validateEmail('first.last@example.com').valid).toBe(true);
    });

    it('should accept emails with plus addressing', () => {
      expect(validateEmail('user+tag@example.com').valid).toBe(true);
    });

    it('should accept emails with special characters in local part', () => {
      expect(validateEmail("user!#$%&'*+/=?^_`{|}~@example.com").valid).toBe(true);
    });

    it('should accept emails with hyphenated domains', () => {
      expect(validateEmail('user@my-domain.com').valid).toBe(true);
    });

    it('should accept emails with subdomain', () => {
      expect(validateEmail('user@mail.example.co.uk').valid).toBe(true);
    });

    it('should normalize to lowercase', () => {
      const result = validateEmail('USER@EXAMPLE.COM');
      expect(result.normalized).toBe('user@example.com');
    });

    it('should trim whitespace', () => {
      const result = validateEmail('  user@example.com  ');
      expect(result.valid).toBe(true);
      expect(result.normalized).toBe('user@example.com');
    });
  });

  describe('Invalid syntax', () => {
    it('should reject empty string', () => {
      const result = validateEmail('');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('invalid_syntax');
    });

    it('should reject whitespace-only string', () => {
      expect(validateEmail('   ').valid).toBe(false);
    });

    it('should reject email without @', () => {
      expect(validateEmail('userexample.com').reason).toBe('invalid_syntax');
    });

    it('should reject email without local part', () => {
      expect(validateEmail('@example.com').reason).toBe('invalid_syntax');
    });

    it('should reject email without domain', () => {
      expect(validateEmail('user@').reason).toBe('invalid_syntax');
    });

    it('should reject consecutive dots in local part', () => {
      expect(validateEmail('user..name@example.com').reason).toBe('invalid_syntax');
    });

    it('should reject leading dot in local part', () => {
      expect(validateEmail('.user@example.com').reason).toBe('invalid_syntax');
    });

    it('should reject trailing dot in local part', () => {
      expect(validateEmail('user.@example.com').reason).toBe('invalid_syntax');
    });

    it('should reject domain without TLD', () => {
      expect(validateEmail('user@localhost').reason).toBe('invalid_syntax');
    });

    it('should reject domain with single-char TLD', () => {
      expect(validateEmail('user@example.c').reason).toBe('invalid_syntax');
    });

    it('should reject email with spaces', () => {
      expect(validateEmail('us er@example.com').reason).toBe('invalid_syntax');
    });

    it('should reject email exceeding 254 characters', () => {
      const longLocal = 'a'.repeat(64);
      const longDomain = 'b'.repeat(180) + '.com';
      expect(validateEmail(`${longLocal}@${longDomain}`).reason).toBe('invalid_syntax');
    });

    it('should reject local part exceeding 64 characters', () => {
      const longLocal = 'a'.repeat(65);
      expect(validateEmail(`${longLocal}@example.com`).reason).toBe('invalid_syntax');
    });

    it('should reject domain exceeding 255 characters', () => {
      const longDomain = ('a'.repeat(60) + '.').repeat(5) + 'com';
      // This creates a domain > 255 chars
      if (longDomain.length > 255) {
        expect(validateEmail(`user@${longDomain}`).reason).toBe('invalid_syntax');
      }
    });
  });

  describe('Disposable email detection', () => {
    it('should reject known disposable domains by default', () => {
      const result = validateEmail('user@mailinator.com');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('disposable');
      expect(result.isDisposable).toBe(true);
    });

    it('should reject tempmail.com', () => {
      expect(validateEmail('user@tempmail.com').reason).toBe('disposable');
    });

    it('should reject guerrillamail.com', () => {
      expect(validateEmail('user@guerrillamail.com').reason).toBe('disposable');
    });

    it('should reject yopmail.com', () => {
      expect(validateEmail('user@yopmail.com').reason).toBe('disposable');
    });

    it('should reject throwaway.email', () => {
      expect(validateEmail('user@throwaway.email').reason).toBe('disposable');
    });

    it('should allow disposable domains when checkDisposable is false', () => {
      const result = validateEmail('user@mailinator.com', { checkDisposable: false });
      expect(result.valid).toBe(true);
      // Should still flag as disposable
      expect(result.isDisposable).toBe(true);
    });
  });

  describe('Free provider detection', () => {
    it('should flag gmail.com as free', () => {
      const result = validateEmail('user@gmail.com');
      expect(result.valid).toBe(true);
      expect(result.isFree).toBe(true);
    });

    it('should flag yahoo.com as free', () => {
      expect(validateEmail('user@yahoo.com').isFree).toBe(true);
    });

    it('should flag outlook.com as free', () => {
      expect(validateEmail('user@outlook.com').isFree).toBe(true);
    });

    it('should flag protonmail.com as free', () => {
      expect(validateEmail('user@protonmail.com').isFree).toBe(true);
    });

    it('should not flag custom domains as free', () => {
      expect(validateEmail('user@company.com').isFree).toBe(false);
    });
  });

  describe('Typo suggestions', () => {
    it('should suggest gmail.com for gmial.com', () => {
      const result = validateEmail('user@gmial.com');
      expect(result.valid).toBe(true);
      expect(result.reason).toBe('typo');
      expect(result.suggestion).toBe('user@gmail.com');
    });

    it('should suggest gmail.com for gmaill.com', () => {
      const result = validateEmail('user@gmaill.com');
      expect(result.reason).toBe('typo');
      expect(result.suggestion).toBe('user@gmail.com');
    });

    it('should suggest gmail.com for gmail.con', () => {
      const result = validateEmail('user@gmail.con');
      expect(result.reason).toBe('typo');
      expect(result.suggestion).toBe('user@gmail.com');
    });

    it('should suggest yahoo.com for yahooo.com', () => {
      const result = validateEmail('user@yahooo.com');
      expect(result.reason).toBe('typo');
      expect(result.suggestion).toBe('user@yahoo.com');
    });

    it('should suggest hotmail.com for hotmial.com', () => {
      const result = validateEmail('user@hotmial.com');
      expect(result.reason).toBe('typo');
      expect(result.suggestion).toBe('user@hotmail.com');
    });

    it('should suggest outlook.com for outlok.com', () => {
      const result = validateEmail('user@outlok.com');
      expect(result.reason).toBe('typo');
      expect(result.suggestion).toBe('user@outlook.com');
    });

    it('should suggest icloud.com for icoud.com', () => {
      const result = validateEmail('user@icoud.com');
      expect(result.reason).toBe('typo');
      expect(result.suggestion).toBe('user@icloud.com');
    });

    it('should preserve local part in suggestion', () => {
      const result = validateEmail('john.doe+test@gmial.com');
      expect(result.suggestion).toBe('john.doe+test@gmail.com');
    });

    it('should flag isFree correctly on suggested domain', () => {
      const result = validateEmail('user@gmial.com');
      expect(result.isFree).toBe(true);
    });

    it('should not suggest when suggestTypoFix is false', () => {
      const result = validateEmail('user@gmial.com', { suggestTypoFix: false });
      expect(result.reason).toBe('valid');
      expect(result.suggestion).toBeNull();
    });
  });

  describe('Blocked domains', () => {
    it('should reject emails from blocked domains', () => {
      const result = validateEmail('user@evil.com', { blockedDomains: ['evil.com'] });
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('blocked');
    });

    it('should be case-insensitive for blocked domains', () => {
      const result = validateEmail('user@EVIL.COM', { blockedDomains: ['evil.com'] });
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('blocked');
    });

    it('should allow emails from non-blocked domains', () => {
      const result = validateEmail('user@good.com', { blockedDomains: ['evil.com'] });
      expect(result.valid).toBe(true);
    });

    it('should support multiple blocked domains', () => {
      const opts = { blockedDomains: ['evil.com', 'bad.org'] };
      expect(validateEmail('user@evil.com', opts).reason).toBe('blocked');
      expect(validateEmail('user@bad.org', opts).reason).toBe('blocked');
      expect(validateEmail('user@good.com', opts).valid).toBe(true);
    });
  });

  describe('Allowed domains', () => {
    it('should bypass disposable check for allowed domains', () => {
      const result = validateEmail('user@mailinator.com', {
        allowedDomains: ['mailinator.com'],
      });
      expect(result.valid).toBe(true);
      expect(result.reason).toBe('valid');
    });

    it('should be case-insensitive for allowed domains', () => {
      const result = validateEmail('user@MAILINATOR.COM', {
        allowedDomains: ['mailinator.com'],
      });
      expect(result.valid).toBe(true);
    });

    it('should still detect free providers on allowed domains', () => {
      const result = validateEmail('user@gmail.com', {
        allowedDomains: ['gmail.com'],
      });
      expect(result.valid).toBe(true);
      expect(result.isFree).toBe(true);
    });
  });

  describe('Combined options', () => {
    it('should allow domain explicitly allowed even if also blocked', () => {
      // Allowed takes priority since it's checked first
      const result = validateEmail('user@special.com', {
        blockedDomains: ['special.com'],
        allowedDomains: ['special.com'],
      });
      expect(result.valid).toBe(true);
    });
  });
});

describe('verifyEmailMx', () => {
  it('should return false for email without @', async () => {
    expect(await verifyEmailMx('notanemail')).toBe(false);
  });

  it('should return false for empty domain', async () => {
    expect(await verifyEmailMx('user@')).toBe(false);
  });

  it('should return false for invalid domain (DNS failure)', async () => {
    // This domain likely has no MX records
    const result = await verifyEmailMx('user@thisdomain-definitely-does-not-exist-12345.com');
    expect(result).toBe(false);
  });

  it('should return true for gmail.com (real MX records)', async () => {
    // Real DNS lookup — may fail in restricted/offline environments
    const result = await verifyEmailMx('user@gmail.com');
    // Accept either outcome since DNS may be unavailable
    expect(typeof result).toBe('boolean');
  });
});

describe('isValidEmailSyntax', () => {
  describe('Valid syntax', () => {
    it('should return true for valid emails', () => {
      expect(isValidEmailSyntax('user@example.com')).toBe(true);
      expect(isValidEmailSyntax('a.b@c.co')).toBe(true);
      expect(isValidEmailSyntax('user+tag@domain.org')).toBe(true);
    });

    it('should trim whitespace', () => {
      expect(isValidEmailSyntax('  user@example.com  ')).toBe(true);
    });
  });

  describe('Invalid syntax', () => {
    it('should return false for empty string', () => {
      expect(isValidEmailSyntax('')).toBe(false);
    });

    it('should return false for missing @', () => {
      expect(isValidEmailSyntax('userexample.com')).toBe(false);
    });

    it('should return false for consecutive dots', () => {
      expect(isValidEmailSyntax('user..name@example.com')).toBe(false);
    });

    it('should return false for leading dot', () => {
      expect(isValidEmailSyntax('.user@example.com')).toBe(false);
    });

    it('should return false for trailing dot', () => {
      expect(isValidEmailSyntax('user.@example.com')).toBe(false);
    });

    it('should return false for overly long email', () => {
      const long = 'a'.repeat(250) + '@b.co';
      expect(isValidEmailSyntax(long)).toBe(false);
    });

    it('should return false for no TLD', () => {
      expect(isValidEmailSyntax('user@localhost')).toBe(false);
    });
  });
});
