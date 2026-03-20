/**
 * PII Detection and Redaction Tests
 * Tests for src/sanitizers/pii.ts
 */

import { describe, it, expect } from 'vitest';
import {
  scanPii,
  detectPii,
  redactPii,
  scanObjectPii,
  redactObjectPii,
} from '../../src/sanitizers/pii';

// ─── scanPii ─────────────────────────────────────────────────────────────────

describe('scanPii', () => {
  describe('email detection', () => {
    it('should detect standard email addresses', () => {
      const matches = scanPii('Contact john@example.com for info');
      expect(matches).toHaveLength(1);
      expect(matches[0]).toMatchObject({
        type: 'email',
        value: 'john@example.com',
      });
    });

    it('should detect multiple emails', () => {
      const matches = scanPii('From alice@test.com to bob@corp.org');
      expect(matches).toHaveLength(2);
      expect(matches[0].value).toBe('alice@test.com');
      expect(matches[1].value).toBe('bob@corp.org');
    });

    it('should detect emails with dots and plus signs', () => {
      const matches = scanPii('Email: first.last+tag@sub.domain.co.uk');
      expect(matches).toHaveLength(1);
      expect(matches[0].value).toBe('first.last+tag@sub.domain.co.uk');
    });

    it('should not match partial patterns', () => {
      const matches = scanPii('user@ or @domain.com', { types: ['email'] });
      expect(matches).toHaveLength(0);
    });
  });

  describe('phone number detection', () => {
    it('should detect US phone with dashes', () => {
      const matches = scanPii('Call 555-123-4567', { types: ['phone'] });
      expect(matches).toHaveLength(1);
      expect(matches[0].value).toBe('555-123-4567');
    });

    it('should detect phone with parentheses', () => {
      const matches = scanPii('Phone: (555) 123-4567', { types: ['phone'] });
      expect(matches).toHaveLength(1);
      expect(matches[0].value).toBe('(555) 123-4567');
    });

    it('should detect phone with dots', () => {
      const matches = scanPii('Call 555.123.4567', { types: ['phone'] });
      expect(matches).toHaveLength(1);
      expect(matches[0].value).toBe('555.123.4567');
    });

    it('should detect phone with country code', () => {
      const matches = scanPii('Call +1-555-123-4567', { types: ['phone'] });
      expect(matches).toHaveLength(1);
      expect(matches[0].value).toBe('+1-555-123-4567');
    });

    it('should not match numbers starting with 0 or 1 area code', () => {
      const matches = scanPii('ID: 012-345-6789', { types: ['phone'] });
      expect(matches).toHaveLength(0);
    });
  });

  describe('credit card detection', () => {
    it('should detect Visa card number', () => {
      const matches = scanPii('Card: 4111111111111111', { types: ['credit_card'] });
      expect(matches).toHaveLength(1);
      expect(matches[0].type).toBe('credit_card');
    });

    it('should detect card with spaces', () => {
      const matches = scanPii('Card: 4111 1111 1111 1111', { types: ['credit_card'] });
      expect(matches).toHaveLength(1);
    });

    it('should detect card with dashes', () => {
      const matches = scanPii('Card: 4111-1111-1111-1111', { types: ['credit_card'] });
      expect(matches).toHaveLength(1);
    });

    it('should reject invalid Luhn numbers', () => {
      const matches = scanPii('Not a card: 1234567890123456', { types: ['credit_card'] });
      expect(matches).toHaveLength(0);
    });

    it('should detect Mastercard', () => {
      const matches = scanPii('MC: 5500000000000004', { types: ['credit_card'] });
      expect(matches).toHaveLength(1);
    });

    it('should detect Amex', () => {
      const matches = scanPii('Amex: 378282246310005', { types: ['credit_card'] });
      expect(matches).toHaveLength(1);
    });
  });

  describe('SSN detection', () => {
    it('should detect SSN with dashes', () => {
      const matches = scanPii('SSN: 123-45-6789', { types: ['ssn'] });
      expect(matches).toHaveLength(1);
      expect(matches[0].value).toBe('123-45-6789');
    });

    it('should detect SSN with spaces', () => {
      const matches = scanPii('SSN: 123 45 6789', { types: ['ssn'] });
      expect(matches).toHaveLength(1);
    });

    it('should reject SSN starting with 000', () => {
      const matches = scanPii('Invalid: 000-12-3456', { types: ['ssn'] });
      expect(matches).toHaveLength(0);
    });

    it('should reject SSN starting with 666', () => {
      const matches = scanPii('Invalid: 666-12-3456', { types: ['ssn'] });
      expect(matches).toHaveLength(0);
    });

    it('should reject SSN starting with 900+', () => {
      const matches = scanPii('Invalid: 900-12-3456', { types: ['ssn'] });
      expect(matches).toHaveLength(0);
    });
  });

  describe('IP address detection', () => {
    it('should detect IPv4 addresses', () => {
      const matches = scanPii('Server at 192.168.1.100', { types: ['ip_address'] });
      expect(matches).toHaveLength(1);
      expect(matches[0].value).toBe('192.168.1.100');
    });

    it('should detect multiple IPs', () => {
      const matches = scanPii('From 10.0.0.1 to 172.16.0.1', { types: ['ip_address'] });
      expect(matches).toHaveLength(2);
    });

    it('should not match invalid octets', () => {
      const matches = scanPii('Not IP: 999.999.999.999', { types: ['ip_address'] });
      expect(matches).toHaveLength(0);
    });
  });

  describe('mixed content', () => {
    it('should detect multiple PII types', () => {
      const input = 'Email john@test.com, call 555-123-4567, SSN 123-45-6789';
      const matches = scanPii(input);
      const types = matches.map(m => m.type);
      expect(types).toContain('email');
      expect(types).toContain('phone');
      expect(types).toContain('ssn');
    });

    it('should return matches sorted by position', () => {
      const input = 'SSN: 123-45-6789, email: z@test.com';
      const matches = scanPii(input);
      for (let i = 1; i < matches.length; i++) {
        expect(matches[i].start).toBeGreaterThanOrEqual(matches[i - 1].start);
      }
    });
  });

  describe('filtering by type', () => {
    it('should only scan specified types', () => {
      const input = 'Email john@test.com, SSN 123-45-6789';
      const matches = scanPii(input, { types: ['email'] });
      expect(matches).toHaveLength(1);
      expect(matches[0].type).toBe('email');
    });
  });

  describe('edge cases', () => {
    it('should return empty for empty string', () => {
      expect(scanPii('')).toEqual([]);
    });

    it('should return empty for non-string', () => {
      expect(scanPii(null as unknown as string)).toEqual([]);
      expect(scanPii(undefined as unknown as string)).toEqual([]);
      expect(scanPii(123 as unknown as string)).toEqual([]);
    });

    it('should return empty for clean text', () => {
      expect(scanPii('Hello world, this is clean text.')).toEqual([]);
    });

    it('should include start and end positions', () => {
      const input = 'SSN: 123-45-6789';
      const matches = scanPii(input, { types: ['ssn'] });
      expect(matches[0].start).toBe(5);
      expect(matches[0].end).toBe(16);
      expect(input.substring(matches[0].start, matches[0].end)).toBe('123-45-6789');
    });
  });
});

// ─── detectPii ───────────────────────────────────────────────────────────────

describe('detectPii', () => {
  it('should return true when PII found', () => {
    expect(detectPii('john@example.com')).toBe(true);
  });

  it('should return false when no PII', () => {
    expect(detectPii('Hello world')).toBe(false);
  });

  it('should respect type filter', () => {
    expect(detectPii('john@example.com', { types: ['ssn'] })).toBe(false);
    expect(detectPii('john@example.com', { types: ['email'] })).toBe(true);
  });
});

// ─── redactPii ───────────────────────────────────────────────────────────────

describe('redactPii', () => {
  it('should redact email with default replacement', () => {
    expect(redactPii('Contact john@example.com')).toBe('Contact [REDACTED]');
  });

  it('should redact multiple PII instances', () => {
    const result = redactPii('Email: a@b.com, SSN: 123-45-6789');
    expect(result).toBe('Email: [REDACTED], SSN: [REDACTED]');
  });

  it('should use custom replacement', () => {
    expect(redactPii('Email: a@b.com', { replacement: '***' })).toBe('Email: ***');
  });

  it('should use type-specific labels', () => {
    const result = redactPii('Email: a@b.com, SSN: 123-45-6789', { typeLabels: true });
    expect(result).toBe('Email: [EMAIL], SSN: [SSN]');
  });

  it('should return original string if no PII', () => {
    expect(redactPii('Hello world')).toBe('Hello world');
  });

  it('should handle empty/null input', () => {
    expect(redactPii('')).toBe('');
    expect(redactPii(null as unknown as string)).toBe(null);
  });

  it('should only redact specified types', () => {
    const input = 'Email: a@b.com, SSN: 123-45-6789';
    const result = redactPii(input, { types: ['ssn'] });
    expect(result).toContain('a@b.com');
    expect(result).toContain('[REDACTED]');
    expect(result).not.toContain('123-45-6789');
  });
});

// ─── scanObjectPii ───────────────────────────────────────────────────────────

describe('scanObjectPii', () => {
  it('should scan flat object fields', () => {
    const results = scanObjectPii({ name: 'John', email: 'john@example.com' });
    expect(results).toHaveLength(1);
    expect(results[0].field).toBe('email');
    expect(results[0].type).toBe('email');
  });

  it('should scan nested objects', () => {
    const results = scanObjectPii({
      user: { contact: { email: 'john@example.com' } },
    });
    expect(results).toHaveLength(1);
    expect(results[0].field).toBe('user.contact.email');
  });

  it('should scan arrays', () => {
    const results = scanObjectPii({
      emails: ['a@b.com', 'c@d.com'],
    });
    expect(results).toHaveLength(2);
    expect(results[0].field).toBe('emails[0]');
    expect(results[1].field).toBe('emails[1]');
  });

  it('should scan objects inside arrays', () => {
    const results = scanObjectPii({
      users: [{ email: 'a@b.com' }, { email: 'c@d.com' }],
    });
    expect(results).toHaveLength(2);
    expect(results[0].field).toBe('users[0].email');
  });

  it('should return empty for no PII', () => {
    expect(scanObjectPii({ name: 'John', age: 30 })).toEqual([]);
  });

  it('should handle null/undefined', () => {
    expect(scanObjectPii(null as unknown as Record<string, unknown>)).toEqual([]);
  });
});

// ─── redactObjectPii ─────────────────────────────────────────────────────────

describe('redactObjectPii', () => {
  it('should redact PII in flat object', () => {
    const result = redactObjectPii({ name: 'John', email: 'john@example.com' });
    expect(result.name).toBe('John');
    expect(result.email).toBe('[REDACTED]');
  });

  it('should redact PII in nested objects', () => {
    const result = redactObjectPii({
      user: { contact: { email: 'john@example.com', name: 'John' } },
    });
    expect((result.user as Record<string, unknown>)).toMatchObject({
      contact: { email: '[REDACTED]', name: 'John' },
    });
  });

  it('should redact PII in arrays', () => {
    const result = redactObjectPii({
      emails: ['a@b.com', 'safe text', 'c@d.com'],
    });
    expect(result.emails).toEqual(['[REDACTED]', 'safe text', '[REDACTED]']);
  });

  it('should preserve non-string values', () => {
    const result = redactObjectPii({ count: 42, active: true, email: 'a@b.com' });
    expect(result.count).toBe(42);
    expect(result.active).toBe(true);
    expect(result.email).toBe('[REDACTED]');
  });

  it('should use type labels when configured', () => {
    const result = redactObjectPii(
      { email: 'a@b.com', ssn: '123-45-6789' },
      { typeLabels: true },
    );
    expect(result.email).toBe('[EMAIL]');
    expect(result.ssn).toBe('[SSN]');
  });
});
