/**
 * Regression tests for LOW-severity audit fixes (L1-L5).
 *
 * L1: XXE billion-laughs defense (size + entity-count cap)
 * L2: PII phone regex narrowed with digit boundaries
 * L3: Cookie config validation (throws on SameSite=None + secure=false)
 * L5: CSRF rotateOnUse option
 */

import { describe, expect, it, vi } from 'vitest';
import type { Request, Response } from 'express';
import { sanitizeXxe } from '../src/sanitizers/xxe';
import { scanPii } from '../src/sanitizers/pii';
import { secureCookieDefaults } from '../src/middleware/cookies';
import { csrfProtection, generateCsrfToken } from '../src/middleware/csrf';

describe('L1: XXE billion-laughs defense', () => {
  it('flattens oversize input (>1MB) to empty string', () => {
    const huge = 'a'.repeat(1_000_001);
    expect(sanitizeXxe(huge)).toBe('');
  });

  it('flattens payload with >64 entity references', () => {
    const bomb = '<root>' + '&lol;'.repeat(65) + '</root>';
    expect(sanitizeXxe(bomb)).toBe('');
  });

  it('records oversize threat when collecting', () => {
    const huge = 'a'.repeat(1_000_001);
    const result = sanitizeXxe(huge, true);
    expect(result.value).toBe('');
    expect(result.wasSanitized).toBe(true);
    expect(result.threats.some(t => t.pattern === 'oversize_input')).toBe(true);
  });

  it('records entity_expansion threat when collecting', () => {
    const bomb = '&a;'.repeat(100);
    const result = sanitizeXxe(bomb, true);
    expect(result.threats.some(t => t.pattern === 'entity_expansion')).toBe(true);
  });

  it('leaves small benign payloads alone', () => {
    expect(sanitizeXxe('<root><item>ok</item></root>')).toBe('<root><item>ok</item></root>');
  });
});

describe('L2: PII phone regex boundaries', () => {
  it('does not match phone-like substring inside longer digit run', () => {
    // Prior regex matched '555-123-4567' inside ZIP+phone concatenations
    // that had surrounding digits. Should NOT match now.
    const matches = scanPii('id=94102555123456789', { types: ['phone'] });
    expect(matches).toHaveLength(0);
  });

  it('still matches standard US phone formats', () => {
    const matches = scanPii('Call 555-123-4567 today', { types: ['phone'] });
    expect(matches).toHaveLength(1);
    expect(matches[0].value).toBe('555-123-4567');
  });

  it('matches +1 prefix format', () => {
    const matches = scanPii('+1 555-123-4567', { types: ['phone'] });
    expect(matches).toHaveLength(1);
  });
});

describe('L3: Cookie config validation', () => {
  it('throws when SameSite=None combined with secure=false', () => {
    expect(() =>
      secureCookieDefaults({ sameSite: 'None', secure: false })
    ).toThrow(/sameSite=None requires secure=true/);
  });

  it('accepts SameSite=None when secure=true', () => {
    expect(() =>
      secureCookieDefaults({ sameSite: 'None', secure: true })
    ).not.toThrow();
  });

  it('accepts default Lax config', () => {
    expect(() => secureCookieDefaults()).not.toThrow();
  });
});

describe('L5: CSRF rotateOnUse', () => {
  function mockReq(overrides: Partial<Request> = {}): Request {
    return {
      method: 'POST',
      path: '/api/submit',
      url: '/api/submit',
      headers: {},
      body: {},
      cookies: {},
      ...overrides,
    } as unknown as Request;
  }

  function mockRes(): Response & { _headers: Record<string, unknown> } {
    const headers: Record<string, unknown> = {};
    const res = {
      _headers: headers,
      setHeader: vi.fn((name: string, value: unknown) => {
        headers[name] = value;
      }),
      getHeader: vi.fn((name: string) => headers[name]),
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    return res as unknown as Response & { _headers: Record<string, unknown> };
  }

  it('issues a fresh Set-Cookie on successful validation when rotateOnUse=true', () => {
    const token = generateCsrfToken(16);
    const mw = csrfProtection({ tokenLength: 16, rotateOnUse: true });

    const req = mockReq({
      cookies: { _csrf: token },
      headers: { 'x-csrf-token': token },
    });
    const res = mockRes();
    const next = vi.fn();

    mw(req, res, next);

    expect(next).toHaveBeenCalled();
    const setCookie = res._headers['Set-Cookie'];
    expect(setCookie).toBeDefined();
    const cookieStr = Array.isArray(setCookie) ? setCookie[0] : String(setCookie);
    // New cookie must contain _csrf= with a token distinct from the submitted one
    expect(cookieStr).toMatch(/_csrf=/);
    const newToken = cookieStr.match(/_csrf=([^;]+)/)?.[1];
    expect(newToken).toBeDefined();
    expect(newToken).not.toBe(token);
  });

  it('does not rotate when rotateOnUse is absent (default)', () => {
    const token = generateCsrfToken(16);
    const mw = csrfProtection({ tokenLength: 16 });

    const req = mockReq({
      cookies: { _csrf: token },
      headers: { 'x-csrf-token': token },
    });
    const res = mockRes();
    const next = vi.fn();

    mw(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res._headers['Set-Cookie']).toBeUndefined();
  });
});
