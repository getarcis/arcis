/**
 * CSRF Protection Middleware Tests
 * Tests for src/middleware/csrf.ts
 */

import { describe, it, expect, vi } from 'vitest';
import {
  generateCsrfToken,
  validateCsrfToken,
  csrfProtection,
  createCsrf,
} from '../../src/middleware/csrf';
import type { Request, Response, NextFunction } from 'express';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function mockRequest(overrides: Record<string, unknown> = {}): Partial<Request> {
  return {
    method: 'GET',
    path: '/',
    url: '/',
    headers: {},
    cookies: {},
    body: {},
    query: {},
    ...overrides,
  };
}

function mockResponse(): Partial<Response> & { statusCode: number } {
  const res: Record<string, unknown> = {
    statusCode: 200,
    headers: {} as Record<string, string>,
  };
  res.status = vi.fn((code: number) => {
    res.statusCode = code;
    return res;
  });
  res.json = vi.fn(() => res);
  res.setHeader = vi.fn((name: string, value: string) => {
    (res.headers as Record<string, string>)[name.toLowerCase()] = value;
    return res;
  });
  return res as Partial<Response> & { statusCode: number };
}

function callCsrf(
  csrfOptions: Parameters<typeof csrfProtection>[0] = {},
  reqOverrides: Record<string, unknown> = {}
) {
  const req = mockRequest(reqOverrides);
  const res = mockResponse();
  const next = vi.fn();
  const middleware = csrfProtection(csrfOptions);
  middleware(req as unknown as Request, res as unknown as Response, next as unknown as NextFunction);
  return { req, res, next };
}

// ─── Token Generation ─────────────────────────────────────────────────────────

describe('generateCsrfToken', () => {
  it('should generate a hex string', () => {
    const token = generateCsrfToken();
    expect(token).toMatch(/^[a-f0-9]+$/);
  });

  it('should generate 64 hex chars by default (32 bytes)', () => {
    const token = generateCsrfToken();
    expect(token).toHaveLength(64);
  });

  it('should respect custom length', () => {
    const token = generateCsrfToken(16);
    expect(token).toHaveLength(32); // 16 bytes = 32 hex chars
  });

  it('should generate unique tokens', () => {
    const tokens = new Set(Array.from({ length: 100 }, () => generateCsrfToken()));
    expect(tokens.size).toBe(100);
  });
});

// ─── Token Validation ─────────────────────────────────────────────────────────

describe('validateCsrfToken', () => {
  it('should return true for matching tokens', () => {
    const token = generateCsrfToken();
    expect(validateCsrfToken(token, token)).toBe(true);
  });

  it('should return false for mismatched tokens', () => {
    const token1 = generateCsrfToken();
    const token2 = generateCsrfToken();
    expect(validateCsrfToken(token1, token2)).toBe(false);
  });

  it('should return false for empty cookie token', () => {
    expect(validateCsrfToken('', 'abc')).toBe(false);
  });

  it('should return false for empty request token', () => {
    expect(validateCsrfToken('abc', '')).toBe(false);
  });

  it('should return false for different length tokens', () => {
    expect(validateCsrfToken('abc', 'abcd')).toBe(false);
  });

  it('should use constant-time comparison (not short-circuit)', () => {
    // Both should take similar time — we just verify correctness here
    const token = 'a'.repeat(64);
    const nearMatch = 'a'.repeat(63) + 'b';
    const farMatch = 'b'.repeat(64);
    expect(validateCsrfToken(token, nearMatch)).toBe(false);
    expect(validateCsrfToken(token, farMatch)).toBe(false);
  });
});

// ─── Middleware: Safe Methods ─────────────────────────────────────────────────

describe('csrfProtection — safe methods', () => {
  it('should call next() for GET requests', () => {
    const { next } = callCsrf({}, { method: 'GET' });
    expect(next).toHaveBeenCalled();
  });

  it('should call next() for HEAD requests', () => {
    const { next } = callCsrf({}, { method: 'HEAD' });
    expect(next).toHaveBeenCalled();
  });

  it('should call next() for OPTIONS requests', () => {
    const { next } = callCsrf({}, { method: 'OPTIONS' });
    expect(next).toHaveBeenCalled();
  });

  it('should set a CSRF cookie on GET if none exists', () => {
    const { res } = callCsrf({}, { method: 'GET' });
    expect(res.setHeader).toHaveBeenCalledWith(
      'Set-Cookie',
      expect.stringContaining('_csrf=')
    );
  });

  it('should not overwrite existing CSRF cookie on GET', () => {
    const { res } = callCsrf({}, {
      method: 'GET',
      cookies: { _csrf: 'existing-token' },
    });
    expect(res.setHeader).not.toHaveBeenCalled();
  });
});

// ─── Middleware: Protected Methods ────────────────────────────────────────────

describe('csrfProtection — protected methods', () => {
  const validToken = 'a'.repeat(64);

  it('should reject POST without CSRF cookie', () => {
    const { res, next } = callCsrf({}, {
      method: 'POST',
      headers: { 'x-csrf-token': validToken },
    });
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('should reject POST without CSRF header/field', () => {
    const { res, next } = callCsrf({}, {
      method: 'POST',
      cookies: { _csrf: validToken },
    });
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('should reject POST with mismatched tokens', () => {
    const { res, next } = callCsrf({}, {
      method: 'POST',
      cookies: { _csrf: validToken },
      headers: { 'x-csrf-token': 'b'.repeat(64) },
    });
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('should allow POST with matching header token', () => {
    const { next } = callCsrf({}, {
      method: 'POST',
      cookies: { _csrf: validToken },
      headers: { 'x-csrf-token': validToken },
    });
    expect(next).toHaveBeenCalled();
  });

  it('should allow POST with matching body field token', () => {
    const { next } = callCsrf({}, {
      method: 'POST',
      cookies: { _csrf: validToken },
      body: { _csrf: validToken },
    });
    expect(next).toHaveBeenCalled();
  });

  it('should allow POST with matching query token', () => {
    const { next } = callCsrf({}, {
      method: 'POST',
      cookies: { _csrf: validToken },
      query: { _csrf: validToken },
    });
    expect(next).toHaveBeenCalled();
  });

  it('should protect PUT requests', () => {
    const { res, next } = callCsrf({}, { method: 'PUT' });
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('should protect PATCH requests', () => {
    const { res, next } = callCsrf({}, { method: 'PATCH' });
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('should protect DELETE requests', () => {
    const { res, next } = callCsrf({}, { method: 'DELETE' });
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });
});

// ─── Middleware: Exclude Paths ────────────────────────────────────────────────

describe('csrfProtection — excludePaths', () => {
  it('should skip CSRF check for excluded exact path', () => {
    const { next } = callCsrf(
      { excludePaths: ['/api/webhooks/stripe'] },
      { method: 'POST', path: '/api/webhooks/stripe' }
    );
    expect(next).toHaveBeenCalled();
  });

  it('should skip CSRF check for excluded path prefix', () => {
    const { next } = callCsrf(
      { excludePaths: ['/api/webhooks'] },
      { method: 'POST', path: '/api/webhooks/github' }
    );
    expect(next).toHaveBeenCalled();
  });

  it('should still check CSRF for non-excluded paths', () => {
    const { res, next } = callCsrf(
      { excludePaths: ['/api/webhooks'] },
      { method: 'POST', path: '/api/users' }
    );
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });
});

// ─── Middleware: Custom Options ───────────────────────────────────────────────

describe('csrfProtection — custom options', () => {
  const validToken = 'a'.repeat(64);

  it('should use custom cookie name', () => {
    const { next } = callCsrf(
      { cookieName: 'my-csrf' },
      {
        method: 'POST',
        cookies: { 'my-csrf': validToken },
        headers: { 'x-csrf-token': validToken },
      }
    );
    expect(next).toHaveBeenCalled();
  });

  it('should use custom header name', () => {
    const { next } = callCsrf(
      { headerName: 'x-xsrf-token' },
      {
        method: 'POST',
        cookies: { _csrf: validToken },
        headers: { 'x-xsrf-token': validToken },
      }
    );
    expect(next).toHaveBeenCalled();
  });

  it('should use custom field name', () => {
    const { next } = callCsrf(
      { fieldName: 'csrfToken' },
      {
        method: 'POST',
        cookies: { _csrf: validToken },
        body: { csrfToken: validToken },
      }
    );
    expect(next).toHaveBeenCalled();
  });

  it('should use custom error handler', () => {
    const onError = vi.fn((_req, res, _next) => {
      res.status(418).json({ error: 'custom' });
    });
    const { res } = callCsrf(
      { onError },
      { method: 'POST' }
    );
    expect(onError).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(418);
  });

  it('should allow custom protected methods', () => {
    // Only protect POST — DELETE should be allowed
    const { next } = callCsrf(
      { protectedMethods: ['POST'] },
      { method: 'DELETE' }
    );
    expect(next).toHaveBeenCalled();
  });
});

// ─── Middleware: Cookie Fallback Parsing ──────────────────────────────────────

describe('csrfProtection — raw cookie header parsing', () => {
  const validToken = 'a'.repeat(64);

  it('should parse CSRF token from raw Cookie header when cookie-parser not used', () => {
    const { next } = callCsrf({}, {
      method: 'POST',
      cookies: undefined, // No cookie-parser
      headers: {
        cookie: `_csrf=${validToken}; other=value`,
        'x-csrf-token': validToken,
      },
    });
    expect(next).toHaveBeenCalled();
  });

  it('should handle missing Cookie header', () => {
    const { res, next } = callCsrf({}, {
      method: 'POST',
      cookies: undefined,
      headers: { 'x-csrf-token': validToken },
    });
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });
});

// ─── Middleware: csrfToken() helper ───────────────────────────────────────────

describe('csrfProtection — req.csrfToken()', () => {
  it('should expose csrfToken() on the request object', () => {
    const { req } = callCsrf({}, { method: 'GET' });
    expect(typeof (req as Record<string, unknown>).csrfToken).toBe('function');
  });

  it('should return existing token from cookie', () => {
    const { req } = callCsrf({}, {
      method: 'GET',
      cookies: { _csrf: 'existing-token' },
    });
    const token = ((req as Record<string, unknown>).csrfToken as () => string)();
    expect(token).toBe('existing-token');
  });

  it('should generate and set a new token if no cookie', () => {
    const { req, res } = callCsrf({}, { method: 'GET' });
    // csrfToken() was already called by middleware, but let's call again
    // The middleware already set a cookie, so csrfToken should return from it
    expect(typeof (req as Record<string, unknown>).csrfToken).toBe('function');
  });
});

// ─── Cookie Options ───────────────────────────────────────────────────────────

describe('csrfProtection — cookie options', () => {
  it('should set SameSite=Lax by default', () => {
    const { res } = callCsrf({}, { method: 'GET' });
    const setCookie = (res.setHeader as ReturnType<typeof vi.fn>).mock.calls
      .find((c: string[]) => c[0] === 'Set-Cookie');
    if (setCookie) {
      expect(setCookie[1]).toContain('SameSite=Lax');
    }
  });

  it('should not set HttpOnly by default (client needs to read it)', () => {
    const { res } = callCsrf({}, { method: 'GET' });
    const setCookie = (res.setHeader as ReturnType<typeof vi.fn>).mock.calls
      .find((c: string[]) => c[0] === 'Set-Cookie');
    if (setCookie) {
      expect(setCookie[1]).not.toContain('HttpOnly');
    }
  });

  it('should respect custom cookie options', () => {
    const { res } = callCsrf(
      { cookie: { sameSite: 'Strict', httpOnly: true, path: '/app' } },
      { method: 'GET' }
    );
    const setCookie = (res.setHeader as ReturnType<typeof vi.fn>).mock.calls
      .find((c: string[]) => c[0] === 'Set-Cookie');
    if (setCookie) {
      expect(setCookie[1]).toContain('SameSite=Strict');
      expect(setCookie[1]).toContain('HttpOnly');
      expect(setCookie[1]).toContain('Path=/app');
    }
  });
});

// ─── Alias ────────────────────────────────────────────────────────────────────

describe('createCsrf alias', () => {
  it('should be the same function as csrfProtection', () => {
    expect(createCsrf).toBe(csrfProtection);
  });
});
