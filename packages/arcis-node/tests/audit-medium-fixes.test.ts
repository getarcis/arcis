/**
 * Regression tests for AUDIT_PLAN medium findings (M1-M10).
 * Each describe block maps 1:1 to an audit finding so future regressions
 * surface at the right severity level.
 */

import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { sanitizeSsti } from '../src/sanitizers/ssti';
import { sanitizeString as sanitizeXss } from '../src/sanitizers/sanitize';
import { sanitizeJsonpCallback, detectJsonpInjection } from '../src/sanitizers/jsonp';
import { hpp } from '../src/middleware/hpp';
import { detectBot } from '../src/middleware/bot-detection';
import { createRateLimiter } from '../src/middleware/rate-limit';

function mockReq(overrides: Record<string, unknown> = {}): Request {
  return {
    method: 'GET',
    path: '/',
    headers: {},
    cookies: {},
    body: {},
    query: {},
    ...overrides,
  } as unknown as Request;
}

function mockRes(): Partial<Response> {
  const res: any = {};
  res.setHeader = vi.fn().mockReturnValue(res);
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res;
}

describe('M1 — SSTI operator-free dunder patterns', () => {
  it('strips ${self.__dict__}', () => {
    expect(sanitizeSsti('hello ${self.__dict__} world')).not.toContain('__dict__');
  });

  it('strips #{obj.__class__} in Pug context', () => {
    expect(sanitizeSsti('#{obj.__class__}')).not.toContain('__class__');
  });

  it('still leaves bare ${name} intact', () => {
    expect(sanitizeSsti('Hello ${name}')).toBe('Hello ${name}');
  });
});

describe('M2 — XSS <style> tag removal', () => {
  it('strips <style> blocks with expression() attack', () => {
    const out = sanitizeXss('<style>body { x: expression(alert(1)) }</style>');
    expect(out.toLowerCase()).not.toContain('<style');
    expect(out).not.toContain('expression');
  });

  it('strips unclosed <style attr>', () => {
    expect(sanitizeXss('<style type="text/css">').toLowerCase()).not.toContain('<style');
  });
});

describe('M3 — JSONP brackets rejected', () => {
  it('rejects callback with unbalanced bracket `cb[x`', () => {
    expect(sanitizeJsonpCallback('cb[x')).toBeNull();
  });

  it('rejects callback with any brackets', () => {
    expect(sanitizeJsonpCallback('cb[0]')).toBeNull();
    expect(sanitizeJsonpCallback('arr[1].fn')).toBeNull();
  });

  it('detectJsonpInjection flags bracketed callbacks', () => {
    expect(detectJsonpInjection('cb[x')).toBe(true);
  });

  it('still accepts simple identifiers and dotted names', () => {
    expect(sanitizeJsonpCallback('myCallback')).toBe('myCallback');
    expect(sanitizeJsonpCallback('ns.cb')).toBe('ns.cb');
  });
});

describe('M4 — HPP whitelist case-insensitive', () => {
  it('whitelisted `tags` matches incoming `TAGS` (preserved as array)', () => {
    const req = mockReq({ query: { TAGS: ['a', 'b'] } });
    const next = vi.fn();
    hpp({ whitelist: ['tags'] })(req, mockRes() as Response, next as unknown as NextFunction);
    expect(Array.isArray((req.query as any).TAGS)).toBe(true);
    expect((req.query as any).TAGS).toEqual(['a', 'b']);
  });

  it('non-whitelisted params still collapse to last value', () => {
    const req = mockReq({ query: { role: ['user', 'admin'] } });
    const next = vi.fn();
    hpp({ whitelist: ['tags'] })(req, mockRes() as Response, next as unknown as NextFunction);
    expect((req.query as any).role).toBe('admin');
  });
});

describe('M5 — Bot detection flags overlong UA', () => {
  it('flags UA > 2048 chars as bot without silent truncation', () => {
    const longUa = 'Mozilla/5.0 ' + 'x'.repeat(2500);
    const req = { headers: { 'user-agent': longUa } } as any;
    const result = detectBot(req);
    expect(result.isBot).toBe(true);
    expect(result.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('accepts normal UA', () => {
    const req = {
      headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0',
        'accept': 'text/html',
        'accept-language': 'en-US',
        'accept-encoding': 'gzip',
      },
    } as any;
    expect(detectBot(req).isBot).toBe(false);
  });
});

describe('M8: Rate limit unknown IP shares one unknown key (spec: Client IP resolution)', () => {
  it('unknown-IP requests share one bucket whatever their UA, and never mix with real IPs', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const limiter = createRateLimiter({ max: 1, windowMs: 60_000 });
    try {
      // A client-chosen User-Agent must not mint a fresh bucket.
      const reqA = {
        ip: undefined,
        socket: {},
        headers: { 'user-agent': 'ClientA/1.0', 'accept-language': 'en' },
      } as unknown as Request;
      const reqB = {
        ip: undefined,
        socket: {},
        headers: { 'user-agent': 'ClientB/1.0', 'accept-language': 'en' },
      } as unknown as Request;
      const reqReal = { socket: { remoteAddress: '203.0.113.9' }, headers: {} } as unknown as Request;

      const nextA = vi.fn();
      const nextB = vi.fn();
      const nextReal = vi.fn();
      const resB = mockRes();
      await limiter(reqA, mockRes() as Response, nextA as unknown as NextFunction);
      await limiter(reqB, resB as Response, nextB as unknown as NextFunction);
      await limiter(reqReal, mockRes() as Response, nextReal as unknown as NextFunction);

      expect(nextA).toHaveBeenCalled();
      expect(nextB).not.toHaveBeenCalled();
      expect(resB.status).toHaveBeenCalledWith(429);
      expect(nextReal).toHaveBeenCalled();
    } finally {
      limiter.close();
      vi.restoreAllMocks();
    }
  });
});
