/**
 * Tests for signupProtection / checkSignup — composite protection for signup endpoints.
 * Closes the Arcjet "signup form protection" gap from AUDIT_PLAN.md.
 */

import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { signupProtection, checkSignup } from '../../src/middleware/signup-protection';

function mockReq(overrides: Record<string, unknown> = {}): Request {
  const headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0',
    accept: 'text/html',
    'accept-language': 'en-US',
    'accept-encoding': 'gzip',
    ...((overrides.headers as Record<string, string>) || {}),
  };
  return {
    method: 'POST',
    path: '/signup',
    ip: '1.2.3.4',
    socket: { remoteAddress: '1.2.3.4' },
    body: {},
    query: {},
    cookies: {},
    ...overrides,
    headers,
  } as unknown as Request;
}

function mockRes(): { res: Response; status: ReturnType<typeof vi.fn>; json: ReturnType<typeof vi.fn>; setHeader: ReturnType<typeof vi.fn> } {
  const obj: any = {};
  const status = vi.fn().mockReturnValue(obj);
  const json = vi.fn().mockReturnValue(obj);
  const setHeader = vi.fn().mockReturnValue(obj);
  obj.status = status;
  obj.json = json;
  obj.setHeader = setHeader;
  return { res: obj as Response, status, json, setHeader };
}

describe('checkSignup (pure)', () => {
  it('allows a valid human signup', () => {
    const req = mockReq({ body: { email: 'alice@gmail.com' } });
    expect(checkSignup(req)).toEqual({ allowed: true, reason: 'ok' });
  });

  it('blocks missing email', () => {
    const req = mockReq({ body: {} });
    expect(checkSignup(req).reason).toBe('missing_email');
  });

  it('blocks invalid email syntax', () => {
    const req = mockReq({ body: { email: 'not-an-email' } });
    expect(checkSignup(req).reason).toBe('invalid_email');
  });

  it('blocks disposable email domains', () => {
    const req = mockReq({ body: { email: 'throwaway@mailinator.com' } });
    expect(checkSignup(req).reason).toBe('disposable_email');
  });

  it('blocks automated bots', () => {
    const req = mockReq({
      body: { email: 'alice@gmail.com' },
      headers: { 'user-agent': 'curl/8.0' },
    });
    const out = checkSignup(req);
    expect(out.allowed).toBe(false);
    expect(out.reason).toBe('bot');
  });

  it('respects allowedBotCategories', () => {
    const req = mockReq({
      body: { email: 'alice@gmail.com' },
      headers: { 'user-agent': 'Googlebot/2.1' },
    });
    expect(checkSignup(req, { allowedBotCategories: ['SEARCH_ENGINE'] }).allowed).toBe(true);
  });

  it('honors custom emailField', () => {
    const req = mockReq({ body: { contact: 'alice@gmail.com' } });
    expect(checkSignup(req, { emailField: 'contact' }).allowed).toBe(true);
  });

  it('allowedEmailDomains bypasses disposable check', () => {
    const req = mockReq({ body: { email: 'ci@mailinator.com' } });
    expect(
      checkSignup(req, { allowedEmailDomains: ['mailinator.com'] }).allowed
    ).toBe(true);
  });
});

describe('signupProtection (middleware)', () => {
  it('calls next() on valid signup', () => {
    const mw = signupProtection({ rateLimit: false });
    try {
      const next = vi.fn();
      const { res } = mockRes();
      mw(mockReq({ body: { email: 'alice@gmail.com' } }), res, next as NextFunction);
      expect(next).toHaveBeenCalledTimes(1);
    } finally {
      mw.close();
    }
  });

  it('responds 400 on invalid email', () => {
    const mw = signupProtection({ rateLimit: false });
    try {
      const next = vi.fn();
      const { res, status, json } = mockRes();
      mw(mockReq({ body: { email: 'bad' } }), res, next as NextFunction);
      expect(status).toHaveBeenCalledWith(400);
      expect(json).toHaveBeenCalledWith(
        expect.objectContaining({ reason: 'invalid_email' })
      );
      expect(next).not.toHaveBeenCalled();
    } finally {
      mw.close();
    }
  });

  it('responds 403 on bot', () => {
    const mw = signupProtection({ rateLimit: false });
    try {
      const next = vi.fn();
      const { res, status } = mockRes();
      mw(
        mockReq({
          body: { email: 'alice@gmail.com' },
          headers: { 'user-agent': 'curl/8.0' },
        }),
        res,
        next as NextFunction
      );
      expect(status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    } finally {
      mw.close();
    }
  });

  it('rate-limits bursts from one IP', async () => {
    const mw = signupProtection({ rateLimit: { max: 2, windowMs: 60_000 } });
    try {
      const req = () => mockReq({ body: { email: 'alice@gmail.com' } });
      const nextCalls: number[] = [];
      const statuses: number[] = [];
      for (let i = 0; i < 4; i++) {
        const next = vi.fn(() => nextCalls.push(i));
        const { res, status } = mockRes();
        await mw(req(), res, next as NextFunction);
        if (status.mock.calls.length) statuses.push(status.mock.calls[0][0]);
      }
      // First 2 pass, 3rd+ blocked by 429
      expect(nextCalls.length).toBe(2);
      expect(statuses).toContain(429);
    } finally {
      mw.close();
    }
  });

  it('onBlocked fires on rejection', () => {
    const onBlocked = vi.fn();
    const mw = signupProtection({ rateLimit: false, onBlocked });
    try {
      const { res } = mockRes();
      mw(mockReq({ body: { email: 'bad' } }), res, vi.fn() as NextFunction);
      expect(onBlocked).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ reason: 'invalid_email' })
      );
    } finally {
      mw.close();
    }
  });
});
