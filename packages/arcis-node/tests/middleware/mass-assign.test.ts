/**
 * Mass-assignment guard tests (sdk-vectors.md tier 1 #25).
 */

import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { massAssign } from '../../src/middleware/mass-assign';

interface FakeRes {
  res: Response;
  state: {
    status: number | null;
    body: unknown;
    sent: boolean;
  };
}

function fakeReq(body: unknown): Request {
  return { body, method: 'POST', headers: {} } as unknown as Request;
}

function fakeRes(): FakeRes {
  const state = {
    status: null as number | null,
    body: undefined as unknown,
    sent: false,
  };
  const res = {
    status(code: number) {
      state.status = code;
      return res;
    },
    json(payload: unknown) {
      state.body = payload;
      state.sent = true;
      return res;
    },
  } as unknown as Response;
  return { res, state };
}

describe('massAssign — option validation', () => {
  it('throws when options.allow is missing', () => {
    expect(() =>
      massAssign({} as unknown as { allow: string[] }),
    ).toThrow(/allow must be a string array/);
  });

  it('throws when options.allow is empty (silent-strip footgun)', () => {
    expect(() => massAssign({ allow: [] })).toThrow(/at least one key/);
  });

  it('accepts a non-empty allow list', () => {
    expect(() => massAssign({ allow: ['email'] })).not.toThrow();
  });
});

describe('massAssign — strip mode (default)', () => {
  it('strips a disallowed top-level key (the classic is_admin payload)', () => {
    const middleware = massAssign({ allow: ['email', 'password'] });
    const req = fakeReq({
      email: 'alice@example.com',
      password: 'secret',
      is_admin: true, // attacker-injected
    });
    const next = vi.fn() as NextFunction;
    const { res } = fakeRes();
    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(req.body).toEqual({
      email: 'alice@example.com',
      password: 'secret',
    });
    expect((req.body as Record<string, unknown>).is_admin).toBeUndefined();
  });

  it('passes through clean bodies unchanged', () => {
    const middleware = massAssign({ allow: ['email', 'password'] });
    const original = { email: 'alice@example.com', password: 'secret' };
    const req = fakeReq(original);
    const next = vi.fn() as NextFunction;
    const { res } = fakeRes();
    middleware(req, res, next);
    expect(req.body).toEqual(original);
    expect(next).toHaveBeenCalled();
  });

  it('preserves the value type of allowed keys (number / boolean / null)', () => {
    const middleware = massAssign({ allow: ['count', 'active', 'tag'] });
    const req = fakeReq({
      count: 42,
      active: true,
      tag: null,
      role: 'admin', // dropped
    });
    const next = vi.fn() as NextFunction;
    const { res } = fakeRes();
    middleware(req, res, next);
    expect(req.body).toEqual({ count: 42, active: true, tag: null });
  });

  it('preserves nested objects untouched (top-level filter only by design)', () => {
    // Nested filtering is explicitly out-of-scope per the docstring;
    // pin the behavior so a future change is a deliberate decision.
    const middleware = massAssign({ allow: ['profile'] });
    const req = fakeReq({
      profile: {
        bio: 'hello',
        is_admin: true, // NOT stripped — nested object, not top-level
      },
      role: 'admin', // dropped at top level
    });
    const next = vi.fn() as NextFunction;
    const { res } = fakeRes();
    middleware(req, res, next);
    expect(req.body).toEqual({
      profile: { bio: 'hello', is_admin: true },
    });
  });

  it('handles missing body (no parser ran upstream)', () => {
    const middleware = massAssign({ allow: ['email'] });
    const req = fakeReq(undefined);
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(state.sent).toBe(false);
  });

  it('handles empty body ({})', () => {
    const middleware = massAssign({ allow: ['email'] });
    const req = fakeReq({});
    const next = vi.fn() as NextFunction;
    const { res } = fakeRes();
    middleware(req, res, next);
    expect(req.body).toEqual({});
    expect(next).toHaveBeenCalled();
  });
});

describe('massAssign — reject mode', () => {
  it('returns 400 with disallowed-key list', () => {
    const middleware = massAssign({
      allow: ['email', 'password'],
      mode: 'reject',
    });
    const req = fakeReq({
      email: 'alice@example.com',
      password: 'secret',
      is_admin: true,
      role: 'admin',
    });
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(state.status).toBe(400);
    expect(state.body).toMatchObject({
      error: 'Disallowed fields',
      fields: expect.arrayContaining(['is_admin', 'role']),
    });
  });

  it('passes through clean bodies (no rejection when allow-list satisfied)', () => {
    const middleware = massAssign({ allow: ['email'], mode: 'reject' });
    const req = fakeReq({ email: 'alice@example.com' });
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(state.sent).toBe(false);
  });

  it('honors custom statusCode + message', () => {
    const middleware = massAssign({
      allow: ['email'],
      mode: 'reject',
      statusCode: 422,
      message: 'Unknown fields rejected',
    });
    const req = fakeReq({ email: 'a@b', extra: 1 });
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(req, res, next);
    expect(state.status).toBe(422);
    expect(state.body).toMatchObject({
      error: 'Unknown fields rejected',
      fields: ['extra'],
    });
  });
});

describe('massAssign — non-object bodies', () => {
  it('passes string body through by default', () => {
    const middleware = massAssign({ allow: ['email'] });
    const req = fakeReq('plain text');
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(state.sent).toBe(false);
  });

  it('passes array body through by default (mass-assign vector targets keys, not arrays)', () => {
    const middleware = massAssign({ allow: ['email'] });
    const req = fakeReq([1, 2, 3]);
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(state.sent).toBe(false);
  });

  it('rejects non-objects when passThroughNonObjects: false', () => {
    const middleware = massAssign({
      allow: ['email'],
      passThroughNonObjects: false,
    });
    const req = fakeReq('plain text');
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(state.status).toBe(400);
    expect(state.body).toMatchObject({
      error: 'Request body must be a JSON object',
    });
  });

  it('rejects array body when passThroughNonObjects: false', () => {
    const middleware = massAssign({
      allow: ['email'],
      passThroughNonObjects: false,
    });
    const req = fakeReq([1, 2]);
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(req, res, next);
    expect(state.status).toBe(400);
  });
});

describe('massAssign — req.body assignment safety', () => {
  it('uses defineProperty so Express 5 frozen-getter req.body still gets replaced', () => {
    // Pin the assignment path. If a future refactor swaps to a plain
    // `req.body = filtered` assignment, this test fails on Node + Express
    // 5 where req.body is sometimes a getter.
    const middleware = massAssign({ allow: ['email'] });

    const original = { email: 'a@b', is_admin: true };
    // Construct a req with req.body as a getter (Express 5 / Connect 4
    // shape). The middleware must still reassign it.
    const req = {} as unknown as Request;
    let internal = original;
    Object.defineProperty(req, 'body', {
      get() {
        return internal;
      },
      set(v) {
        internal = v as typeof original;
      },
      configurable: true,
      enumerable: true,
    });

    const next = vi.fn() as NextFunction;
    const { res } = fakeRes();
    middleware(req, res, next);

    expect(req.body).toEqual({ email: 'a@b' });
    expect(next).toHaveBeenCalled();
  });
});
