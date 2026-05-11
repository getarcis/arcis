/**
 * Method allowlist tests (sdk-vectors.md tier 1 #26).
 * Covers the two threats: disallowed methods (TRACE/CONNECT) and
 * method-override header bypass.
 */

import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { methodAllowlist } from '../../src/middleware/method-allowlist';

interface FakeRes {
  res: Response;
  state: {
    status: number | null;
    body: unknown;
    headers: Record<string, string>;
    sent: boolean;
  };
}

function fakeReq(method: string, headers: Record<string, string> = {}): Request {
  return { method, headers: { ...headers } } as unknown as Request;
}

function fakeRes(): FakeRes {
  const state = {
    status: null as number | null,
    body: undefined as unknown,
    headers: {} as Record<string, string>,
    sent: false,
  };
  const res = {
    status(code: number) {
      state.status = code;
      return res;
    },
    json(body: unknown) {
      state.body = body;
      state.sent = true;
      return res;
    },
    setHeader(name: string, value: string) {
      state.headers[name] = value;
    },
  } as unknown as Response;
  return { res, state };
}

describe('methodAllowlist', () => {
  describe('Default allowlist', () => {
    it.each(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'])(
      'allows %s',
      (method) => {
        const middleware = methodAllowlist();
        const next = vi.fn() as NextFunction;
        const { res, state } = fakeRes();
        middleware(fakeReq(method), res, next);
        expect(next).toHaveBeenCalled();
        expect(state.sent).toBe(false);
      },
    );

    it('rejects TRACE (XST risk)', () => {
      const middleware = methodAllowlist();
      const next = vi.fn() as NextFunction;
      const { res, state } = fakeRes();
      middleware(fakeReq('TRACE'), res, next);
      expect(next).not.toHaveBeenCalled();
      expect(state.status).toBe(405);
      expect(state.headers['Allow']).toMatch(/GET/);
    });

    it('rejects CONNECT', () => {
      const middleware = methodAllowlist();
      const next = vi.fn() as NextFunction;
      const { res, state } = fakeRes();
      middleware(fakeReq('CONNECT'), res, next);
      expect(state.status).toBe(405);
      expect(next).not.toHaveBeenCalled();
    });

    it('rejects custom / unknown methods', () => {
      const middleware = methodAllowlist();
      const next = vi.fn() as NextFunction;
      const { res, state } = fakeRes();
      middleware(fakeReq('FROBNICATE'), res, next);
      expect(state.status).toBe(405);
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('Custom allowlist', () => {
    it('honors a narrowed allow list', () => {
      const middleware = methodAllowlist({ allow: ['GET', 'POST'] });
      const next = vi.fn() as NextFunction;

      const { res: r1, state: s1 } = fakeRes();
      middleware(fakeReq('GET'), r1, next);
      expect(next).toHaveBeenCalledTimes(1);

      const { res: r2, state: s2 } = fakeRes();
      middleware(fakeReq('DELETE'), r2, next);
      expect(s2.status).toBe(405);
    });

    it('uppercase-normalises configured methods', () => {
      const middleware = methodAllowlist({ allow: ['get', 'post'] });
      const next = vi.fn() as NextFunction;
      const { res } = fakeRes();
      middleware(fakeReq('GET'), res, next);
      expect(next).toHaveBeenCalled();
    });

    it('custom statusCode + message are respected', () => {
      const middleware = methodAllowlist({
        statusCode: 418,
        message: 'Not on this teapot',
      });
      const next = vi.fn() as NextFunction;
      const { res, state } = fakeRes();
      middleware(fakeReq('TRACE'), res, next);
      expect(state.status).toBe(418);
      expect(state.body).toMatchObject({ error: 'Not on this teapot' });
    });

    it('emits the Allow header per RFC 9110 §15.5.6', () => {
      const middleware = methodAllowlist({ allow: ['GET', 'POST'] });
      const next = vi.fn() as NextFunction;
      const { res, state } = fakeRes();
      middleware(fakeReq('DELETE'), res, next);
      expect(state.headers['Allow']).toBe('GET, POST');
    });
  });

  describe('Method-override header stripping', () => {
    it('strips X-HTTP-Method-Override before the route runs', () => {
      const middleware = methodAllowlist();
      const next = vi.fn() as NextFunction;
      const req = fakeReq('GET', { 'x-http-method-override': 'TRACE' });
      const { res } = fakeRes();
      middleware(req, res, next);
      expect(next).toHaveBeenCalled();
      // Header gone — downstream framework can't rewrite the method.
      expect(req.headers['x-http-method-override']).toBeUndefined();
    });

    it('strips all three override aliases', () => {
      const middleware = methodAllowlist();
      const next = vi.fn() as NextFunction;
      const req = fakeReq('GET', {
        'x-http-method-override': 'DELETE',
        'x-method-override': 'PUT',
        'x-http-method': 'PATCH',
      });
      const { res } = fakeRes();
      middleware(req, res, next);
      expect(req.headers['x-http-method-override']).toBeUndefined();
      expect(req.headers['x-method-override']).toBeUndefined();
      expect(req.headers['x-http-method']).toBeUndefined();
    });

    it('preserves the headers when stripOverrideHeaders: false', () => {
      // For stacks that legitimately use method tunneling AND have
      // verified their auth-per-override-target. Pin: opt-out works.
      const middleware = methodAllowlist({ stripOverrideHeaders: false });
      const next = vi.fn() as NextFunction;
      const req = fakeReq('GET', { 'x-http-method-override': 'PATCH' });
      const { res } = fakeRes();
      middleware(req, res, next);
      expect(req.headers['x-http-method-override']).toBe('PATCH');
    });

    it('strip happens BEFORE allowlist check so override-via-disallowed-wire-method is rejected', () => {
      // Wire method TRACE + override=GET. The strip removes the
      // override (good — the route would have run as GET otherwise),
      // then the allowlist sees TRACE and rejects. Pinning here so a
      // future refactor that swaps the order can't regress.
      const middleware = methodAllowlist();
      const next = vi.fn() as NextFunction;
      const req = fakeReq('TRACE', { 'x-http-method-override': 'GET' });
      const { res, state } = fakeRes();
      middleware(req, res, next);
      expect(state.status).toBe(405);
      expect(req.headers['x-http-method-override']).toBeUndefined();
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('Edge cases', () => {
    it('handles missing req.method gracefully (rejects)', () => {
      const middleware = methodAllowlist();
      const next = vi.fn() as NextFunction;
      const req = { headers: {} } as unknown as Request;
      const { res, state } = fakeRes();
      middleware(req, res, next);
      expect(state.status).toBe(405);
      expect(next).not.toHaveBeenCalled();
    });

    it('lowercase wire methods are normalised before matching', () => {
      // Spec: req.method comes uppercased from Express, but be defensive
      // against test mocks / proxies that pass lowercase.
      const middleware = methodAllowlist();
      const next = vi.fn() as NextFunction;
      const { res } = fakeRes();
      middleware(fakeReq('get'), res, next);
      expect(next).toHaveBeenCalled();
    });
  });
});
