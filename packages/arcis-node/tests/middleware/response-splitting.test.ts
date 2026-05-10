/**
 * Response splitting tests (sdk-vectors.md tier 1 #27).
 *
 * Covers the *output* boundary: even when app code forgets to sanitise,
 * the wrapped res.setHeader / res.writeHead / res.appendHeader strip
 * (or reject) embedded CR / LF / NUL.
 */

import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import {
  responseSplittingGuard,
  detectResponseSplitting,
  sanitizeResponseHeader,
  ResponseSplittingError,
} from '../../src/middleware/response-splitting';

interface FakeResState {
  headers: Record<string, string | string[]>;
  status: number | null;
  statusMessage: string | undefined;
  writeHeadCalledWith: unknown[];
}

function makeRes() {
  const state: FakeResState = {
    headers: {},
    status: null,
    statusMessage: undefined,
    writeHeadCalledWith: [],
  };
  const res = {
    setHeader(name: string, value: string | number | readonly string[]) {
      // Record raw what made it past the guard.
      state.headers[name] =
        typeof value === 'number'
          ? String(value)
          : Array.isArray(value)
            ? [...value]
            : (value as string);
      return res;
    },
    writeHead(statusCode: number, ...rest: unknown[]) {
      state.status = statusCode;
      if (typeof rest[0] === 'string') {
        state.statusMessage = rest[0];
        state.writeHeadCalledWith = [statusCode, rest[0], rest[1]];
      } else {
        state.writeHeadCalledWith = [statusCode, rest[0]];
      }
      return res;
    },
    appendHeader(name: string, value: string | string[]) {
      const existing = state.headers[name];
      const incoming = Array.isArray(value) ? value : [value];
      if (Array.isArray(existing)) {
        state.headers[name] = [...existing, ...incoming];
      } else if (existing) {
        state.headers[name] = [existing as string, ...incoming];
      } else {
        state.headers[name] = incoming.length === 1 ? incoming[0]! : incoming;
      }
      return res;
    },
  } as unknown as Response;
  return { res, state };
}

function fakeReq(): Request {
  return {} as Request;
}

describe('responseSplittingGuard', () => {
  describe('strip mode (default)', () => {
    it('strips CRLF from setHeader values', () => {
      const middleware = responseSplittingGuard();
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      expect(next).toHaveBeenCalled();

      res.setHeader('Location', '/safe\r\nX-Injected: evil');
      expect(state.headers['Location']).toBe('/safeX-Injected: evil');
    });

    it('strips bare CR and bare LF', () => {
      const middleware = responseSplittingGuard();
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      res.setHeader('X-Foo', 'a\rb\nc');
      expect(state.headers['X-Foo']).toBe('abc');
    });

    it('strips null bytes', () => {
      const middleware = responseSplittingGuard();
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      res.setHeader('X-Foo', 'a\0b');
      expect(state.headers['X-Foo']).toBe('ab');
    });

    it('strips CRLF from header NAMES (always, even in strip mode)', () => {
      const middleware = responseSplittingGuard();
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      res.setHeader('X-Bad\r\nEvil', 'v');
      expect(state.headers['X-BadEvil']).toBe('v');
      expect(state.headers['X-Bad\r\nEvil']).toBeUndefined();
    });

    it('passes clean values through unchanged', () => {
      const middleware = responseSplittingGuard();
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      res.setHeader('Content-Type', 'application/json');
      expect(state.headers['Content-Type']).toBe('application/json');
    });

    it('coerces numeric values without altering them', () => {
      const middleware = responseSplittingGuard();
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      res.setHeader('Content-Length', 42);
      // After coercion through the guard the value reaches setHeader
      // as the string "42"; the inner setHeader records that.
      expect(state.headers['Content-Length']).toBe('42');
    });

    it('cleans every entry of an array value (Set-Cookie)', () => {
      const middleware = responseSplittingGuard();
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      res.setHeader('Set-Cookie', ['a=1\r\nfoo', 'b=2']);
      expect(state.headers['Set-Cookie']).toEqual(['a=1foo', 'b=2']);
    });
  });

  describe('reject mode', () => {
    it('throws ResponseSplittingError when CRLF is detected on setHeader', () => {
      const middleware = responseSplittingGuard({ mode: 'reject' });
      const next = vi.fn() as NextFunction;
      const { res } = makeRes();
      middleware(fakeReq(), res, next);
      expect(() => res.setHeader('Location', '/x\r\nY: z')).toThrow(
        ResponseSplittingError,
      );
    });

    it('error carries header name and original value', () => {
      const middleware = responseSplittingGuard({ mode: 'reject' });
      const next = vi.fn() as NextFunction;
      const { res } = makeRes();
      middleware(fakeReq(), res, next);
      try {
        res.setHeader('X-Foo', 'a\nb');
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(ResponseSplittingError);
        expect((err as ResponseSplittingError).header).toBe('X-Foo');
        expect((err as ResponseSplittingError).value).toBe('a\nb');
      }
    });

    it('clean values still pass in reject mode', () => {
      const middleware = responseSplittingGuard({ mode: 'reject' });
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      res.setHeader('X-OK', 'fine');
      expect(state.headers['X-OK']).toBe('fine');
    });
  });

  describe('onDetect callback', () => {
    it('fires on each detected value before strip', () => {
      const onDetect = vi.fn();
      const middleware = responseSplittingGuard({ onDetect });
      const next = vi.fn() as NextFunction;
      const { res } = makeRes();
      middleware(fakeReq(), res, next);
      res.setHeader('X-Multi', ['ok', 'bad\r\nv', 'also bad\nv']);
      expect(onDetect).toHaveBeenCalledTimes(2);
      expect(onDetect).toHaveBeenCalledWith('X-Multi', 'bad\r\nv');
      expect(onDetect).toHaveBeenCalledWith('X-Multi', 'also bad\nv');
    });

    it('fires before reject throw', () => {
      const onDetect = vi.fn();
      const middleware = responseSplittingGuard({ mode: 'reject', onDetect });
      const next = vi.fn() as NextFunction;
      const { res } = makeRes();
      middleware(fakeReq(), res, next);
      try {
        res.setHeader('X-Foo', 'a\r\nb');
      } catch {
        // expected
      }
      expect(onDetect).toHaveBeenCalledWith('X-Foo', 'a\r\nb');
    });
  });

  describe('writeHead wrapper', () => {
    it('strips CRLF from object-form headers', () => {
      const middleware = responseSplittingGuard();
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      res.writeHead(302, { Location: '/x\r\nY: z' });
      expect(state.status).toBe(302);
      const headers = state.writeHeadCalledWith[1] as Record<string, unknown>;
      expect(headers['Location']).toBe('/xY: z');
    });

    it('preserves status message when provided', () => {
      const middleware = responseSplittingGuard();
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      res.writeHead(302, 'Found', { Location: '/safe' });
      expect(state.status).toBe(302);
      expect(state.statusMessage).toBe('Found');
    });

    it('handles flat-array header form', () => {
      const middleware = responseSplittingGuard();
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      res.writeHead(200, ['X-Foo', 'bad\r\nv', 'X-Bar', 'ok']);
      const headers = state.writeHeadCalledWith[1] as unknown[];
      expect(headers).toEqual(['X-Foo', 'badv', 'X-Bar', 'ok']);
    });

    it('handles nested-pair-array header form', () => {
      const middleware = responseSplittingGuard();
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      res.writeHead(200, [
        ['X-Foo', 'bad\r\nv'],
        ['X-Bar', 'ok'],
      ]);
      const headers = state.writeHeadCalledWith[1] as unknown[][];
      expect(headers).toEqual([
        ['X-Foo', 'badv'],
        ['X-Bar', 'ok'],
      ]);
    });

    it('passes through when no headers given', () => {
      const middleware = responseSplittingGuard();
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      res.writeHead(204);
      expect(state.status).toBe(204);
    });
  });

  describe('appendHeader wrapper', () => {
    it('sanitises values appended after the initial setHeader', () => {
      const middleware = responseSplittingGuard();
      const next = vi.fn() as NextFunction;
      const { res, state } = makeRes();
      middleware(fakeReq(), res, next);
      const r = res as Response & { appendHeader: (n: string, v: string) => Response };
      r.appendHeader('Set-Cookie', 'session=ok\r\nfoo');
      expect(state.headers['Set-Cookie']).toBe('session=okfoo');
    });
  });

  describe('Wrapping isolation', () => {
    it('wraps per request (later mounts with different options do not affect earlier ones)', () => {
      const m1 = responseSplittingGuard({ mode: 'strip' });
      const m2 = responseSplittingGuard({ mode: 'reject' });
      const next = vi.fn() as NextFunction;

      const { res: r1, state: s1 } = makeRes();
      m1(fakeReq(), r1, next);
      r1.setHeader('Location', '/x\r\ny');
      expect(s1.headers['Location']).toBe('/xy'); // m1 strips

      const { res: r2 } = makeRes();
      m2(fakeReq(), r2, next);
      expect(() => r2.setHeader('Location', '/x\r\ny')).toThrow(
        ResponseSplittingError,
      );
    });
  });

  describe('Pure helpers', () => {
    it('detectResponseSplitting matches header injection', () => {
      expect(detectResponseSplitting('a\r\nb')).toBe(true);
      expect(detectResponseSplitting('clean')).toBe(false);
    });

    it('sanitizeResponseHeader strips CRLF/null', () => {
      expect(sanitizeResponseHeader('a\r\n\0b')).toBe('ab');
    });
  });
});
