/**
 * HPP (HTTP Parameter Pollution) Protection Tests
 * Tests for src/middleware/hpp.ts
 */

import { describe, it, expect, vi } from 'vitest';
import { hpp, createHpp } from '../../src/middleware/hpp';
import type { Request, Response, NextFunction } from 'express';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function mockRequest(overrides: Record<string, unknown> = {}): Request {
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

function mockResponse(): Partial<Response> {
  return {};
}

function callHpp(
  options: Parameters<typeof hpp>[0] = {},
  reqOverrides: Record<string, unknown> = {}
) {
  const req = mockRequest(reqOverrides);
  const res = mockResponse();
  const next = vi.fn();
  const middleware = hpp(options);
  middleware(req, res as Response, next as unknown as NextFunction);
  return { req, res, next };
}

// ─── Basic Normalization ──────────────────────────────────────────────────────

describe('hpp — query normalization', () => {
  it('passes through single values unchanged', () => {
    const { req, next } = callHpp({}, { query: { role: 'user', name: 'alice' } });
    expect((req.query as Record<string, unknown>).role).toBe('user');
    expect((req.query as Record<string, unknown>).name).toBe('alice');
    expect(next).toHaveBeenCalledOnce();
  });

  it('last value wins for duplicate params', () => {
    const { req } = callHpp({}, { query: { role: ['user', 'admin'] } });
    expect((req.query as Record<string, unknown>).role).toBe('admin');
  });

  it('stores originals in queryPolluted', () => {
    const { req } = callHpp({}, { query: { role: ['user', 'admin'] } });
    expect((req as unknown as Record<string, unknown>).queryPolluted).toEqual({
      role: ['user', 'admin'],
    });
  });

  it('queryPolluted is empty when no duplicates', () => {
    const { req } = callHpp({}, { query: { role: 'user' } });
    expect((req as unknown as Record<string, unknown>).queryPolluted).toEqual({});
  });

  it('normalizes multiple duplicate params', () => {
    const { req } = callHpp({}, { query: { role: ['user', 'admin'], sort: ['asc', 'desc'] } });
    expect((req.query as Record<string, unknown>).role).toBe('admin');
    expect((req.query as Record<string, unknown>).sort).toBe('desc');
  });

  it('handles empty array value', () => {
    const { req } = callHpp({}, { query: { empty: [] as string[] } });
    expect((req.query as Record<string, unknown>).empty).toBe('');
  });
});

// ─── Body Normalization ───────────────────────────────────────────────────────

describe('hpp — body normalization', () => {
  it('last value wins for duplicate body params', () => {
    const { req } = callHpp({}, { body: { role: ['user', 'admin'] } });
    expect((req.body as Record<string, unknown>).role).toBe('admin');
  });

  it('stores originals in bodyPolluted', () => {
    const { req } = callHpp({}, { body: { role: ['user', 'admin'] } });
    expect((req as unknown as Record<string, unknown>).bodyPolluted).toEqual({
      role: ['user', 'admin'],
    });
  });

  it('bodyPolluted is empty when no duplicates', () => {
    const { req } = callHpp({}, { body: { name: 'alice' } });
    expect((req as unknown as Record<string, unknown>).bodyPolluted).toEqual({});
  });

  it('skips body normalization when checkBody is false', () => {
    const { req } = callHpp({ checkBody: false }, { body: { role: ['user', 'admin'] } });
    expect((req.body as Record<string, unknown>).role).toEqual(['user', 'admin']);
  });

  it('skips array body altogether', () => {
    const body = ['a', 'b'];
    const { req } = callHpp({}, { body });
    // Array bodies should not be modified
    expect(req.body).toEqual(['a', 'b']);
  });
});

// ─── Whitelist ────────────────────────────────────────────────────────────────

describe('hpp — whitelist', () => {
  it('whitelisted param keeps array in query', () => {
    const { req } = callHpp({ whitelist: ['tags'] }, { query: { tags: ['python', 'security'] } });
    expect((req.query as Record<string, unknown>).tags).toEqual(['python', 'security']);
  });

  it('whitelisted param not added to queryPolluted', () => {
    const { req } = callHpp({ whitelist: ['tags'] }, { query: { tags: ['a', 'b'] } });
    expect((req as unknown as Record<string, unknown>).queryPolluted).toEqual({});
  });

  it('non-whitelisted params still normalized', () => {
    const { req } = callHpp(
      { whitelist: ['tags'] },
      { query: { tags: ['a', 'b'], role: ['user', 'admin'] } }
    );
    expect((req.query as Record<string, unknown>).tags).toEqual(['a', 'b']);
    expect((req.query as Record<string, unknown>).role).toBe('admin');
  });

  it('whitelist applies to body too', () => {
    const { req } = callHpp({ whitelist: ['ids'] }, { body: { ids: [1, 2, 3], role: ['user', 'admin'] } });
    expect((req.body as Record<string, unknown>).ids).toEqual([1, 2, 3]);
    expect((req.body as Record<string, unknown>).role).toBe('admin');
  });
});

// ─── checkQuery flag ──────────────────────────────────────────────────────────

describe('hpp — checkQuery flag', () => {
  it('skips query normalization when checkQuery is false', () => {
    const { req } = callHpp({ checkQuery: false }, { query: { role: ['user', 'admin'] } });
    // query should remain as-is (array)
    expect((req.query as Record<string, unknown>).role).toEqual(['user', 'admin']);
  });
});

// ─── Always calls next ────────────────────────────────────────────────────────

describe('hpp — next() always called', () => {
  it('calls next for clean request', () => {
    const { next } = callHpp({}, { query: { x: 'y' } });
    expect(next).toHaveBeenCalledOnce();
  });

  it('calls next even when pollution detected', () => {
    const { next } = callHpp({}, { query: { role: ['user', 'admin'] } });
    expect(next).toHaveBeenCalledOnce();
  });

  it('calls next when body is null', () => {
    const { next } = callHpp({}, { body: null });
    expect(next).toHaveBeenCalledOnce();
  });
});

// ─── createHpp alias ─────────────────────────────────────────────────────────

describe('createHpp', () => {
  it('is an alias for hpp', () => {
    expect(createHpp).toBe(hpp);
  });

  it('works the same as hpp()', () => {
    const { req, next } = (() => {
      const req = mockRequest({ query: { role: ['user', 'admin'] } });
      const res = mockResponse();
      const next = vi.fn();
      createHpp()(req, res as Response, next as unknown as NextFunction);
      return { req, next };
    })();
    expect((req.query as Record<string, unknown>).role).toBe('admin');
    expect(next).toHaveBeenCalledOnce();
  });
});
