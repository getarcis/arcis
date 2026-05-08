/**
 * GraphQL injection / depth-bomb tests (sdk-vectors.md tier 1 #21).
 *
 * Two test layers:
 * 1. Pure sanitizer (`inspectGraphqlQuery` / `detectGraphqlAbuse`) over
 *    plain strings — no Express, no I/O.
 * 2. Middleware (`graphqlGuard`) over fake req/res driving the depth /
 *    introspection / length deny paths and the pass-through path.
 */

import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import {
  detectGraphqlAbuse,
  inspectGraphqlQuery,
} from '../../src/sanitizers/graphql';
import { graphqlGuard } from '../../src/middleware/graphql';

interface FakeRes {
  res: Response;
  state: { status: number | null; body: unknown; sent: boolean };
}

function fakeReq(body?: unknown, query?: Record<string, string>): Request {
  return {
    body,
    query: query ?? {},
    method: 'POST',
    headers: {},
  } as unknown as Request;
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

describe('inspectGraphqlQuery — depth detection', () => {
  it('reports depth=0 for a single-field query', () => {
    const r = inspectGraphqlQuery('{ user }');
    expect(r.depth).toBe(1);
    expect(r.blocked).toBe(false);
  });

  it('counts every nesting level', () => {
    const r = inspectGraphqlQuery('{ a { b { c { d } } } }');
    expect(r.depth).toBe(4);
    expect(r.blocked).toBe(false); // default maxDepth is 10
  });

  it('blocks queries deeper than maxDepth', () => {
    // Build a 12-deep nested query.
    const open = '{ a '.repeat(12);
    const close = '} '.repeat(12);
    const query = open + close;
    const r = inspectGraphqlQuery(query);
    expect(r.depth).toBe(12);
    expect(r.blocked).toBe(true);
    expect(r.reason).toBe('depth');
  });

  it('honors a custom maxDepth', () => {
    const r = inspectGraphqlQuery('{ a { b { c } } }', { maxDepth: 2 });
    expect(r.depth).toBe(3);
    expect(r.blocked).toBe(true);
    expect(r.reason).toBe('depth');
  });

  it('clamps brace counter at 0 on malformed input (extra closes)', () => {
    // `} } } } { a }` would underflow if we didn't clamp. Final depth
    // is 1 (the only `{` to `}` block). Pin: doesn't crash, doesn't
    // miscount.
    const r = inspectGraphqlQuery('} } } } { a }');
    expect(r.depth).toBe(1);
    expect(r.blocked).toBe(false);
  });
});

describe('inspectGraphqlQuery — introspection detection', () => {
  it('blocks __schema queries', () => {
    const r = inspectGraphqlQuery('{ __schema { types { name } } }');
    expect(r.blocked).toBe(true);
    expect(r.reason).toBe('introspection');
  });

  it('blocks __type queries', () => {
    const r = inspectGraphqlQuery('{ __type(name: "User") { fields { name } } }');
    expect(r.blocked).toBe(true);
    expect(r.reason).toBe('introspection');
  });

  it('does NOT block legitimate __typename usage (Apollo client convention)', () => {
    // Apollo + Relay clients add __typename to every query for cache
    // identity. Blocking it would break virtually every GraphQL
    // client. Pin: __typename passes; __schema/__type do not.
    const r = inspectGraphqlQuery('{ user { id __typename } }');
    expect(r.blocked).toBe(false);
  });

  it('does NOT false-fire on user fields with double underscores not at start', () => {
    // `last__updated_at` shouldn't match — the boundary regex requires
    // the `__` to be word-boundary-prefixed.
    const r = inspectGraphqlQuery('{ user { last__updated_at } }');
    expect(r.blocked).toBe(false);
  });

  it('passes introspection through when blockIntrospection: false', () => {
    // Dev tools (GraphiQL, Apollo Studio) need introspection. Pin
    // that opt-out works.
    const r = inspectGraphqlQuery('{ __schema { types { name } } }', {
      blockIntrospection: false,
    });
    expect(r.blocked).toBe(false);
  });
});

describe('inspectGraphqlQuery — length detection', () => {
  it('blocks queries longer than maxLength', () => {
    // Default maxLength is 10000 — exceed it with padding.
    const long = `{ field(arg: "${'x'.repeat(10100)}") }`;
    const r = inspectGraphqlQuery(long);
    expect(r.blocked).toBe(true);
    expect(r.reason).toBe('length');
  });

  it('honors a custom maxLength', () => {
    const r = inspectGraphqlQuery('{ aaaaaaaaaa }', { maxLength: 10 });
    expect(r.blocked).toBe(true);
    expect(r.reason).toBe('length');
  });
});

describe('inspectGraphqlQuery — precedence', () => {
  it('reports depth before introspection when both fire', () => {
    // Build a query that's both 12-deep AND contains __schema. Depth
    // is the more security-critical signal (DoS) and is also the
    // most expensive to surface, so it wins.
    const open = '{ a '.repeat(12);
    const close = '} '.repeat(12);
    const query = `${open} __schema ${close}`;
    const r = inspectGraphqlQuery(query);
    expect(r.blocked).toBe(true);
    expect(r.reason).toBe('depth');
  });

  it('reports introspection before length when both fire', () => {
    const long = `{ __schema(arg: "${'x'.repeat(10100)}") { types } }`;
    const r = inspectGraphqlQuery(long);
    expect(r.blocked).toBe(true);
    expect(r.reason).toBe('introspection');
  });
});

describe('detectGraphqlAbuse — boolean wrapper', () => {
  it('returns true for blocked queries', () => {
    expect(detectGraphqlAbuse('{ __schema { types } }')).toBe(true);
  });

  it('returns false for clean queries', () => {
    expect(detectGraphqlAbuse('{ user { id name } }')).toBe(false);
  });

  it('returns false for non-string input', () => {
    expect(detectGraphqlAbuse(undefined as unknown as string)).toBe(false);
    expect(detectGraphqlAbuse(null as unknown as string)).toBe(false);
    expect(detectGraphqlAbuse('')).toBe(false);
    expect(detectGraphqlAbuse(42 as unknown as string)).toBe(false);
  });
});

describe('graphqlGuard middleware', () => {
  it('passes a clean query through to next()', () => {
    const middleware = graphqlGuard();
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(fakeReq({ query: '{ user { id name } }' }), res, next);
    expect(next).toHaveBeenCalled();
    expect(state.sent).toBe(false);
  });

  it('returns 400 on a depth-bomb', () => {
    const middleware = graphqlGuard({ maxDepth: 5 });
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(
      fakeReq({ query: '{ a { b { c { d { e { f } } } } } }' }),
      res,
      next,
    );
    expect(next).not.toHaveBeenCalled();
    expect(state.status).toBe(400);
    expect(state.body).toMatchObject({
      reason: 'depth',
      observed: { depth: 6 },
    });
  });

  it('returns 400 on an introspection query', () => {
    const middleware = graphqlGuard();
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(fakeReq({ query: '{ __schema { types { name } } }' }), res, next);
    expect(state.status).toBe(400);
    expect(state.body).toMatchObject({ reason: 'introspection' });
  });

  it('reads the query from req.query.query for GET transport', () => {
    const middleware = graphqlGuard();
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(fakeReq(undefined, { query: '{ __schema { types } }' }), res, next);
    expect(state.status).toBe(400);
    expect(state.body).toMatchObject({ reason: 'introspection' });
  });

  it('passes through when no query is present (non-GraphQL request)', () => {
    // Same path used for /graphql can also receive heartbeats /
    // health-checks; a missing query shouldn't 400.
    const middleware = graphqlGuard();
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(fakeReq({}), res, next);
    expect(next).toHaveBeenCalled();
    expect(state.sent).toBe(false);
  });

  it('honors a custom statusCode', () => {
    const middleware = graphqlGuard({ statusCode: 422 });
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(fakeReq({ query: '{ __schema { types } }' }), res, next);
    expect(state.status).toBe(422);
  });

  it('honors a static custom message', () => {
    const middleware = graphqlGuard({ message: 'Nope' });
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(fakeReq({ query: '{ __schema { types } }' }), res, next);
    expect(state.body).toMatchObject({ error: 'Nope' });
  });

  it('honors a per-reason message function', () => {
    const middleware = graphqlGuard({
      message: (reason) => `Reason was ${reason}`,
    });
    const next = vi.fn() as NextFunction;
    const { res, state } = fakeRes();
    middleware(fakeReq({ query: '{ __schema { types } }' }), res, next);
    expect(state.body).toMatchObject({ error: 'Reason was introspection' });
  });
});
