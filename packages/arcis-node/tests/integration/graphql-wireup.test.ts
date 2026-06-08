/**
 * v1.7 W3 GraphQL wire-up integration tests.
 *
 * arcis() by default inspects request bodies with a `query` field as
 * GraphQL documents and blocks depth-bomb, alias-bomb (>10), fragment
 * cycles, and introspection. Opt-out via { graphql: false }. The 4
 * bench payloads MUST all return 403.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Request, Response } from 'express';
import arcis from '../../src/index';
import { createTestServer, TestServer } from '../setup';

describe('Integration: GraphQL wire-up (v1.7 W3)', () => {
  describe('default-on blocks the 4 bench payloads', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.post('/graphql', (_req: Request, res: Response) => {
          res.json({ data: {} });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    const benchPayloads: Array<[string, string]> = [
      ['alias-bomb', '{a:user{id} b:user{id} c:user{id} d:user{id} e:user{id} f:user{id} g:user{id} h:user{id} i:user{id} j:user{id} k:user{id} l:user{id}}'],
      ['fragment-cycle', 'fragment A on Query { ...B } fragment B on Query { ...A } { ...A }'],
      ['deep-query', '{user{posts{comments{replies{replies{replies{replies{replies{replies{replies{id}}}}}}}}}}}'],
      ['introspection', '{__schema{types{name fields{name type{name}}}}}'],
    ];

    it.each(benchPayloads)('blocks %s with 403', async (_name, query) => {
      const r = await fetch(server.url + '/graphql', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ query }),
      });
      expect(r.status).toBe(403);
    });
  });

  describe('allows legitimate queries', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.post('/graphql', (_req: Request, res: Response) => {
          res.json({ data: {} });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    const legit: Array<[string, string]> = [
      ['simple', '{ user { id name email } }'],
      ['nested-reasonable', '{ user { posts { comments { author { name } } } } }'],
      ['with-typename', '{ user { __typename id name } }'],
      ['few-aliases', '{ a: user(id: 1) { name } b: user(id: 2) { name } }'],
      ['no-query-field', ''],
    ];

    it.each(legit)('allows %s with 200', async (_name, query) => {
      const body = query === '' ? { other: 'field' } : { query };
      const r = await fetch(server.url + '/graphql', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      expect(r.status).toBe(200);
    });
  });

  describe('opt-out via { graphql: false }', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false, graphql: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.post('/graphql', (_req: Request, res: Response) => {
          res.json({ data: {} });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    it('lets alias bomb through when graphql is disabled', async () => {
      const r = await fetch(server.url + '/graphql', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ query: '{a:u{id} b:u{id} c:u{id} d:u{id} e:u{id} f:u{id} g:u{id} h:u{id} i:u{id} j:u{id} k:u{id} l:u{id}}' }),
      });
      expect(r.status).toBe(200);
    });
  });

  describe('custom options pass through', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      // Dev profile: allow introspection.
      stack = arcis({ rateLimit: false, graphql: { blockIntrospection: false } });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.post('/graphql', (_req: Request, res: Response) => {
          res.json({ data: {} });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    it('lets introspection through when blockIntrospection: false', async () => {
      const r = await fetch(server.url + '/graphql', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ query: '{__schema{types{name}}}' }),
      });
      expect(r.status).toBe(200);
    });
  });

  describe('dryRun mode never blocks', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false, dryRun: true });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.post('/graphql', (_req: Request, res: Response) => {
          res.json({ data: {} });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    it('lets alias bomb through under dry-run', async () => {
      const r = await fetch(server.url + '/graphql', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ query: '{a:u{id} b:u{id} c:u{id} d:u{id} e:u{id} f:u{id} g:u{id} h:u{id} i:u{id} j:u{id} k:u{id} l:u{id}}' }),
      });
      expect(r.status).toBe(200);
    });
  });
});
