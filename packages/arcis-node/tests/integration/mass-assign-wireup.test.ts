/**
 * v1.7 W4 mass-assignment field detection integration tests.
 *
 * arcis() by default scans JSON bodies (recursively) for privilege-
 * escalation field names (isAdmin, role, permissions, ...) and blocks
 * with 403. Opt-out via { massAssign: false }. The 3 bench payloads
 * (including the nested one) MUST be blocked; ordinary profile updates
 * MUST pass.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Request, Response } from 'express';
import arcis from '../../src/index';
import { createTestServer, TestServer } from '../setup';

describe('Integration: mass-assignment wire-up (v1.7 W4)', () => {
  describe('default-on blocks the 3 bench payloads', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.post('/users', (_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    const benchPayloads: Array<[string, unknown]> = [
      ['isAdmin', { name: 'john', email: 'j@x.com', isAdmin: true }],
      ['role', { username: 'j', role: 'superadmin' }],
      ['nested-permissions', { profile: { name: 'j', permissions: ['admin', 'billing'] } }],
    ];

    it.each(benchPayloads)('blocks %s with 403', async (_name, body) => {
      const r = await fetch(server.url + '/users', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      expect(r.status).toBe(403);
    });
  });

  describe('allows ordinary profile updates', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.post('/users', (_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    const legit: Array<[string, unknown]> = [
      ['name+email', { name: 'Alice', email: 'alice@example.com' }],
      ['profile bio', { profile: { displayName: 'Al', bio: 'hello world' } }],
      ['nested address', { user: { name: 'Bob', address: { city: 'NYC', zip: '10001' } } }],
      ['order', { items: [{ sku: 'A1', qty: 2 }], total: 49.99 }],
      ['empty', {}],
    ];

    it.each(legit)('allows %s with 200', async (_name, body) => {
      const r = await fetch(server.url + '/users', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      expect(r.status).toBe(200);
    });
  });

  describe('opt-out via { massAssign: false }', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false, massAssign: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.post('/users', (_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    it('lets isAdmin through when massAssign is disabled', async () => {
      const r = await fetch(server.url + '/users', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'j', isAdmin: true }),
      });
      expect(r.status).toBe(200);
    });
  });

  describe('case + separator insensitivity', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.post('/users', (_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    const variants: Array<[string]> = [
      ['is_admin'],
      ['IS_ADMIN'],
      ['is-admin'],
      ['isAdmin'],
    ];

    it.each(variants)('blocks %s variant', async (key) => {
      const r = await fetch(server.url + '/users', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'j', [key]: true }),
      });
      expect(r.status).toBe(403);
    });
  });
});
