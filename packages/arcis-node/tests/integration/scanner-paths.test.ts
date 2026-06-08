/**
 * v1.7 W2 scanner-paths wire-up integration tests.
 *
 * arcis() by default blocks well-known scanner probe paths (/.env,
 * /.git/, /wp-admin, /phpmyadmin, /admin, etc) with 403. Opt-out via
 * { scannerPaths: false }. Real app paths that happen to share a
 * prefix (e.g. /admin/dashboard) MUST still pass.
 *
 * Covers the 3 benchmark "scanner_burst" payloads.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Request, Response } from 'express';
import arcis from '../../src/index';
import { createTestServer, TestServer } from '../setup';

describe('Integration: scanner-path wire-up (v1.7 W2)', () => {
  describe('default-on blocks the 3 bench scanner paths', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.use((_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    const benchPaths: Array<[string]> = [
      ['/admin'],
      ['/wp-admin'],
      ['/.env'],
    ];

    it.each(benchPaths)('denies %s with 403', async (path) => {
      const r = await fetch(server.url + path);
      expect(r.status).toBe(403);
    });
  });

  describe('default-on blocks the broader probe corpus', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.use((_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    const probes: Array<[string]> = [
      ['/.env.local'],
      ['/.git/config'],
      ['/.git/HEAD'],
      ['/.svn/entries'],
      ['/.aws/credentials'],
      ['/wp-login.php'],
      ['/wp-config.php'],
      ['/xmlrpc.php'],
      ['/phpmyadmin/index.php'],
      ['/pma/'],
      ['/adminer.php'],
      ['/phpinfo.php'],
      ['/server-status'],
      ['/administrator'],
    ];

    it.each(probes)('denies %s with 403', async (path) => {
      const r = await fetch(server.url + path);
      expect(r.status).toBe(403);
    });
  });

  describe('non-probe paths pass through unchanged', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.use((_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    // Important: must NOT block routes that legitimately start with
    // one of the probe prefixes but have additional path segments.
    // /admin/dashboard is a real route on many apps; only bare /admin
    // is the probe shape.
    const legit: Array<[string]> = [
      ['/'],
      ['/admin/dashboard'],
      ['/admin/users/42'],
      ['/api/v1/users'],
      ['/healthcheck'],
      ['/env-vars'],
      ['/environment'],
      ['/gitlab/projects'],
      ['/static/image.png'],
      ['/login'],
    ];

    it.each(legit)('allows %s with 200', async (path) => {
      const r = await fetch(server.url + path);
      expect(r.status).toBe(200);
    });
  });

  describe('opt-out via { scannerPaths: false }', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false, scannerPaths: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.use((_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    it('lets /.env through when scannerPaths is disabled', async () => {
      const r = await fetch(server.url + '/.env');
      expect(r.status).toBe(200);
    });

    it('lets /wp-admin through when scannerPaths is disabled', async () => {
      const r = await fetch(server.url + '/wp-admin');
      expect(r.status).toBe(200);
    });
  });

  describe('custom matcher list', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({
        rateLimit: false,
        scannerPaths: { patterns: [/^\/secret-only$/] },
      });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.use((_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    it('blocks custom /secret-only', async () => {
      const r = await fetch(server.url + '/secret-only');
      expect(r.status).toBe(403);
    });

    it('does NOT block default patterns when overridden', async () => {
      const r = await fetch(server.url + '/.env');
      expect(r.status).toBe(200);
    });
  });
});
