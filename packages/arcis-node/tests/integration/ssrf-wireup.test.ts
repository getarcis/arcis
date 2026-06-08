/**
 * v1.7 W5 SSRF body-URL validation integration tests.
 *
 * arcis() by default walks JSON bodies for URL-shaped string values and
 * validates each. Private / loopback / link-local / metadata / file:// /
 * gopher:// URLs get a 403; public URLs pass. Opt-out via { ssrf: false }.
 * Covers the 8 benchmark SSRF payloads.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Request, Response } from 'express';
import arcis from '../../src/index';
import { createTestServer, TestServer } from '../setup';

describe('Integration: SSRF wire-up (v1.7 W5)', () => {
  describe('default-on blocks the 8 bench payloads', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.post('/fetch', (_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    const benchPayloads: Array<[string, string]> = [
      ['loopback', 'http://127.0.0.1:8080/admin'],
      ['aws-metadata', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'],
      ['gcp-metadata', 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'],
      ['azure-metadata', 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'],
      ['decimal-ip', 'http://2130706433/admin'],
      ['hex-ip', 'http://0x7f000001/admin'],
      ['file-scheme', 'file:///etc/passwd'],
      ['gopher-smtp', 'gopher://127.0.0.1:25/_EHLO%20attacker'],
    ];

    it.each(benchPayloads)('blocks %s with 403', async (_name, url) => {
      const r = await fetch(server.url + '/fetch', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      expect(r.status).toBe(403);
    });
  });

  describe('allows public URLs', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.post('/fetch', (_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    const publicUrls: Array<[string]> = [
      ['https://example.com/page'],
      ['https://api.github.com/repos/x/y'],
      ['http://cdn.example.org/asset.png'],
      ['https://sub.domain.example.com:8443/path?a=1'],
      // ftp to a public host is a legit fetch scheme, not SSRF.
      ['ftp://files.example.com/public/manual.pdf'],
      // localhost hostname is common in dev/config payloads; allowed.
      // (Loopback IP forms like 127.0.0.1 are still blocked above.)
      ['http://localhost:3000/api/health'],
    ];

    it.each(publicUrls)('allows %s with 200', async (url) => {
      const r = await fetch(server.url + '/fetch', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      expect(r.status).toBe(200);
    });

    it('allows a body with no URL fields', async () => {
      const r = await fetch(server.url + '/fetch', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'alice', count: 3 }),
      });
      expect(r.status).toBe(200);
    });

    it('catches a private URL nested deep in the body', async () => {
      const r = await fetch(server.url + '/fetch', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ config: { webhook: { url: 'http://169.254.169.254/' } } }),
      });
      expect(r.status).toBe(403);
    });
  });

  describe('opt-out via { ssrf: false }', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false, ssrf: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.post('/fetch', (_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    it('lets a loopback URL through when ssrf is disabled', async () => {
      const r = await fetch(server.url + '/fetch', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'http://127.0.0.1:8080/admin' }),
      });
      expect(r.status).toBe(200);
    });
  });
});
