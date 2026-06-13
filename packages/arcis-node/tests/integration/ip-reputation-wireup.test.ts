/**
 * Phase C — cloud IP-reputation wire-up integration tests.
 *
 * arcis({ intelligence: { endpoint, cloudDecisions: ['ip-rep'], blockThreshold } })
 * consults a locally-cached reputation feed served by an Arcis intelligence
 * endpoint. Lookups are cache-first and non-blocking: the FIRST request from an
 * IP is a cache miss (allowed) that schedules a background refresh; later
 * requests read the cached verdict and block when severity >= blockThreshold.
 * An unreachable service fails open. Omitting cloudDecisions makes it inert.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Request, Response, Express } from 'express';
import arcis from '../../src/index';
import { createTestServer, TestServer } from '../setup';

const PUBLIC_IP = '203.0.113.50';
const CLEAN_IP = '198.51.100.20';

/** Stub Arcis intelligence endpoint. Returns a verdict per IP and counts hits. */
async function createIntelStub(
  verdicts: Record<string, { severity: number; categories?: string[] }>,
): Promise<TestServer & { hits: () => number }> {
  let hitCount = 0;
  const server = await createTestServer((app) => {
    app.get('/v1/intel/ip-reputation/:ip', (req: Request, res: Response) => {
      hitCount += 1;
      const v = verdicts[req.params.ip];
      if (!v) {
        res.json({ ip: req.params.ip, found: false });
        return;
      }
      res.json({
        ip: req.params.ip,
        found: true,
        severity: v.severity,
        categories: v.categories ?? ['abuse'],
        sources: ['tor-exit'],
        first_seen: '2026-06-11',
        last_seen: '2026-06-11',
        matched: req.params.ip,
      });
    });
  });
  return { ...server, hits: () => hitCount };
}

/** Make GET / requests until one returns `status`, or fail after `tries`. */
async function pollUntilStatus(
  url: string,
  status: number,
  tries = 50,
): Promise<boolean> {
  for (let i = 0; i < tries; i++) {
    const r = await fetch(url + '/', {
      headers: { 'x-forwarded-for': PUBLIC_IP, 'user-agent': 'Mozilla/5.0' },
    });
    if (r.status === status) return true;
    await new Promise((res) => setTimeout(res, 15));
  }
  return false;
}

describe('Integration: IP reputation wire-up (Phase C)', () => {
  describe('blocks a known-bad IP once the cache warms', () => {
    let intel: Awaited<ReturnType<typeof createIntelStub>>;
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      intel = await createIntelStub({ [PUBLIC_IP]: { severity: 9, categories: ['botnet'] } });
      stack = arcis({
        rateLimit: false,
        intelligence: {
          endpoint: intel.url,
          cloudDecisions: ['ip-rep'],
          blockThreshold: 7,
        },
      });
      server = await createTestServer((app: Express) => {
        app.set('trust proxy', true); // honor X-Forwarded-For as the client IP
        app.use(...stack);
        app.get('/', (_req: Request, res: Response) => res.json({ ok: true }));
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
      await intel.close();
    });

    it('first request is allowed (cache miss), then blocks after warm-up', async () => {
      const first = await fetch(server.url + '/', {
        headers: { 'x-forwarded-for': PUBLIC_IP, 'user-agent': 'Mozilla/5.0' },
      });
      expect(first.status).toBe(200); // non-blocking on the miss

      const blocked = await pollUntilStatus(server.url, 403);
      expect(blocked).toBe(true);
    });

    it('never blocks a clean IP', async () => {
      // CLEAN_IP has no verdict in the stub -> found:false -> always allowed.
      for (let i = 0; i < 5; i++) {
        const r = await fetch(server.url + '/', {
          headers: { 'x-forwarded-for': CLEAN_IP, 'user-agent': 'Mozilla/5.0' },
        });
        expect(r.status).toBe(200);
        await new Promise((res) => setTimeout(res, 15));
      }
    });
  });

  describe('fails open when the intelligence service is unreachable', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({
        rateLimit: false,
        intelligence: {
          endpoint: 'http://127.0.0.1:1', // nothing listening
          cloudDecisions: ['ip-rep'],
          blockThreshold: 1,
          timeoutMs: 300,
        },
      });
      server = await createTestServer((app: Express) => {
        app.set('trust proxy', true);
        app.use(...stack);
        app.get('/', (_req: Request, res: Response) => res.json({ ok: true }));
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    it('keeps serving 200 even though the lookup always fails', async () => {
      // Even with blockThreshold:1, an unreachable service never warms the
      // cache, so nothing ever blocks. Poll a few times to be sure.
      const got403 = await pollUntilStatus(server.url, 403, 8);
      expect(got403).toBe(false);
    });
  });

  describe('inert when cloudDecisions omits ip-rep', () => {
    let intel: Awaited<ReturnType<typeof createIntelStub>>;
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      intel = await createIntelStub({ [PUBLIC_IP]: { severity: 9 } });
      stack = arcis({
        rateLimit: false,
        // endpoint set, but no cloudDecisions -> middleware not installed.
        intelligence: { endpoint: intel.url, blockThreshold: 1 },
      });
      server = await createTestServer((app: Express) => {
        app.set('trust proxy', true);
        app.use(...stack);
        app.get('/', (_req: Request, res: Response) => res.json({ ok: true }));
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
      await intel.close();
    });

    it('does not call the intelligence service and never blocks', async () => {
      for (let i = 0; i < 4; i++) {
        const r = await fetch(server.url + '/', {
          headers: { 'x-forwarded-for': PUBLIC_IP, 'user-agent': 'Mozilla/5.0' },
        });
        expect(r.status).toBe(200);
        await new Promise((res) => setTimeout(res, 15));
      }
      expect(intel.hits()).toBe(0);
    });
  });

  describe('dry-run never blocks even above threshold', () => {
    let intel: Awaited<ReturnType<typeof createIntelStub>>;
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      intel = await createIntelStub({ [PUBLIC_IP]: { severity: 10 } });
      stack = arcis({
        rateLimit: false,
        dryRun: true,
        intelligence: {
          endpoint: intel.url,
          cloudDecisions: ['ip-rep'],
          blockThreshold: 1,
        },
      });
      server = await createTestServer((app: Express) => {
        app.set('trust proxy', true);
        app.use(...stack);
        app.get('/', (_req: Request, res: Response) => res.json({ ok: true }));
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
      await intel.close();
    });

    it('stays 200 in dry-run even after the cache warms to severity 10', async () => {
      // Warm the cache: first request schedules the refresh.
      await fetch(server.url + '/', {
        headers: { 'x-forwarded-for': PUBLIC_IP, 'user-agent': 'Mozilla/5.0' },
      });
      // Give the background refresh time to land, then confirm no 403.
      await new Promise((res) => setTimeout(res, 100));
      const got403 = await pollUntilStatus(server.url, 403, 6);
      expect(got403).toBe(false);
    });
  });
});
