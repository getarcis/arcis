/**
 * Phase C bot-corpus cloud-refresh wire-up. With
 * intelligence.cloudDecisions including 'bot-corpus', arcis() fetches the
 * corpus snapshot on startup and merges it on top of the bundled corpus, so a
 * scanner UA that the bundle doesn't know becomes classified (and denied, since
 * SECURITY_SCANNER is default-denied) without an SDK release. Fail-open: an
 * unreachable service leaves the bundled corpus untouched.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Request, Response, Express } from 'express';
import arcis from '../../src/index';
import { _resetBotPatternsForTest } from '../../src/middleware/bot-detection';
import { createTestServer, TestServer } from '../setup';

const NOVEL_UA = 'ArcisWireupScanner-7777/1.0';

async function createCorpusStub(entries: unknown[]): Promise<TestServer & { hits: () => number }> {
  let hitCount = 0;
  const server = await createTestServer((app) => {
    app.get('/v1/intel/bot-corpus/snapshot', (_req: Request, res: Response) => {
      hitCount += 1;
      res.json({ schema_version: '1', count: entries.length, entries });
    });
  });
  return { ...server, hits: () => hitCount };
}

async function pollDenied(url: string, tries = 60): Promise<boolean> {
  for (let i = 0; i < tries; i++) {
    const r = await fetch(url + '/', { headers: { 'user-agent': NOVEL_UA } });
    if (r.status === 403) return true;
    await new Promise((res) => setTimeout(res, 15));
  }
  return false;
}

describe('Integration: bot-corpus cloud refresh (Phase C)', () => {
  afterAll(() => _resetBotPatternsForTest());

  it('classifies + denies a novel scanner UA after the corpus refresh lands', async () => {
    const intel = await createCorpusStub([
      { id: 'arcis-wireup-scanner', category: 'SECURITY_SCANNER', name: 'ArcisWireupScanner', patterns: ['ArcisWireupScanner-7777'], forbidden: [] },
    ]);
    const stack = arcis({
      rateLimit: false,
      intelligence: { endpoint: intel.url, cloudDecisions: ['bot-corpus'] },
    });
    const server = await createTestServer((app: Express) => {
      app.use(...stack);
      app.get('/', (_req: Request, res: Response) => res.json({ ok: true }));
    });
    try {
      // The bundle doesn't know this UA; once the startup refresh merges the
      // entry, the SECURITY_SCANNER category is default-denied -> 403.
      expect(await pollDenied(server.url)).toBe(true);
      expect(intel.hits()).toBeGreaterThan(0);
    } finally {
      stack.close();
      await server.close();
      await intel.close();
      _resetBotPatternsForTest();
    }
  });

  it('fails open: unreachable corpus service leaves the bundle intact', async () => {
    const stack = arcis({
      rateLimit: false,
      intelligence: { endpoint: 'http://127.0.0.1:1', cloudDecisions: ['bot-corpus'] },
    });
    const server = await createTestServer((app: Express) => {
      app.use(...stack);
      app.get('/', (_req: Request, res: Response) => res.json({ ok: true }));
    });
    try {
      // Novel UA stays unknown (allowed) because the refresh failed.
      const r = await fetch(server.url + '/', { headers: { 'user-agent': NOVEL_UA } });
      expect(r.status).toBe(200);
    } finally {
      stack.close();
      await server.close();
      _resetBotPatternsForTest();
    }
  });
});
