/**
 * v1.7 W1 bot UA wire-up integration tests.
 *
 * arcis() by default classifies the request User-Agent and denies the
 * AUTOMATED + SCRAPER categories with 403. Opt-out via { bot: false }.
 *
 * The five "bench bot" UAs (curl, python-requests, sqlmap, nikto, nuclei)
 * MUST be denied by default. These are the same payloads the local
 * benchmark fires against the ghost + mealie targets.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Request, Response } from 'express';
import arcis from '../../src/index';
import { createTestServer, TestServer } from '../setup';

describe('Integration: bot UA wire-up (v1.7 W1)', () => {
  describe('default-on, blocks the 5 bench bot UAs', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.get('/echo', (_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    const benchBots: Array<[string, string]> = [
      ['curl/7.68.0', 'curl'],
      ['python-requests/2.28.0', 'python-requests'],
      ['sqlmap/1.7.2#stable (https://sqlmap.org)', 'sqlmap'],
      ['Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)', 'Nikto'],
      ['Nuclei - Open-source project (github.com/projectdiscovery/nuclei)', 'Nuclei'],
    ];

    it.each(benchBots)('denies %s with 403', async (ua) => {
      const r = await fetch(server.url + '/echo', {
        headers: { 'user-agent': ua },
      });
      expect(r.status).toBe(403);
    });
  });

  describe('default-on, lets real browsers + search engines through', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.get('/echo', (_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    const realClients: Array<[string]> = [
      ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'],
      ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'],
      ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'],
      ['Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'],
      ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
      ['Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)'],
    ];

    it.each(realClients)('allows %s with 200', async (ua) => {
      const r = await fetch(server.url + '/echo', {
        headers: {
          'user-agent': ua,
          'accept': 'text/html,application/xhtml+xml',
          'accept-language': 'en-US,en;q=0.9',
          'accept-encoding': 'gzip, deflate, br',
        },
      });
      expect(r.status).toBe(200);
    });
  });

  describe('opt-out via { bot: false }', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false, bot: false });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.get('/echo', (_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    it('lets curl through when bot is disabled', async () => {
      const r = await fetch(server.url + '/echo', {
        headers: { 'user-agent': 'curl/7.68.0' },
      });
      expect(r.status).toBe(200);
    });

    it('lets sqlmap through when bot is disabled', async () => {
      const r = await fetch(server.url + '/echo', {
        headers: { 'user-agent': 'sqlmap/1.7' },
      });
      expect(r.status).toBe(200);
    });
  });

  describe('custom deny list via { bot: { deny: [...] } }', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false, bot: { deny: ['AUTOMATED'] } });
      server = await createTestServer((app) => {
        app.use(...stack);
        app.get('/echo', (_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    it('respects user-supplied deny: lets SCRAPER through when only AUTOMATED is denied', async () => {
      const r = await fetch(server.url + '/echo', {
        headers: { 'user-agent': 'curl/7.68.0' },
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
        app.get('/echo', (_req: Request, res: Response) => {
          res.json({ ok: true });
        });
      });
    });

    afterAll(async () => {
      stack.close();
      await server.close();
    });

    it('lets sqlmap through under dryRun even though it would normally be blocked', async () => {
      const r = await fetch(server.url + '/echo', {
        headers: { 'user-agent': 'sqlmap/1.7' },
      });
      expect(r.status).toBe(200);
    });
  });

  describe('corpus categorization regression', () => {
    // Catches future drift if patterns silently fall through enum validation
    // (the v1.7 W1 prep round remapped 28 GENERIC + 6 SEO entries that were
    // previously unmatchable because the categories didn't exist in the enum).
    it('classifies the 5 bench bot UAs as SCRAPER (not UNKNOWN)', async () => {
      const { detectBot } = await import('../../src/middleware/bot-detection');
      const minReq = (ua: string): any => ({ headers: { 'user-agent': ua, 'accept': 'text/html', 'accept-language': 'en-US', 'accept-encoding': 'gzip' } });
      expect(detectBot(minReq('curl/7.68.0')).category).toBe('SCRAPER');
      expect(detectBot(minReq('python-requests/2.28')).category).toBe('SCRAPER');
      expect(detectBot(minReq('sqlmap/1.7')).category).toBe('SCRAPER');
      expect(detectBot(minReq('Nikto/2.5')).category).toBe('SCRAPER');
      expect(detectBot(minReq('Nuclei/2.9')).category).toBe('SCRAPER');
    });
  });
});
