/**
 * v1.7 W1 bot UA wire-up integration tests.
 *
 * arcis() by default classifies the request User-Agent and denies the
 * AUTOMATED category (headless browser automation: Selenium, Puppeteer,
 * Playwright, PhantomJS, WebDriver, Headless Chrome) with 403. Opt-out via
 * { bot: false }.
 *
 * SCRAPER (curl, wget, python-requests, sqlmap, nikto, nuclei) is NOT denied
 * by default: that category also covers legitimate non-browser clients such
 * as health checks, monitoring, and server-to-server calls. Blocking scrapers
 * is opt-in via { bot: { deny: ['AUTOMATED', 'SCRAPER'] } }.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Request, Response } from 'express';
import arcis from '../../src/index';
import { createTestServer, TestServer } from '../setup';

describe('Integration: bot UA wire-up (v1.7 W1)', () => {
  describe('default-on, blocks AUTOMATED browser-automation UAs', () => {
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

    const automatedBots: Array<[string]> = [
      ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36'],
      ['Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/534.34'],
      ['Mozilla/5.0 (compatible; Selenium/4.16.0)'],
    ];

    it.each(automatedBots)('denies %s with 403', async (ua) => {
      const r = await fetch(server.url + '/echo', {
        headers: { 'user-agent': ua },
      });
      expect(r.status).toBe(403);
    });
  });

  describe('default-on, lets browsers, search engines, and non-browser clients through', () => {
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

    // Real browsers + search engines (full browser header set).
    const browsers: Array<[string]> = [
      ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'],
      ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'],
      ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
    ];

    it.each(browsers)('allows browser/search-engine %s with 200', async (ua) => {
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

    // SCRAPER-category clients are not default-denied. Sends the bare UA with
    // no Accept headers, mirroring a `curl` health check or an uptime monitor.
    const nonBrowserClients: Array<[string]> = [
      ['curl/7.68.0'],
      ['python-requests/2.28.0'],
      ['Wget/1.21.3'],
    ];

    it.each(nonBrowserClients)('allows non-browser client %s with 200', async (ua) => {
      const r = await fetch(server.url + '/echo', {
        headers: { 'user-agent': ua },
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

    it('lets a HeadlessChrome UA through when bot is disabled', async () => {
      const r = await fetch(server.url + '/echo', {
        headers: { 'user-agent': 'Mozilla/5.0 HeadlessChrome/120.0.0.0' },
      });
      expect(r.status).toBe(200);
    });
  });

  describe('opt-in scraper blocking via { bot: { deny: [AUTOMATED, SCRAPER] } }', () => {
    let server: TestServer;
    let stack: ReturnType<typeof arcis>;

    beforeAll(async () => {
      stack = arcis({ rateLimit: false, bot: { deny: ['AUTOMATED', 'SCRAPER'] } });
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

    it('blocks curl with 403 when SCRAPER is explicitly denied', async () => {
      const r = await fetch(server.url + '/echo', {
        headers: { 'user-agent': 'curl/7.68.0' },
      });
      expect(r.status).toBe(403);
    });

    it('blocks sqlmap with 403 when SCRAPER is explicitly denied', async () => {
      const r = await fetch(server.url + '/echo', {
        headers: { 'user-agent': 'sqlmap/1.7.2#stable (https://sqlmap.org)' },
      });
      expect(r.status).toBe(403);
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

    it('lets a HeadlessChrome UA through under dryRun even though it would normally be blocked', async () => {
      const r = await fetch(server.url + '/echo', {
        headers: { 'user-agent': 'Mozilla/5.0 HeadlessChrome/120.0.0.0' },
      });
      expect(r.status).toBe(200);
    });
  });

  describe('corpus categorization regression', () => {
    // Catches future drift if patterns silently fall through enum validation.
    it('classifies the bench scraper UAs as SCRAPER (not UNKNOWN)', async () => {
      const { detectBot } = await import('../../src/middleware/bot-detection');
      const minReq = (ua: string): any => ({ headers: { 'user-agent': ua, 'accept': 'text/html', 'accept-language': 'en-US', 'accept-encoding': 'gzip' } });
      expect(detectBot(minReq('curl/7.68.0')).category).toBe('SCRAPER');
      expect(detectBot(minReq('python-requests/2.28')).category).toBe('SCRAPER');
      expect(detectBot(minReq('sqlmap/1.7')).category).toBe('SCRAPER');
      expect(detectBot(minReq('Nikto/2.5')).category).toBe('SCRAPER');
      expect(detectBot(minReq('Nuclei/2.9')).category).toBe('SCRAPER');
    });

    it('classifies headless browser automation UAs as AUTOMATED', async () => {
      const { detectBot } = await import('../../src/middleware/bot-detection');
      const minReq = (ua: string): any => ({ headers: { 'user-agent': ua } });
      expect(detectBot(minReq('Mozilla/5.0 HeadlessChrome/120.0.0.0')).category).toBe('AUTOMATED');
      expect(detectBot(minReq('PhantomJS/2.1.1')).category).toBe('AUTOMATED');
    });
  });
});
