/**
 * v1.7 W1 bot UA wire-up integration tests.
 *
 * arcis() by default classifies the request User-Agent and denies two
 * categories with 403:
 *   - AUTOMATED: headless browser automation (Selenium, Puppeteer,
 *     Playwright, PhantomJS, WebDriver, Headless Chrome).
 *   - SECURITY_SCANNER: offensive scanners (sqlmap, nikto, nuclei, nmap,
 *     masscan, wpscan, Acunetix, Nessus, dirbuster).
 *
 * SCRAPER (curl, wget, python-requests, monitoring) is NOT denied by default:
 * that category also covers legitimate non-browser clients such as health
 * checks and server-to-server calls. Blocking scrapers is opt-in via
 * { bot: { deny: ['AUTOMATED', 'SCRAPER'] } }.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Request, Response } from 'express';
import arcis from '../../src/index';
import { createTestServer, TestServer } from '../setup';

function makeServer(opts: Parameters<typeof arcis>[0] = {}) {
  let server: TestServer;
  let stack: ReturnType<typeof arcis>;
  beforeAll(async () => {
    stack = arcis({ rateLimit: false, ...opts });
    server = await createTestServer((app) => {
      app.use(...stack);
      app.get('/echo', (_req: Request, res: Response) => res.json({ ok: true }));
    });
  });
  afterAll(async () => {
    stack.close();
    await server.close();
  });
  return () => server;
}

const ua = (s: string) => ({ headers: { 'user-agent': s } });

describe('Integration: bot UA wire-up (v1.7 W1)', () => {
  describe('default-on denies AUTOMATED browser-automation UAs', () => {
    const srv = makeServer();
    const bots: Array<[string]> = [
      ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36'],
      ['Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/534.34'],
      ['Mozilla/5.0 (compatible; Selenium/4.16.0)'],
    ];
    it.each(bots)('denies %s with 403', async (u) => {
      const r = await fetch(srv().url + '/echo', ua(u));
      expect(r.status).toBe(403);
    });
  });

  describe('default-on denies SECURITY_SCANNER UAs', () => {
    const srv = makeServer();
    const scanners: Array<[string]> = [
      ['sqlmap/1.7.2#stable (https://sqlmap.org)'],
      ['Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)'],
      ['Nuclei - Open-source project (github.com/projectdiscovery/nuclei)'],
      ['masscan/1.3.2'],
      ['Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)'],
    ];
    it.each(scanners)('denies %s with 403', async (u) => {
      const r = await fetch(srv().url + '/echo', ua(u));
      expect(r.status).toBe(403);
    });
  });

  describe('default-on allows browsers, search engines, and non-browser clients', () => {
    const srv = makeServer();
    const browsers: Array<[string]> = [
      ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'],
      ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
    ];
    it.each(browsers)('allows browser/search-engine %s with 200', async (u) => {
      const r = await fetch(srv().url + '/echo', {
        headers: {
          'user-agent': u,
          'accept': 'text/html,application/xhtml+xml',
          'accept-language': 'en-US,en;q=0.9',
          'accept-encoding': 'gzip, deflate, br',
        },
      });
      expect(r.status).toBe(200);
    });

    // SCRAPER-category clients are not default-denied. Bare UA, no Accept
    // headers, mirrors a curl health check or an uptime monitor.
    const clients: Array<[string]> = [['curl/7.68.0'], ['python-requests/2.28.0'], ['Wget/1.21.3']];
    it.each(clients)('allows non-browser client %s with 200', async (u) => {
      const r = await fetch(srv().url + '/echo', ua(u));
      expect(r.status).toBe(200);
    });
  });

  describe('opt-out via { bot: false }', () => {
    const srv = makeServer({ bot: false });
    it('lets a scanner UA through when bot is disabled', async () => {
      const r = await fetch(srv().url + '/echo', ua('sqlmap/1.7.2'));
      expect(r.status).toBe(200);
    });
  });

  describe('opt-in scraper blocking via { bot: { deny: [AUTOMATED, SCRAPER] } }', () => {
    const srv = makeServer({ bot: { deny: ['AUTOMATED', 'SCRAPER'] } });
    it('blocks curl with 403 when SCRAPER is explicitly denied', async () => {
      const r = await fetch(srv().url + '/echo', ua('curl/7.68.0'));
      expect(r.status).toBe(403);
    });
  });

  describe('dryRun mode never blocks', () => {
    const srv = makeServer({ dryRun: true });
    it('lets a scanner UA through under dryRun even though it would normally be blocked', async () => {
      const r = await fetch(srv().url + '/echo', ua('sqlmap/1.7.2'));
      expect(r.status).toBe(200);
    });
  });

  describe('corpus categorization regression', () => {
    it('classifies offensive scanners as SECURITY_SCANNER', async () => {
      const { detectBot } = await import('../../src/middleware/bot-detection');
      const minReq = (u: string): any => ({ headers: { 'user-agent': u } });
      expect(detectBot(minReq('sqlmap/1.7')).category).toBe('SECURITY_SCANNER');
      expect(detectBot(minReq('Nikto/2.5')).category).toBe('SECURITY_SCANNER');
      expect(detectBot(minReq('Nuclei/2.9')).category).toBe('SECURITY_SCANNER');
      expect(detectBot(minReq('masscan/1.3')).category).toBe('SECURITY_SCANNER');
    });

    it('keeps generic non-browser clients as SCRAPER', async () => {
      const { detectBot } = await import('../../src/middleware/bot-detection');
      const minReq = (u: string): any => ({ headers: { 'user-agent': u } });
      expect(detectBot(minReq('curl/7.68.0')).category).toBe('SCRAPER');
      expect(detectBot(minReq('python-requests/2.28')).category).toBe('SCRAPER');
    });

    it('classifies headless browser automation as AUTOMATED', async () => {
      const { detectBot } = await import('../../src/middleware/bot-detection');
      const minReq = (u: string): any => ({ headers: { 'user-agent': u } });
      expect(detectBot(minReq('Mozilla/5.0 HeadlessChrome/120.0.0.0')).category).toBe('AUTOMATED');
      expect(detectBot(minReq('PhantomJS/2.1.1')).category).toBe('AUTOMATED');
    });
  });
});
