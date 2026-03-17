/**
 * Bot Detection Tests
 * Tests for src/middleware/bot-detection.ts
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response } from 'express';
import { detectBot, botProtection } from '../../src/middleware/bot-detection';
import type { BotDetectionResult, BotProtectionOptions } from '../../src/middleware/bot-detection';
import { mockRequest, mockResponse, mockNext } from '../setup';

// Helper: create request with specific User-Agent and optional headers
function botReq(ua: string | undefined, extraHeaders: Record<string, string> = {}): Partial<Request> {
  const headers: Record<string, string | undefined> = {
    'accept': 'text/html',
    'accept-language': 'en-US',
    'accept-encoding': 'gzip',
    ...extraHeaders,
  };
  if (ua !== undefined) {
    headers['user-agent'] = ua;
  }
  return mockRequest({ headers });
}

// Helper: minimal request (no standard headers)
function bareReq(ua?: string): Partial<Request> {
  const headers: Record<string, string | undefined> = {};
  if (ua !== undefined) {
    headers['user-agent'] = ua;
  }
  return mockRequest({ headers });
}

describe('detectBot', () => {
  // =========================================================================
  // SEARCH ENGINE BOTS
  // =========================================================================
  describe('Search Engine detection', () => {
    const searchBots = [
      ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'Googlebot'],
      ['Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)', 'Bingbot'],
      ['Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com)', 'DuckDuckBot'],
      ['Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)', 'YandexBot'],
      ['Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com)', 'Baiduspider'],
      ['Mozilla/5.0 (compatible; Applebot/0.3; +http://www.apple.com)', 'Applebot'],
    ];

    it.each(searchBots)('detects %s as SEARCH_ENGINE', (ua, expectedName) => {
      const result = detectBot(botReq(ua) as Request);
      expect(result.isBot).toBe(true);
      expect(result.category).toBe('SEARCH_ENGINE');
      expect(result.name).toBe(expectedName);
      expect(result.confidence).toBeGreaterThanOrEqual(0.9);
    });
  });

  // =========================================================================
  // SOCIAL BOTS
  // =========================================================================
  describe('Social bot detection', () => {
    const socialBots = [
      ['Twitterbot/1.0', 'Twitterbot'],
      ['facebookexternalhit/1.1', 'Facebook'],
      ['LinkedInBot/1.0', 'LinkedInBot'],
      ['Slackbot-LinkExpanding 1.0', 'Slackbot'],
      ['WhatsApp/2.21', 'WhatsApp'],
      ['Discordbot/2.0', 'Discordbot'],
    ];

    it.each(socialBots)('detects %s as SOCIAL', (ua, expectedName) => {
      const result = detectBot(botReq(ua) as Request);
      expect(result.isBot).toBe(true);
      expect(result.category).toBe('SOCIAL');
      expect(result.name).toBe(expectedName);
    });
  });

  // =========================================================================
  // MONITORING BOTS
  // =========================================================================
  describe('Monitoring bot detection', () => {
    const monitorBots = [
      ['UptimeRobot/2.0', 'UptimeRobot'],
      ['Pingdom.com_bot_version_1.4', 'Pingdom'],
      ['Datadog/Synthetics', 'Datadog'],
    ];

    it.each(monitorBots)('detects %s as MONITORING', (ua, expectedName) => {
      const result = detectBot(botReq(ua) as Request);
      expect(result.isBot).toBe(true);
      expect(result.category).toBe('MONITORING');
      expect(result.name).toBe(expectedName);
    });
  });

  // =========================================================================
  // AI CRAWLERS
  // =========================================================================
  describe('AI Crawler detection', () => {
    const aiCrawlers = [
      ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0)', 'GPTBot'],
      ['ClaudeBot/1.0', 'ClaudeBot'],
      ['anthropic-ai', 'Anthropic'],
      ['CCBot/2.0', 'CCBot'],
      ['PerplexityBot/1.0', 'PerplexityBot'],
      ['Bytespider', 'Bytespider'],
      ['meta-externalagent/1.0', 'Meta AI'],
    ];

    it.each(aiCrawlers)('detects %s as AI_CRAWLER', (ua, expectedName) => {
      const result = detectBot(botReq(ua) as Request);
      expect(result.isBot).toBe(true);
      expect(result.category).toBe('AI_CRAWLER');
      expect(result.name).toBe(expectedName);
    });
  });

  // =========================================================================
  // AUTOMATED TOOLS
  // =========================================================================
  describe('Automated tool detection', () => {
    const automated = [
      ['Mozilla/5.0 HeadlessChrome/90.0', 'Headless Chrome'],
      ['PhantomJS/2.1', 'PhantomJS'],
      ['Mozilla/5.0 Selenium/4.0', 'Selenium'],
      ['Mozilla/5.0 Puppeteer', 'Puppeteer'],
      ['Mozilla/5.0 Playwright/1.0', 'Playwright'],
    ];

    it.each(automated)('detects %s as AUTOMATED', (ua, expectedName) => {
      const result = detectBot(botReq(ua) as Request);
      expect(result.isBot).toBe(true);
      expect(result.category).toBe('AUTOMATED');
      expect(result.name).toBe(expectedName);
    });
  });

  // =========================================================================
  // SCRAPERS / CLI TOOLS
  // =========================================================================
  describe('Scraper/CLI detection', () => {
    const scrapers = [
      ['curl/7.68.0', 'curl'],
      ['wget/1.21', 'wget'],
      ['python-requests/2.25.1', 'python-requests'],
      ['python-httpx/0.23.0', 'python-httpx'],
      ['Go-http-client/1.1', 'Go-http-client'],
      ['axios/0.21.1', 'axios'],
      ['Postman Runtime/7.28', 'Postman'],
      ['HTTPie/3.0', 'HTTPie'],
      ['Scrapy/2.5', 'Scrapy'],
    ];

    it.each(scrapers)('detects %s as SCRAPER', (ua, expectedName) => {
      const result = detectBot(botReq(ua) as Request);
      expect(result.isBot).toBe(true);
      expect(result.category).toBe('SCRAPER');
      expect(result.name).toBe(expectedName);
    });
  });

  // =========================================================================
  // HUMAN DETECTION
  // =========================================================================
  describe('Human detection', () => {
    it('identifies normal browser as HUMAN', () => {
      const result = detectBot(botReq(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      ) as Request);
      expect(result.isBot).toBe(false);
      expect(result.category).toBe('HUMAN');
      expect(result.name).toBeNull();
      expect(result.confidence).toBeGreaterThan(0.5);
    });

    it('identifies Firefox as HUMAN', () => {
      const result = detectBot(botReq(
        'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0'
      ) as Request);
      expect(result.isBot).toBe(false);
      expect(result.category).toBe('HUMAN');
    });

    it('identifies Safari as HUMAN', () => {
      const result = detectBot(botReq(
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'
      ) as Request);
      expect(result.isBot).toBe(false);
      expect(result.category).toBe('HUMAN');
    });

    it('identifies mobile browser as HUMAN', () => {
      const result = detectBot(botReq(
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
      ) as Request);
      expect(result.isBot).toBe(false);
      expect(result.category).toBe('HUMAN');
    });
  });

  // =========================================================================
  // NO USER-AGENT
  // =========================================================================
  describe('Missing User-Agent', () => {
    it('flags missing UA as UNKNOWN bot', () => {
      const req = mockRequest({ headers: {} });
      const result = detectBot(req as Request);
      expect(result.isBot).toBe(true);
      expect(result.category).toBe('UNKNOWN');
      expect(result.confidence).toBeGreaterThanOrEqual(0.8);
      expect(result.signals).toContain('missing_user_agent');
    });

    it('flags empty UA as UNKNOWN bot', () => {
      const req = mockRequest({ headers: { 'user-agent': '' } });
      const result = detectBot(req as Request);
      expect(result.isBot).toBe(true);
      expect(result.category).toBe('UNKNOWN');
    });
  });

  // =========================================================================
  // BEHAVIORAL SIGNALS
  // =========================================================================
  describe('Behavioral signals', () => {
    it('detects missing accept headers', () => {
      const req = bareReq('SomeUnknownUA/1.0');
      const result = detectBot(req as Request);
      expect(result.signals).toContain('missing_accept');
      expect(result.signals).toContain('missing_accept_language');
      expect(result.signals).toContain('missing_accept_encoding');
    });

    it('flags unknown UA with 3+ missing headers as bot', () => {
      const req = bareReq('CustomApp/1.0');
      const result = detectBot(req as Request);
      // 3 missing headers: accept, accept-language, accept-encoding
      expect(result.isBot).toBe(true);
      expect(result.category).toBe('UNKNOWN');
      expect(result.confidence).toBeGreaterThan(0.6);
    });

    it('detects connection:close signal', () => {
      const req = botReq('SomeUA/1.0', { connection: 'close' });
      const result = detectBot(req as Request);
      expect(result.signals).toContain('connection_close');
    });

    it('lowers confidence with 1-2 missing headers but stays human', () => {
      // Has UA and accept, but missing accept-language and accept-encoding
      const req = mockRequest({
        headers: {
          'user-agent': 'NormalBrowser/1.0',
          'accept': 'text/html',
        },
      });
      const result = detectBot(req as Request);
      expect(result.isBot).toBe(false);
      expect(result.category).toBe('HUMAN');
      expect(result.confidence).toBeLessThan(1.0);
    });
  });

  // =========================================================================
  // CASE INSENSITIVITY
  // =========================================================================
  describe('Case insensitivity', () => {
    it('detects lowercase bot names', () => {
      const result = detectBot(botReq('googlebot/2.1') as Request);
      expect(result.isBot).toBe(true);
      expect(result.category).toBe('SEARCH_ENGINE');
    });

    it('detects mixed-case bot names', () => {
      const result = detectBot(botReq('GPTBOT/1.0') as Request);
      expect(result.isBot).toBe(true);
      expect(result.category).toBe('AI_CRAWLER');
    });
  });

  // =========================================================================
  // RESULT SHAPE
  // =========================================================================
  describe('Result structure', () => {
    it('returns all required fields', () => {
      const result = detectBot(botReq('Googlebot/2.1') as Request);
      expect(result).toHaveProperty('isBot');
      expect(result).toHaveProperty('category');
      expect(result).toHaveProperty('name');
      expect(result).toHaveProperty('confidence');
      expect(result).toHaveProperty('signals');
      expect(Array.isArray(result.signals)).toBe(true);
    });

    it('confidence is between 0 and 1', () => {
      const bots = ['Googlebot/2.1', 'curl/7.0', ''];
      for (const ua of bots) {
        const result = detectBot(botReq(ua) as Request);
        expect(result.confidence).toBeGreaterThanOrEqual(0);
        expect(result.confidence).toBeLessThanOrEqual(1);
      }
    });
  });
});

describe('botProtection middleware', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  function runMiddleware(ua: string, options?: BotProtectionOptions, extraHeaders?: Record<string, string>) {
    const middleware = botProtection(options);
    const req = botReq(ua, extraHeaders) as Request;
    const res = mockResponse();
    const next = vi.fn();
    middleware(req, res as Response, next);
    return { req, res, next };
  }

  // =========================================================================
  // DEFAULT BEHAVIOR
  // =========================================================================
  describe('Default config', () => {
    it('allows human traffic', () => {
      const { next } = runMiddleware('Mozilla/5.0 Chrome/120.0');
      expect(next).toHaveBeenCalled();
    });

    it('allows search engines by default', () => {
      const { next } = runMiddleware('Googlebot/2.1');
      expect(next).toHaveBeenCalled();
    });

    it('allows social bots by default', () => {
      const { next } = runMiddleware('Twitterbot/1.0');
      expect(next).toHaveBeenCalled();
    });

    it('allows monitoring bots by default', () => {
      const { next } = runMiddleware('UptimeRobot/2.0');
      expect(next).toHaveBeenCalled();
    });

    it('blocks AUTOMATED by default', () => {
      const { res, next } = runMiddleware('HeadlessChrome/90.0');
      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it('allows AI crawlers by default (not in deny list)', () => {
      const { next } = runMiddleware('GPTBot/1.0');
      expect(next).toHaveBeenCalled();
    });

    it('allows scrapers by default (not in deny list)', () => {
      const { next } = runMiddleware('curl/7.68.0');
      expect(next).toHaveBeenCalled();
    });
  });

  // =========================================================================
  // CUSTOM ALLOW/DENY
  // =========================================================================
  describe('Custom allow/deny', () => {
    it('blocks scrapers when added to deny list', () => {
      const { res, next } = runMiddleware('curl/7.68.0', {
        deny: ['SCRAPER', 'AUTOMATED'],
      });
      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it('blocks AI crawlers when denied', () => {
      const { res, next } = runMiddleware('GPTBot/1.0', {
        deny: ['AI_CRAWLER'],
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('allows automated tools when explicitly allowed', () => {
      const { next } = runMiddleware('HeadlessChrome/90.0', {
        allow: ['AUTOMATED', 'SEARCH_ENGINE'],
        deny: [],
      });
      expect(next).toHaveBeenCalled();
    });
  });

  // =========================================================================
  // DEFAULT ACTION
  // =========================================================================
  describe('defaultAction', () => {
    it('deny-by-default blocks uncategorized bots', () => {
      const { res, next } = runMiddleware('GPTBot/1.0', {
        allow: ['SEARCH_ENGINE'],
        deny: [],
        defaultAction: 'deny',
      });
      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it('deny-by-default still allows explicitly allowed categories', () => {
      const { next } = runMiddleware('Googlebot/2.1', {
        allow: ['SEARCH_ENGINE'],
        defaultAction: 'deny',
      });
      expect(next).toHaveBeenCalled();
    });
  });

  // =========================================================================
  // CUSTOM STATUS CODE AND MESSAGE
  // =========================================================================
  describe('Custom responses', () => {
    it('uses custom status code', () => {
      const { res } = runMiddleware('HeadlessChrome/90.0', {
        deny: ['AUTOMATED'],
        statusCode: 429,
      });
      expect(res.status).toHaveBeenCalledWith(429);
    });

    it('uses custom message', () => {
      const { res } = runMiddleware('HeadlessChrome/90.0', {
        deny: ['AUTOMATED'],
        message: 'Bots not welcome',
      });
      expect(res.json).toHaveBeenCalledWith({ error: 'Bots not welcome' });
    });
  });

  // =========================================================================
  // onDetected CALLBACK
  // =========================================================================
  describe('onDetected callback', () => {
    it('calls onDetected instead of default response', () => {
      const onDetected = vi.fn();
      const middleware = botProtection({
        deny: ['AUTOMATED'],
        onDetected,
      });
      const req = botReq('HeadlessChrome/90.0') as Request;
      const res = mockResponse();
      const next = vi.fn();
      middleware(req, res as Response, next);

      expect(onDetected).toHaveBeenCalledWith(req, res, expect.objectContaining({
        isBot: true,
        category: 'AUTOMATED',
      }));
      expect(next).not.toHaveBeenCalled();
    });

    it('calls onDetected on defaultAction deny', () => {
      const onDetected = vi.fn();
      const { next } = runMiddleware('curl/7.0', {
        allow: [],
        deny: [],
        defaultAction: 'deny',
        onDetected,
      });
      expect(onDetected).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // REQUEST AUGMENTATION
  // =========================================================================
  describe('Request augmentation', () => {
    it('attaches botDetection result to request', () => {
      const middleware = botProtection();
      const req = botReq('Googlebot/2.1') as Request;
      const res = mockResponse();
      const next = vi.fn();
      middleware(req, res as Response, next);

      const augmented = req as unknown as Record<string, unknown>;
      expect(augmented.botDetection).toBeDefined();
      const result = augmented.botDetection as BotDetectionResult;
      expect(result.isBot).toBe(true);
      expect(result.category).toBe('SEARCH_ENGINE');
    });
  });
});
