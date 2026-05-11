/**
 * Next.js Adapter Tests
 * Tests for src/middleware/nextjs.ts (arcisMiddleware + arcisProtect)
 */

import { describe, it, expect, vi } from 'vitest';
import { arcisMiddleware, arcisProtect } from '../../src/middleware/nextjs';

interface BuildOpts {
  ip?: string;
  url?: string;
  method?: string;
  headers?: Record<string, string>;
}

function buildRequest(opts: BuildOpts = {}): Request {
  const url = opts.url ?? 'https://example.test/';
  const headers = new Headers(opts.headers ?? {});
  // x-forwarded-for is the canonical IP-key carrier on Vercel + Cloudflare;
  // tests use it to drive rate-limit keys without depending on platform IP
  // accessors that the adapter intentionally doesn't reach for.
  if (opts.ip && !headers.has('x-forwarded-for')) {
    headers.set('x-forwarded-for', opts.ip);
  }
  return new Request(url, { method: opts.method ?? 'GET', headers });
}

describe('arcisMiddleware (Edge Middleware factory)', () => {
  describe('Allow path', () => {
    it('returns undefined when nothing blocks', async () => {
      const middleware = arcisMiddleware();
      const result = await middleware(buildRequest());
      expect(result).toBeUndefined();
    });

    it('returns undefined when rate limit and bot are both disabled', async () => {
      const middleware = arcisMiddleware({ rateLimit: false, bot: false });
      // Same IP hammered, no limiter engaged → always undefined.
      for (let i = 0; i < 50; i++) {
        const result = await middleware(buildRequest({ ip: '1.2.3.4' }));
        expect(result).toBeUndefined();
      }
    });
  });

  describe('Rate limiting', () => {
    it('passes requests under the limit through', async () => {
      const middleware = arcisMiddleware({ rateLimit: { max: 3, windowMs: 60_000 } });
      for (let i = 0; i < 3; i++) {
        const result = await middleware(buildRequest({ ip: '1.2.3.4' }));
        expect(result).toBeUndefined();
      }
    });

    it('returns 429 when the limit is exceeded for the same IP', async () => {
      const middleware = arcisMiddleware({ rateLimit: { max: 2, windowMs: 60_000 } });
      await middleware(buildRequest({ ip: '1.2.3.4' }));
      await middleware(buildRequest({ ip: '1.2.3.4' }));
      const blocked = await middleware(buildRequest({ ip: '1.2.3.4' }));
      expect(blocked).toBeInstanceOf(Response);
      expect(blocked!.status).toBe(429);
      expect(blocked!.headers.get('Retry-After')).toBeTruthy();
      expect(blocked!.headers.get('X-RateLimit-Limit')).toBe('2');
      expect(blocked!.headers.get('X-RateLimit-Remaining')).toBe('0');
    });

    it('rate-limits per-IP, not globally', async () => {
      // Different IPs should each get their own counter; pin against a
      // regression where a missing key (e.g. clientIpOf returning a
      // shared 'unknown' for both) would conflate counters across users.
      const middleware = arcisMiddleware({ rateLimit: { max: 1, windowMs: 60_000 } });
      const aliceFirst = await middleware(buildRequest({ ip: '1.1.1.1' }));
      const bobFirst = await middleware(buildRequest({ ip: '2.2.2.2' }));
      expect(aliceFirst).toBeUndefined();
      expect(bobFirst).toBeUndefined();
      const aliceSecond = await middleware(buildRequest({ ip: '1.1.1.1' }));
      expect(aliceSecond).toBeInstanceOf(Response);
      expect(aliceSecond!.status).toBe(429);
    });

    it('honors x-real-ip when x-forwarded-for is absent', async () => {
      const middleware = arcisMiddleware({ rateLimit: { max: 1, windowMs: 60_000 } });
      await middleware(buildRequest({ headers: { 'x-real-ip': '9.9.9.9' } }));
      const blocked = await middleware(buildRequest({ headers: { 'x-real-ip': '9.9.9.9' } }));
      expect(blocked!.status).toBe(429);
    });

    it('honors cf-connecting-ip when other IP headers are absent', async () => {
      // Cloudflare sets only cf-connecting-ip in some pass-through paths.
      const middleware = arcisMiddleware({ rateLimit: { max: 1, windowMs: 60_000 } });
      await middleware(buildRequest({ headers: { 'cf-connecting-ip': '8.8.8.8' } }));
      const blocked = await middleware(buildRequest({ headers: { 'cf-connecting-ip': '8.8.8.8' } }));
      expect(blocked!.status).toBe(429);
    });

    it('falls back to the literal "unknown" key when no IP header is present', async () => {
      // Two no-IP requests rate-limit against each other under the same
      // 'unknown' bucket. This is the documented fallback behavior.
      const middleware = arcisMiddleware({ rateLimit: { max: 1, windowMs: 60_000 } });
      await middleware(buildRequest());
      const blocked = await middleware(buildRequest());
      expect(blocked!.status).toBe(429);
    });

    it('exposes count + reset in the 429 body', async () => {
      const middleware = arcisMiddleware({ rateLimit: { max: 1, windowMs: 60_000 } });
      await middleware(buildRequest({ ip: '5.5.5.5' }));
      const blocked = await middleware(buildRequest({ ip: '5.5.5.5' }));
      const body = await blocked!.json();
      expect(body).toMatchObject({
        error: expect.stringContaining('Too many requests'),
        retryAfter: expect.any(Number),
      });
    });
  });

  describe('Bot detection', () => {
    it('blocks denied bot categories with 403 by default', async () => {
      const middleware = arcisMiddleware({
        rateLimit: false,
        bot: { deny: ['AUTOMATED'] },
      });
      const blocked = await middleware(
        buildRequest({
          headers: { 'user-agent': 'HeadlessChrome/120.0.0.0' },
        }),
      );
      expect(blocked).toBeInstanceOf(Response);
      expect(blocked!.status).toBe(403);
    });

    it('passes browsers through when bot detection is enabled', async () => {
      const middleware = arcisMiddleware({ rateLimit: false, bot: true });
      const result = await middleware(
        buildRequest({
          headers: {
            'user-agent':
              'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            accept: 'text/html,application/xhtml+xml',
            'accept-language': 'en-US,en;q=0.9',
            'accept-encoding': 'gzip, deflate, br',
          },
        }),
      );
      expect(result).toBeUndefined();
    });

    it('honors a custom statusCode + message', async () => {
      const middleware = arcisMiddleware({
        rateLimit: false,
        bot: { deny: ['AUTOMATED'], statusCode: 418, message: 'Bot teapot' },
      });
      const blocked = await middleware(
        buildRequest({ headers: { 'user-agent': 'HeadlessChrome/120.0.0.0' } }),
      );
      expect(blocked!.status).toBe(418);
      const body = await blocked!.json();
      expect(body).toMatchObject({ error: 'Bot teapot' });
    });
  });

  describe('Allocation isolation', () => {
    it('two factory calls have independent rate-limit counters', async () => {
      // Pins the "build pipeline once per factory call" contract — a
      // future refactor that accidentally shared the limiter store would
      // make tests in different files leak state into each other.
      const a = arcisMiddleware({ rateLimit: { max: 1, windowMs: 60_000 } });
      const b = arcisMiddleware({ rateLimit: { max: 1, windowMs: 60_000 } });
      await a(buildRequest({ ip: '1.1.1.1' }));
      const aBlocked = await a(buildRequest({ ip: '1.1.1.1' }));
      const bAllowed = await b(buildRequest({ ip: '1.1.1.1' }));
      expect(aBlocked!.status).toBe(429);
      expect(bAllowed).toBeUndefined();
    });
  });
});

describe('arcisProtect (App Router route handler wrapper)', () => {
  describe('Allow path', () => {
    it('calls the handler and returns its response', async () => {
      const handler = vi.fn(async () => Response.json({ ok: true }));
      const protect = arcisProtect(handler);
      const response = await protect(buildRequest());
      expect(handler).toHaveBeenCalledTimes(1);
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body).toMatchObject({ ok: true });
    });

    it('forwards extra args (params shape) to the handler', async () => {
      // App Router passes `(request, { params })` for dynamic routes.
      // The wrapper's variadic spread must preserve that.
      const handler = vi.fn(
        async (_req: Request, ctx: { params: { id: string } }) => Response.json(ctx.params),
      );
      const protect = arcisProtect(handler);
      const response = await protect(buildRequest(), { params: { id: '42' } });
      const body = await response.json();
      expect(body).toMatchObject({ id: '42' });
      expect(handler).toHaveBeenCalledTimes(1);
    });

    it('does not call the handler when rate-limited', async () => {
      const handler = vi.fn(async () => Response.json({ ok: true }));
      const protect = arcisProtect(handler, { rateLimit: { max: 1, windowMs: 60_000 } });
      await protect(buildRequest({ ip: '1.1.1.1' }));
      const blocked = await protect(buildRequest({ ip: '1.1.1.1' }));
      expect(blocked.status).toBe(429);
      expect(handler).toHaveBeenCalledTimes(1); // only the first allow call
    });

    it('does not call the handler when bot-denied', async () => {
      const handler = vi.fn(async () => Response.json({ ok: true }));
      const protect = arcisProtect(handler, {
        rateLimit: false,
        bot: { deny: ['AUTOMATED'] },
      });
      const blocked = await protect(
        buildRequest({ headers: { 'user-agent': 'HeadlessChrome/120.0.0.0' } }),
      );
      expect(blocked.status).toBe(403);
      expect(handler).not.toHaveBeenCalled();
    });
  });

  describe('Security headers', () => {
    it('sets standard security headers on the handler response by default', async () => {
      const protect = arcisProtect(async () => Response.json({ ok: true }));
      const response = await protect(buildRequest({ url: 'https://example.test/api' }));
      expect(response.headers.get('Content-Security-Policy')).toBeTruthy();
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
      expect(response.headers.get('X-Frame-Options')).toBe('DENY');
      expect(response.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    });

    it('sets HSTS only over HTTPS', async () => {
      const protect = arcisProtect(async () => new Response('ok'));
      const httpsResp = await protect(buildRequest({ url: 'https://example.test/' }));
      expect(httpsResp.headers.get('Strict-Transport-Security')).toMatch(/max-age=/);

      const httpResp = await protect(buildRequest({ url: 'http://example.test/' }));
      expect(httpResp.headers.get('Strict-Transport-Security')).toBeNull();
    });

    it('honors x-forwarded-proto: https for HSTS', async () => {
      const protect = arcisProtect(async () => new Response('ok'));
      const response = await protect(
        buildRequest({
          url: 'http://example.test/',
          headers: { 'x-forwarded-proto': 'https' },
        }),
      );
      expect(response.headers.get('Strict-Transport-Security')).toMatch(/max-age=/);
    });

    it('does not set headers when headers: false', async () => {
      const protect = arcisProtect(async () => new Response('ok'), { headers: false });
      const response = await protect(buildRequest({ url: 'https://example.test/' }));
      expect(response.headers.get('Content-Security-Policy')).toBeNull();
      expect(response.headers.get('X-Content-Type-Options')).toBeNull();
    });

    it('respects custom headers config (frameOptions: SAMEORIGIN)', async () => {
      const protect = arcisProtect(async () => new Response('ok'), {
        headers: { frameOptions: 'SAMEORIGIN' },
      });
      const response = await protect(buildRequest({ url: 'https://example.test/' }));
      expect(response.headers.get('X-Frame-Options')).toBe('SAMEORIGIN');
    });

    it('removes X-Powered-By if the handler set it', async () => {
      const protect = arcisProtect(
        async () =>
          new Response('ok', { headers: { 'X-Powered-By': 'Next.js' } }),
      );
      const response = await protect(buildRequest({ url: 'https://example.test/' }));
      expect(response.headers.get('X-Powered-By')).toBeNull();
    });

  });
});
