/**
 * Hono adapter tests (sdk-vectors.md N3 / P2 #22).
 *
 * The shape mirrors the SvelteKit / Astro / Nuxt adapter tests because
 * Hono's middleware is also Web Fetch-native — the only differences are
 * the context surface (`c.req.raw`, `c.res`) and the `next()` calling
 * convention.
 */

import { describe, it, expect, vi } from 'vitest';
import { arcisHono } from '../../src/middleware/hono';

interface FakeCtx {
  req: { raw: Request };
  res: Response;
}

function buildCtx(opts: {
  url?: string;
  method?: string;
  headers?: Record<string, string>;
} = {}): FakeCtx {
  const url = opts.url ?? 'https://example.test/';
  const request = new Request(url, {
    method: opts.method ?? 'GET',
    headers: new Headers(opts.headers ?? {}),
  });
  // Default downstream response — middleware tests overwrite when they
  // care about the body.
  const res = new Response('ok', {
    status: 200,
    headers: { 'Content-Type': 'text/plain' },
  });
  return { req: { raw: request }, res };
}

function passthroughNext(ctx: FakeCtx, body = 'ok', status = 200): () => Promise<void> {
  return async () => {
    ctx.res = new Response(body, {
      status,
      headers: { 'Content-Type': 'text/plain' },
    });
  };
}

describe('arcisHono', () => {
  describe('Security headers', () => {
    it('sets the standard security headers on c.res by default', async () => {
      const handler = arcisHono();
      const ctx = buildCtx();
      await handler(ctx, passthroughNext(ctx));
      expect(ctx.res.headers.get('Content-Security-Policy')).toBeTruthy();
      expect(ctx.res.headers.get('X-Content-Type-Options')).toBe('nosniff');
      expect(ctx.res.headers.get('X-Frame-Options')).toBe('DENY');
      expect(ctx.res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
      expect(ctx.res.headers.get('Cross-Origin-Opener-Policy')).toBe('same-origin');
      expect(ctx.res.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('none');
    });

    it('sets HSTS only over HTTPS', async () => {
      const handler = arcisHono();
      const httpsCtx = buildCtx({ url: 'https://example.test/' });
      await handler(httpsCtx, passthroughNext(httpsCtx));
      expect(httpsCtx.res.headers.get('Strict-Transport-Security')).toContain('max-age=');

      const httpCtx = buildCtx({ url: 'http://example.test/' });
      await handler(httpCtx, passthroughNext(httpCtx));
      expect(httpCtx.res.headers.get('Strict-Transport-Security')).toBeNull();
    });

    it('honours x-forwarded-proto: https for HSTS gating', async () => {
      const handler = arcisHono();
      const ctx = buildCtx({
        url: 'http://internal.app/',
        headers: { 'x-forwarded-proto': 'https' },
      });
      await handler(ctx, passthroughNext(ctx));
      expect(ctx.res.headers.get('Strict-Transport-Security')).toContain('max-age=');
    });

    it('strips X-Powered-By', async () => {
      const handler = arcisHono();
      const ctx = buildCtx();
      const nextFn = async () => {
        ctx.res = new Response('ok', {
          status: 200,
          headers: { 'X-Powered-By': 'Hono' },
        });
      };
      await handler(ctx, nextFn);
      expect(ctx.res.headers.get('X-Powered-By')).toBeNull();
    });

    it('disables headers entirely when headers: false', async () => {
      const handler = arcisHono({ headers: false });
      const ctx = buildCtx();
      await handler(ctx, passthroughNext(ctx));
      expect(ctx.res.headers.get('Content-Security-Policy')).toBeNull();
      expect(ctx.res.headers.get('X-Content-Type-Options')).toBeNull();
    });

    it('honours a custom CSP string', async () => {
      const handler = arcisHono({
        headers: { contentSecurityPolicy: "default-src 'self'; img-src cdn.example" },
      });
      const ctx = buildCtx();
      await handler(ctx, passthroughNext(ctx));
      expect(ctx.res.headers.get('Content-Security-Policy')).toBe(
        "default-src 'self'; img-src cdn.example",
      );
    });
  });

  describe('Rate limiting', () => {
    it('returns 429 + Retry-After once the cap is exceeded for a single IP', async () => {
      const handler = arcisHono({ rateLimit: { max: 2, windowMs: 60_000 } });
      const next = vi.fn();

      const c1 = buildCtx({ headers: { 'cf-connecting-ip': '1.2.3.4' } });
      const r1 = await handler(c1, async () => {
        next();
      });
      expect(r1).toBeUndefined();
      expect(next).toHaveBeenCalledTimes(1);

      const c2 = buildCtx({ headers: { 'cf-connecting-ip': '1.2.3.4' } });
      const r2 = await handler(c2, async () => {
        next();
      });
      expect(r2).toBeUndefined();
      expect(next).toHaveBeenCalledTimes(2);

      const c3 = buildCtx({ headers: { 'cf-connecting-ip': '1.2.3.4' } });
      const r3 = await handler(c3, async () => {
        next();
      });
      expect(r3).toBeInstanceOf(Response);
      expect((r3 as Response).status).toBe(429);
      expect((r3 as Response).headers.get('Retry-After')).toBeTruthy();
      expect(next).toHaveBeenCalledTimes(2); // not invoked on the 429
    });

    it('uses cf-connecting-ip > x-forwarded-for > x-real-ip in that order', async () => {
      const handler = arcisHono({ rateLimit: { max: 1, windowMs: 60_000 } });
      const next = vi.fn();

      // CF wins.
      const c1 = buildCtx({
        headers: {
          'cf-connecting-ip': '9.9.9.9',
          'x-forwarded-for': '1.1.1.1',
          'x-real-ip': '2.2.2.2',
        },
      });
      await handler(c1, async () => {
        next();
      });

      // Same CF — second hit should 429.
      const c2 = buildCtx({
        headers: {
          'cf-connecting-ip': '9.9.9.9',
          'x-forwarded-for': '8.8.8.8',
        },
      });
      const r2 = await handler(c2, async () => {
        next();
      });
      expect((r2 as Response).status).toBe(429);
    });

    it('isolates rate-limit buckets per client IP', async () => {
      const handler = arcisHono({ rateLimit: { max: 1, windowMs: 60_000 } });
      const next = vi.fn();

      const a = buildCtx({ headers: { 'x-forwarded-for': '1.1.1.1' } });
      const b = buildCtx({ headers: { 'x-forwarded-for': '2.2.2.2' } });

      await handler(a, async () => { next(); });
      await handler(b, async () => { next(); });
      expect(next).toHaveBeenCalledTimes(2); // both first hits succeed
    });

    it('disables rate limiting entirely when rateLimit: false', async () => {
      const handler = arcisHono({ rateLimit: false });
      const next = vi.fn();
      // 50 hits from the same IP — all should pass.
      for (let i = 0; i < 50; i++) {
        const c = buildCtx({ headers: { 'cf-connecting-ip': '5.5.5.5' } });
        await handler(c, async () => { next(); });
      }
      expect(next).toHaveBeenCalledTimes(50);
    });
  });

  describe('Bot detection', () => {
    it('passes through when bot detection is off', async () => {
      const handler = arcisHono(); // bot disabled by default
      const next = vi.fn();
      const ctx = buildCtx({ headers: { 'user-agent': 'curl/7.85.0' } });
      const r = await handler(ctx, async () => { next(); });
      expect(r).toBeUndefined();
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('allows search-engine bots through when bot is enabled with defaults', async () => {
      const handler = arcisHono({ bot: true });
      const next = vi.fn();
      const ctx = buildCtx({
        headers: { 'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' },
      });
      const r = await handler(ctx, async () => { next(); });
      expect(r).toBeUndefined();
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('blocks AUTOMATED bots with 403 by default', async () => {
      const handler = arcisHono({ bot: true });
      const next = vi.fn();
      const ctx = buildCtx({
        headers: { 'user-agent': 'HeadlessChrome/120.0.0.0 Safari/537.36' },
      });
      const r = await handler(ctx, async () => { next(); });
      expect(r).toBeInstanceOf(Response);
      expect((r as Response).status).toBe(403);
      expect(next).not.toHaveBeenCalled();
    });

    it('honours a custom statusCode + message', async () => {
      const handler = arcisHono({
        bot: { statusCode: 451, message: 'Unavailable for legal reasons.' },
      });
      const next = vi.fn();
      const ctx = buildCtx({
        headers: { 'user-agent': 'HeadlessChrome/120.0.0.0' },
      });
      const r = await handler(ctx, async () => { next(); });
      expect((r as Response).status).toBe(451);
      const body = await (r as Response).json();
      expect(body.error).toBe('Unavailable for legal reasons.');
    });
  });

  describe('Edge runtime — Workers / Deno smoke', () => {
    it('does not throw when request.url is a typical Workers URL with non-default port', async () => {
      const handler = arcisHono({ rateLimit: { max: 100, windowMs: 60_000 } });
      const ctx = buildCtx({ url: 'https://my-worker.workers.dev:443/path?x=1' });
      const r = await handler(ctx, passthroughNext(ctx));
      expect(r).toBeUndefined();
      expect(ctx.res.status).toBe(200);
    });

    it('does not throw when no client-IP header is present (uses unknown bucket)', async () => {
      const handler = arcisHono({ rateLimit: { max: 1, windowMs: 60_000 } });
      const next = vi.fn();
      const ctx = buildCtx();
      const r = await handler(ctx, async () => { next(); });
      expect(r).toBeUndefined();
      expect(next).toHaveBeenCalledTimes(1);
    });
  });
});
