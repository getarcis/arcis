/**
 * Koa Adapter Tests
 * Tests for src/middleware/koa.ts (arcisKoa)
 *
 * Drives the middleware through a duck-typed KoaContext so tests don't
 * depend on a real Koa install. The duck contracts the adapter exposes
 * are exactly what these tests assert against.
 */

import { describe, it, expect, vi } from 'vitest';
import {
  arcisKoa,
  type KoaContextLike,
  type KoaNext,
  type KoaRequestLike,
} from '../../src/middleware/koa';

interface BuildCtxOpts {
  ip?: string;
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  socketRemoteAddress?: string;
  /** When set, ctx.ip is left undefined and ctx.request.ip is used. */
  requestIp?: string;
}

function buildCtx(opts: BuildCtxOpts = {}): KoaContextLike {
  const headers: Record<string, string | string[] | undefined> = { ...(opts.headers ?? {}) };
  const request: KoaRequestLike = {
    headers,
    url: opts.url ?? '/',
    method: opts.method ?? 'GET',
    ip: opts.requestIp,
    socket: { remoteAddress: opts.socketRemoteAddress },
  };
  const setHeaders: Record<string, string> = {};
  const ctx: KoaContextLike = {
    request,
    response: {
      status: 200,
      body: undefined,
      set(name, value) {
        setHeaders[name] = value;
      },
    },
    ip: opts.ip,
    set(name, value) {
      setHeaders[name] = value;
      ctx.response.set(name, value);
    },
    status: 200,
    body: undefined,
  };
  // Expose the headers map via a marker so tests can read it without
  // breaking the duck-typed contract.
  (ctx as unknown as { __setHeaders: Record<string, string> }).__setHeaders = setHeaders;
  return ctx;
}

function getHeaders(ctx: KoaContextLike): Record<string, string> {
  return (ctx as unknown as { __setHeaders: Record<string, string> }).__setHeaders;
}

const passThroughNext: KoaNext = async () => undefined;

describe('arcisKoa (Koa middleware)', () => {
  describe('Allow path', () => {
    it('calls next() under the rate limit', async () => {
      const middleware = arcisKoa({ rateLimit: { max: 3, windowMs: 60_000 } });
      const next = vi.fn(passThroughNext);
      const ctx = buildCtx({ ip: '1.2.3.4' });
      await middleware(ctx, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(ctx.status).toBe(200); // unchanged from default
      const headers = getHeaders(ctx);
      expect(headers['X-RateLimit-Limit']).toBe('3');
      expect(headers['X-RateLimit-Remaining']).toBe('2');
    });
  });

  describe('Rate limiting', () => {
    it('returns 429 + Retry-After when the limit is exceeded for the same IP', async () => {
      const middleware = arcisKoa({ rateLimit: { max: 2, windowMs: 60_000 } });
      const next = vi.fn(passThroughNext);

      const c1 = buildCtx({ ip: '1.2.3.4' });
      await middleware(c1, next);
      const c2 = buildCtx({ ip: '1.2.3.4' });
      await middleware(c2, next);
      const c3 = buildCtx({ ip: '1.2.3.4' });
      await middleware(c3, next);

      expect(c3.status).toBe(429);
      expect(c3.body).toMatchObject({
        error: expect.stringContaining('Too many requests'),
        retryAfter: expect.any(Number),
      });
      const c3headers = getHeaders(c3);
      expect(c3headers['Retry-After']).toBeTruthy();
      expect(c3headers['X-RateLimit-Remaining']).toBe('0');
      // Handler must not have been invoked on the third request — the
      // deny path returns BEFORE awaiting next(). Pin: next called twice
      // (once per allow), not three times.
      expect(next).toHaveBeenCalledTimes(2);
    });

    it('rate-limits per-IP, not globally', async () => {
      const middleware = arcisKoa({ rateLimit: { max: 1, windowMs: 60_000 } });
      const next = vi.fn(passThroughNext);

      const alice1 = buildCtx({ ip: '1.1.1.1' });
      await middleware(alice1, next);
      const bob1 = buildCtx({ ip: '2.2.2.2' });
      await middleware(bob1, next);
      expect(alice1.status).toBe(200);
      expect(bob1.status).toBe(200);

      const alice2 = buildCtx({ ip: '1.1.1.1' });
      await middleware(alice2, next);
      expect(alice2.status).toBe(429);
    });

    it('honors ctx.request.ip when ctx.ip is absent', async () => {
      // Real Koa exposes ctx.ip as a getter delegating to ctx.request.ip;
      // the duck contract treats them as separate fields so users mocking
      // either get the same behavior.
      const middleware = arcisKoa({ rateLimit: { max: 1, windowMs: 60_000 } });
      const next = vi.fn(passThroughNext);

      const c1 = buildCtx({ requestIp: '7.7.7.7' });
      await middleware(c1, next);
      const c2 = buildCtx({ requestIp: '7.7.7.7' });
      await middleware(c2, next);
      expect(c1.status).toBe(200);
      expect(c2.status).toBe(429);
    });

    it('falls back to X-Forwarded-For when neither ctx.ip nor ctx.request.ip is set', async () => {
      const middleware = arcisKoa({ rateLimit: { max: 1, windowMs: 60_000 } });
      const next = vi.fn(passThroughNext);

      const c1 = buildCtx({ headers: { 'x-forwarded-for': '9.9.9.9, 1.1.1.1' } });
      await middleware(c1, next);
      const c2 = buildCtx({ headers: { 'x-forwarded-for': '9.9.9.9, 1.1.1.1' } });
      await middleware(c2, next);
      expect(c2.status).toBe(429);
    });

    it('falls back to socket.remoteAddress when no IP info is available', async () => {
      const middleware = arcisKoa({ rateLimit: { max: 1, windowMs: 60_000 } });
      const next = vi.fn(passThroughNext);

      const c1 = buildCtx({ socketRemoteAddress: '5.5.5.5' });
      await middleware(c1, next);
      const c2 = buildCtx({ socketRemoteAddress: '5.5.5.5' });
      await middleware(c2, next);
      expect(c2.status).toBe(429);
    });

    it('does not engage the limiter when rateLimit: false', async () => {
      const middleware = arcisKoa({ rateLimit: false });
      const next = vi.fn(passThroughNext);

      // Hammer past any reasonable limit; nothing should ever 429.
      for (let i = 0; i < 50; i++) {
        const ctx = buildCtx({ ip: '1.1.1.1' });
        await middleware(ctx, next);
        expect(ctx.status).toBe(200);
      }
      expect(next).toHaveBeenCalledTimes(50);
    });
  });

  describe('Bot detection', () => {
    it('blocks denied bot categories with 403 by default', async () => {
      const middleware = arcisKoa({
        rateLimit: false,
        bot: { deny: ['AUTOMATED'] },
      });
      const next = vi.fn(passThroughNext);

      const ctx = buildCtx({ headers: { 'user-agent': 'HeadlessChrome/120.0.0.0' } });
      await middleware(ctx, next);
      expect(ctx.status).toBe(403);
      expect(next).not.toHaveBeenCalled();
    });

    it('passes browsers through when bot: true', async () => {
      const middleware = arcisKoa({ rateLimit: false, bot: true });
      const next = vi.fn(passThroughNext);

      const ctx = buildCtx({
        headers: {
          'user-agent':
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
          accept: 'text/html,application/xhtml+xml',
          'accept-language': 'en-US,en;q=0.9',
          'accept-encoding': 'gzip, deflate, br',
        },
      });
      await middleware(ctx, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(ctx.status).toBe(200);
    });

    it('honors a custom statusCode + message', async () => {
      const middleware = arcisKoa({
        rateLimit: false,
        bot: { deny: ['AUTOMATED'], statusCode: 418, message: 'Bot teapot' },
      });
      const next = vi.fn(passThroughNext);

      const ctx = buildCtx({ headers: { 'user-agent': 'HeadlessChrome/120.0.0.0' } });
      await middleware(ctx, next);
      expect(ctx.status).toBe(418);
      expect(ctx.body).toMatchObject({ error: 'Bot teapot' });
    });
  });

  describe('Security headers', () => {
    it('sets the standard headers after next() resolves', async () => {
      const middleware = arcisKoa();
      const ctx = buildCtx();
      await middleware(ctx, passThroughNext);

      const headers = getHeaders(ctx);
      expect(headers['Content-Security-Policy']).toBeTruthy();
      expect(headers['X-Content-Type-Options']).toBe('nosniff');
      expect(headers['X-Frame-Options']).toBe('DENY');
      expect(headers['Referrer-Policy']).toBe('strict-origin-when-cross-origin');
      expect(headers['X-Permitted-Cross-Domain-Policies']).toBe('none');
    });

    it('does not set headers when headers: false', async () => {
      const middleware = arcisKoa({ headers: false });
      const ctx = buildCtx();
      await middleware(ctx, passThroughNext);

      const headers = getHeaders(ctx);
      expect(headers['Content-Security-Policy']).toBeUndefined();
      expect(headers['X-Frame-Options']).toBeUndefined();
    });

    it('respects custom headers config (frameOptions: SAMEORIGIN)', async () => {
      const middleware = arcisKoa({ headers: { frameOptions: 'SAMEORIGIN' } });
      const ctx = buildCtx();
      await middleware(ctx, passThroughNext);

      expect(getHeaders(ctx)['X-Frame-Options']).toBe('SAMEORIGIN');
    });

    it('sets HSTS only when X-Forwarded-Proto: https is present', async () => {
      const middleware = arcisKoa();

      const httpCtx = buildCtx();
      await middleware(httpCtx, passThroughNext);
      expect(getHeaders(httpCtx)['Strict-Transport-Security']).toBeUndefined();

      const httpsCtx = buildCtx({ headers: { 'x-forwarded-proto': 'https' } });
      await middleware(httpsCtx, passThroughNext);
      expect(getHeaders(httpsCtx)['Strict-Transport-Security']).toMatch(/max-age=/);
    });

    it('does NOT set headers when the deny path short-circuits', async () => {
      // On 429 / 403, the middleware returns BEFORE the post-handler
      // header pass. Pin: a deny response should not get the security
      // header set (those would still be valuable but landing them
      // requires a wrapper similar to Fastify's onSend hook — out of
      // scope for v1).
      const middleware = arcisKoa({ rateLimit: { max: 1, windowMs: 60_000 } });
      const next = vi.fn(passThroughNext);

      // Burn the limit
      await middleware(buildCtx({ ip: '1.1.1.1' }), next);
      const denied = buildCtx({ ip: '1.1.1.1' });
      await middleware(denied, next);
      expect(denied.status).toBe(429);
      // Limit headers ARE set (rate-limit path); CSP is NOT.
      const headers = getHeaders(denied);
      expect(headers['X-RateLimit-Limit']).toBe('1');
      expect(headers['Content-Security-Policy']).toBeUndefined();
    });
  });

  describe('Allocation isolation', () => {
    it('two middleware instances have independent rate-limit counters', async () => {
      const a = arcisKoa({ rateLimit: { max: 1, windowMs: 60_000 } });
      const b = arcisKoa({ rateLimit: { max: 1, windowMs: 60_000 } });
      const next = vi.fn(passThroughNext);

      await a(buildCtx({ ip: '1.1.1.1' }), next);
      const aBlocked = buildCtx({ ip: '1.1.1.1' });
      await a(aBlocked, next);
      const bAllowed = buildCtx({ ip: '1.1.1.1' });
      await b(bAllowed, next);

      expect(aBlocked.status).toBe(429);
      expect(bAllowed.status).toBe(200);
    });
  });
});
