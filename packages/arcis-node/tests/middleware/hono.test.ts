/**
 * Hono adapter tests (sdk-vectors.md N3 / P2 #22).
 *
 * The shape mirrors the SvelteKit / Astro / Nuxt adapter tests because
 * Hono's middleware is also Web Fetch-native — the only differences are
 * the context surface (`c.req.raw`, `c.res`) and the `next()` calling
 * convention.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { arcisHono } from '../../src/middleware/hono';
import { _resetClientIpWarnings } from '../../src/utils/client-ip';

interface FakeCtx {
  req: { raw: Request };
  res: Response;
  env?: unknown;
}

/** `c.env` as @hono/node-server sets it: the Node request with its socket. */
function nodeEnv(remoteAddress: string): unknown {
  return { incoming: { socket: { remoteAddress } } };
}

function buildCtx(opts: {
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  env?: unknown;
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
  return { req: { raw: request }, res, env: opts.env };
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
    afterEach(() => {
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
      vi.unstubAllEnvs();
      _resetClientIpWarnings();
    });

    it('returns 429 + Retry-After once the cap is exceeded for a single IP', async () => {
      const handler = arcisHono({ rateLimit: { max: 2, windowMs: 60_000 } });
      const next = vi.fn();
      const hit = () => handler(buildCtx({ env: nodeEnv('203.0.113.5') }), async () => { next(); });

      expect(await hit()).toBeUndefined();
      expect(await hit()).toBeUndefined();
      const r3 = await hit();
      expect(r3).toBeInstanceOf(Response);
      expect((r3 as Response).status).toBe(429);
      expect((r3 as Response).headers.get('Retry-After')).toBeTruthy();
      expect(next).toHaveBeenCalledTimes(2); // not invoked on the 429
    });

    it('never trusts CF-Connecting-IP or X-Forwarded-For from a public peer', async () => {
      vi.spyOn(console, 'warn').mockImplementation(() => {});
      const handler = arcisHono({ rateLimit: { max: 2, windowMs: 60_000 } });
      const statuses: number[] = [];
      for (let i = 0; i < 5; i++) {
        const ctx = buildCtx({
          env: nodeEnv('203.0.113.5'),
          headers: { 'cf-connecting-ip': `198.51.100.${i}`, 'x-forwarded-for': `192.0.2.${i}` },
        });
        const r = await handler(ctx, passthroughNext(ctx));
        statuses.push(r ? (r as Response).status : 200);
      }
      expect(statuses).toEqual([200, 200, 429, 429, 429]);
    });

    it('does not trust CF-Connecting-IP off Cloudflare Workers (no peer)', async () => {
      vi.spyOn(console, 'warn').mockImplementation(() => {});
      vi.stubEnv('VERCEL', '');
      const handler = arcisHono({ rateLimit: { max: 1, windowMs: 60_000 } });
      const a = buildCtx({ headers: { 'cf-connecting-ip': '9.9.9.9' } });
      const b = buildCtx({ headers: { 'cf-connecting-ip': '8.8.8.8' } });
      expect(await handler(a, passthroughNext(a))).toBeUndefined();
      // Both share the unknown key: a forged header does not mint a bucket.
      expect(((await handler(b, passthroughNext(b))) as Response).status).toBe(429);
    });

    it('uses CF-Connecting-IP on Cloudflare Workers', async () => {
      vi.stubGlobal('navigator', { userAgent: 'Cloudflare-Workers' });
      const handler = arcisHono({ rateLimit: { max: 1, windowMs: 60_000 } });
      const a = buildCtx({ headers: { 'cf-connecting-ip': '9.9.9.9' } });
      const b = buildCtx({ headers: { 'cf-connecting-ip': '8.8.8.8' } });
      const a2 = buildCtx({ headers: { 'cf-connecting-ip': '9.9.9.9' } });
      expect(await handler(a, passthroughNext(a))).toBeUndefined();
      expect(await handler(b, passthroughNext(b))).toBeUndefined();
      expect(((await handler(a2, passthroughNext(a2))) as Response).status).toBe(429);
    });

    it('isolates rate-limit buckets per client IP behind a trusted private proxy', async () => {
      const handler = arcisHono({ rateLimit: { max: 1, windowMs: 60_000 } });
      const next = vi.fn();
      const a = buildCtx({ env: nodeEnv('10.0.0.2'), headers: { 'x-forwarded-for': '198.51.100.1' } });
      const b = buildCtx({ env: nodeEnv('10.0.0.2'), headers: { 'x-forwarded-for': '198.51.100.2' } });
      const a2 = buildCtx({ env: nodeEnv('10.0.0.2'), headers: { 'x-forwarded-for': '198.51.100.1' } });

      await handler(a, async () => { next(); });
      await handler(b, async () => { next(); });
      expect(next).toHaveBeenCalledTimes(2); // both first hits succeed
      expect(((await handler(a2, async () => { next(); })) as Response).status).toBe(429);
    });

    it('reads the peer from Bun (env.requestIP) and Deno (env.remoteAddr)', async () => {
      const handler = arcisHono({ rateLimit: { max: 1, windowMs: 60_000 } });
      const bun = { requestIP: () => ({ address: '203.0.113.7' }) };
      const deno = { remoteAddr: { hostname: '203.0.113.8' } };
      const c1 = buildCtx({ env: bun });
      const c2 = buildCtx({ env: deno });
      const c3 = buildCtx({ env: bun });
      expect(await handler(c1, passthroughNext(c1))).toBeUndefined();
      expect(await handler(c2, passthroughNext(c2))).toBeUndefined();
      expect(((await handler(c3, passthroughNext(c3))) as Response).status).toBe(429);
    });

    it('honors trustedProxies and getClientIp', async () => {
      const viaTrust = arcisHono({ trustedProxies: ['203.0.113.0/24'], rateLimit: { max: 1, windowMs: 60_000 } });
      const t1 = buildCtx({ env: nodeEnv('203.0.113.5'), headers: { 'x-forwarded-for': '198.51.100.1' } });
      const t2 = buildCtx({ env: nodeEnv('203.0.113.5'), headers: { 'x-forwarded-for': '198.51.100.2' } });
      expect(await viaTrust(t1, passthroughNext(t1))).toBeUndefined();
      expect(await viaTrust(t2, passthroughNext(t2))).toBeUndefined();

      const viaResolver = arcisHono({
        getClientIp: (req) => req.headers.get('x-client'),
        rateLimit: { max: 1, windowMs: 60_000 },
      });
      const r1 = buildCtx({ headers: { 'x-client': '198.51.100.3' } });
      const r2 = buildCtx({ headers: { 'x-client': '198.51.100.4' } });
      const r3 = buildCtx({ headers: { 'x-client': '198.51.100.3' } });
      expect(await viaResolver(r1, passthroughNext(r1))).toBeUndefined();
      expect(await viaResolver(r2, passthroughNext(r2))).toBeUndefined();
      expect(((await viaResolver(r3, passthroughNext(r3))) as Response).status).toBe(429);
    });

    it('disables rate limiting entirely when rateLimit: false', async () => {
      const handler = arcisHono({ rateLimit: false });
      const next = vi.fn();
      // 50 hits from the same IP — all should pass.
      for (let i = 0; i < 50; i++) {
        const c = buildCtx({ env: nodeEnv('203.0.113.5') });
        await handler(c, async () => { next(); });
      }
      expect(next).toHaveBeenCalledTimes(50);
    });

    it('rejects invalid limiter configuration at construction', () => {
      expect(() => arcisHono({ rateLimit: { windowMs: 0 } })).toThrow(RangeError);
      expect(() => arcisHono({ rateLimit: { max: -1 } })).toThrow(RangeError);
      expect(() => arcisHono({ trustedProxies: ['not-a-cidr'] })).toThrow(TypeError);
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
