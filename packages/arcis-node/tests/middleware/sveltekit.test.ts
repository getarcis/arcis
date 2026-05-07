/**
 * SvelteKit Adapter Tests
 * Tests for src/middleware/sveltekit.ts (arcisHandle factory)
 */

import { describe, it, expect, vi } from 'vitest';
import { arcisHandle, type SvelteKitRequestEvent } from '../../src/middleware/sveltekit';

interface BuildOpts {
  ip?: string;
  url?: string;
  method?: string;
  headers?: Record<string, string>;
}

function buildEvent(opts: BuildOpts = {}): SvelteKitRequestEvent {
  const url = new URL(opts.url ?? 'https://example.test/');
  const headers = new Headers(opts.headers ?? {});
  return {
    request: new Request(url.toString(), { method: opts.method ?? 'GET', headers }),
    url,
    cookies: {
      get: () => undefined,
      set: () => {},
      delete: () => {},
    },
    getClientAddress: () => opts.ip ?? '127.0.0.1',
  };
}

function passthroughResolver(): (event: SvelteKitRequestEvent) => Promise<Response> {
  return async () => new Response('ok', { status: 200, headers: { 'Content-Type': 'text/plain' } });
}

describe('arcisHandle (SvelteKit Handle factory)', () => {
  describe('Security headers', () => {
    it('sets the standard security headers on the response by default', async () => {
      const handle = arcisHandle();
      const response = await handle({ event: buildEvent(), resolve: passthroughResolver() });

      expect(response.headers.get('Content-Security-Policy')).toBeTruthy();
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
      expect(response.headers.get('X-Frame-Options')).toBe('DENY');
      expect(response.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
      expect(response.headers.get('Cross-Origin-Opener-Policy')).toBe('same-origin');
      expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('none');
    });

    it('sets HSTS only over HTTPS', async () => {
      const handle = arcisHandle();
      const httpsResp = await handle({
        event: buildEvent({ url: 'https://example.test/' }),
        resolve: passthroughResolver(),
      });
      expect(httpsResp.headers.get('Strict-Transport-Security')).toMatch(/max-age=/);

      const httpResp = await handle({
        event: buildEvent({ url: 'http://example.test/' }),
        resolve: passthroughResolver(),
      });
      expect(httpResp.headers.get('Strict-Transport-Security')).toBeNull();
    });

    it('honors X-Forwarded-Proto: https for HSTS when client claims HTTPS', async () => {
      const handle = arcisHandle();
      const response = await handle({
        event: buildEvent({
          url: 'http://example.test/',
          headers: { 'x-forwarded-proto': 'https' },
        }),
        resolve: passthroughResolver(),
      });
      expect(response.headers.get('Strict-Transport-Security')).toMatch(/max-age=/);
    });

    it('respects custom headers config (frameOptions: SAMEORIGIN)', async () => {
      const handle = arcisHandle({ headers: { frameOptions: 'SAMEORIGIN' } });
      const response = await handle({ event: buildEvent(), resolve: passthroughResolver() });
      expect(response.headers.get('X-Frame-Options')).toBe('SAMEORIGIN');
    });

    it('does not set headers when headers: false', async () => {
      const handle = arcisHandle({ headers: false });
      const response = await handle({ event: buildEvent(), resolve: passthroughResolver() });
      expect(response.headers.get('Content-Security-Policy')).toBeNull();
      expect(response.headers.get('X-Content-Type-Options')).toBeNull();
    });

    it('removes X-Powered-By if the inner response set it', async () => {
      const handle = arcisHandle();
      const response = await handle({
        event: buildEvent(),
        resolve: async () =>
          new Response('ok', { status: 200, headers: { 'X-Powered-By': 'Express' } }),
      });
      expect(response.headers.get('X-Powered-By')).toBeNull();
    });
  });

  describe('Rate limiting', () => {
    it('passes requests under the limit through to resolve()', async () => {
      const handle = arcisHandle({ rateLimit: { max: 3, windowMs: 60_000 } });
      const resolve = vi.fn(passthroughResolver());
      for (let i = 0; i < 3; i++) {
        const response = await handle({ event: buildEvent({ ip: '1.2.3.4' }), resolve });
        expect(response.status).toBe(200);
      }
      expect(resolve).toHaveBeenCalledTimes(3);
    });

    it('returns 429 when the limit is exceeded for the same IP', async () => {
      const handle = arcisHandle({ rateLimit: { max: 2, windowMs: 60_000 } });
      const resolve = vi.fn(passthroughResolver());
      await handle({ event: buildEvent({ ip: '1.2.3.4' }), resolve });
      await handle({ event: buildEvent({ ip: '1.2.3.4' }), resolve });
      const blocked = await handle({ event: buildEvent({ ip: '1.2.3.4' }), resolve });
      expect(blocked.status).toBe(429);
      expect(blocked.headers.get('Retry-After')).toBeTruthy();
      expect(blocked.headers.get('X-RateLimit-Limit')).toBe('2');
      expect(blocked.headers.get('X-RateLimit-Remaining')).toBe('0');
      // resolve was called only twice — third request short-circuited
      expect(resolve).toHaveBeenCalledTimes(2);
    });

    it('isolates counters per IP — different IPs share no quota', async () => {
      const handle = arcisHandle({ rateLimit: { max: 1, windowMs: 60_000 } });
      const r1 = await handle({ event: buildEvent({ ip: '1.1.1.1' }), resolve: passthroughResolver() });
      const r2 = await handle({ event: buildEvent({ ip: '2.2.2.2' }), resolve: passthroughResolver() });
      expect(r1.status).toBe(200);
      expect(r2.status).toBe(200);
    });

    it('does not rate limit when rateLimit: false', async () => {
      const handle = arcisHandle({ rateLimit: false });
      const resolve = vi.fn(passthroughResolver());
      for (let i = 0; i < 50; i++) {
        await handle({ event: buildEvent({ ip: '1.2.3.4' }), resolve });
      }
      expect(resolve).toHaveBeenCalledTimes(50);
    });
  });

  describe('Bot detection', () => {
    it('does not detect bots when bot option is omitted (opt-in)', async () => {
      const handle = arcisHandle();
      const response = await handle({
        event: buildEvent({ headers: { 'user-agent': 'curl/8.0.0' } }),
        resolve: passthroughResolver(),
      });
      expect(response.status).toBe(200);
    });

    it('blocks AUTOMATED bots when bot: true (default deny list includes AUTOMATED)', async () => {
      const handle = arcisHandle({ bot: true, rateLimit: false });
      const response = await handle({
        event: buildEvent({ headers: { 'user-agent': 'HeadlessChrome/120.0.0.0' } }),
        resolve: passthroughResolver(),
      });
      expect(response.status).toBe(403);
    });

    it('allows search-engine bots by default', async () => {
      const handle = arcisHandle({ bot: true, rateLimit: false });
      const response = await handle({
        event: buildEvent({ headers: { 'user-agent': 'Googlebot/2.1' } }),
        resolve: passthroughResolver(),
      });
      expect(response.status).toBe(200);
    });

    it('respects custom deny lists', async () => {
      const handle = arcisHandle({ bot: { deny: ['SCRAPER'] }, rateLimit: false });
      const response = await handle({
        event: buildEvent({ headers: { 'user-agent': 'curl/8.0.0' } }),
        resolve: passthroughResolver(),
      });
      expect(response.status).toBe(403);
    });
  });

  describe('Resolution', () => {
    it('forwards the resolved response body when allowed', async () => {
      const handle = arcisHandle();
      const response = await handle({
        event: buildEvent(),
        resolve: async () => new Response('hello world', { status: 200 }),
      });
      expect(await response.text()).toBe('hello world');
      expect(response.status).toBe(200);
    });

    it('preserves the resolved status code', async () => {
      const handle = arcisHandle();
      const response = await handle({
        event: buildEvent(),
        resolve: async () => new Response('not found', { status: 404 }),
      });
      expect(response.status).toBe(404);
    });
  });
});
