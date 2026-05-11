/**
 * Astro Adapter Tests
 * Tests for src/middleware/astro.ts (onRequest factory)
 */

import { describe, it, expect, vi } from 'vitest';
import { onRequest, type AstroAPIContext } from '../../src/middleware/astro';

interface BuildOpts {
  ip?: string;
  url?: string;
  method?: string;
  headers?: Record<string, string>;
}

function buildContext(opts: BuildOpts = {}): AstroAPIContext {
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
    clientAddress: opts.ip ?? '127.0.0.1',
  };
}

const okNext = (): (() => Promise<Response>) =>
  async () => new Response('ok', { status: 200, headers: { 'Content-Type': 'text/plain' } });

describe('onRequest (Astro MiddlewareHandler factory)', () => {
  describe('Security headers', () => {
    it('sets standard security headers on the response by default', async () => {
      const handler = onRequest();
      const response = await handler(buildContext(), okNext());

      expect(response.headers.get('Content-Security-Policy')).toBeTruthy();
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
      expect(response.headers.get('X-Frame-Options')).toBe('DENY');
      expect(response.headers.get('Cross-Origin-Opener-Policy')).toBe('same-origin');
      expect(response.headers.get('Cache-Control')).toMatch(/no-store/);
    });

    it('sets HSTS only over HTTPS', async () => {
      const handler = onRequest();
      const httpsResp = await handler(buildContext({ url: 'https://example.test/' }), okNext());
      expect(httpsResp.headers.get('Strict-Transport-Security')).toMatch(/max-age=/);

      const httpResp = await handler(buildContext({ url: 'http://example.test/' }), okNext());
      expect(httpResp.headers.get('Strict-Transport-Security')).toBeNull();
    });

    it('honors X-Forwarded-Proto for HSTS gating', async () => {
      const handler = onRequest();
      const response = await handler(
        buildContext({ url: 'http://example.test/', headers: { 'x-forwarded-proto': 'https' } }),
        okNext(),
      );
      expect(response.headers.get('Strict-Transport-Security')).toMatch(/max-age=/);
    });

    it('does not set headers when headers: false', async () => {
      const handler = onRequest({ headers: false });
      const response = await handler(buildContext(), okNext());
      expect(response.headers.get('Content-Security-Policy')).toBeNull();
    });

    it('removes X-Powered-By if the inner response set it', async () => {
      const handler = onRequest();
      const response = await handler(
        buildContext(),
        async () => new Response('ok', { status: 200, headers: { 'X-Powered-By': 'Astro' } }),
      );
      expect(response.headers.get('X-Powered-By')).toBeNull();
    });
  });

  describe('Rate limiting', () => {
    it('passes requests under the limit through to next()', async () => {
      const handler = onRequest({ rateLimit: { max: 3 } });
      const next = vi.fn(okNext());
      for (let i = 0; i < 3; i++) {
        const response = await handler(buildContext({ ip: '1.2.3.4' }), next);
        expect(response.status).toBe(200);
      }
      expect(next).toHaveBeenCalledTimes(3);
    });

    it('returns 429 when limit is exceeded', async () => {
      const handler = onRequest({ rateLimit: { max: 1 } });
      const next = vi.fn(okNext());
      await handler(buildContext({ ip: '1.2.3.4' }), next);
      const blocked = await handler(buildContext({ ip: '1.2.3.4' }), next);
      expect(blocked.status).toBe(429);
      expect(blocked.headers.get('Retry-After')).toBeTruthy();
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('isolates counters per client IP', async () => {
      const handler = onRequest({ rateLimit: { max: 1 } });
      const r1 = await handler(buildContext({ ip: '1.1.1.1' }), okNext());
      const r2 = await handler(buildContext({ ip: '2.2.2.2' }), okNext());
      expect(r1.status).toBe(200);
      expect(r2.status).toBe(200);
    });
  });

  describe('Bot detection', () => {
    it('blocks AUTOMATED bots when bot: true', async () => {
      const handler = onRequest({ bot: true, rateLimit: false });
      const response = await handler(
        buildContext({ headers: { 'user-agent': 'HeadlessChrome/120.0.0.0' } }),
        okNext(),
      );
      expect(response.status).toBe(403);
    });

    it('allows search-engine bots by default', async () => {
      const handler = onRequest({ bot: true, rateLimit: false });
      const response = await handler(
        buildContext({ headers: { 'user-agent': 'Googlebot/2.1' } }),
        okNext(),
      );
      expect(response.status).toBe(200);
    });

    it('does not detect bots when bot option is omitted (opt-in)', async () => {
      const handler = onRequest();
      const response = await handler(
        buildContext({ headers: { 'user-agent': 'curl/8.0.0' } }),
        okNext(),
      );
      expect(response.status).toBe(200);
    });
  });

  describe('Resolution', () => {
    it('forwards the next() response body and status', async () => {
      const handler = onRequest();
      const response = await handler(
        buildContext(),
        async () => new Response('hello', { status: 201 }),
      );
      expect(await response.text()).toBe('hello');
      expect(response.status).toBe(201);
    });
  });
});
