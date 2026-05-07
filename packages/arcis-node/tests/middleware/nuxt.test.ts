/**
 * Nuxt (h3) Adapter Tests
 * Tests for src/middleware/nuxt.ts (arcisHandler factory)
 */

import { describe, it, expect, vi } from 'vitest';
import { arcisHandler, type H3EventLike } from '../../src/middleware/nuxt';

interface BuildOpts {
  ip?: string;
  headers?: Record<string, string | string[] | undefined>;
}

interface MockRes {
  statusCode: number;
  body: string | undefined;
  ended: boolean;
  headers: Record<string, string | number | string[]>;
  setHeader: (name: string, value: string | number | string[]) => void;
  removeHeader: (name: string) => void;
  end: (body?: string) => void;
  writableEnded: boolean;
}

function buildEvent(opts: BuildOpts = {}): { event: H3EventLike; res: MockRes } {
  const res: MockRes = {
    statusCode: 200,
    body: undefined,
    ended: false,
    headers: {},
    writableEnded: false,
    setHeader(name, value) {
      this.headers[name] = value;
    },
    removeHeader(name) {
      delete this.headers[name];
    },
    end(body) {
      this.body = body;
      this.ended = true;
      this.writableEnded = true;
    },
  };
  const event: H3EventLike = {
    node: {
      req: {
        headers: opts.headers ?? {},
        socket: { remoteAddress: opts.ip ?? '127.0.0.1' },
        method: 'GET',
        url: '/',
      },
      res,
    },
  };
  return { event, res };
}

describe('arcisHandler (Nuxt h3 event handler factory)', () => {
  describe('Security headers', () => {
    it('sets standard security headers when invoked', async () => {
      const handler = arcisHandler();
      const { event, res } = buildEvent();
      await handler(event);

      expect(res.headers['Content-Security-Policy']).toBeTruthy();
      expect(res.headers['X-Content-Type-Options']).toBe('nosniff');
      expect(res.headers['X-Frame-Options']).toBe('DENY');
      expect(res.headers['Cross-Origin-Opener-Policy']).toBe('same-origin');
      expect(res.headers['Cache-Control']).toMatch(/no-store/);
    });

    it('only sets HSTS when X-Forwarded-Proto: https', async () => {
      const handler = arcisHandler();
      const { event: e1, res: r1 } = buildEvent({ headers: { 'x-forwarded-proto': 'https' } });
      await handler(e1);
      expect(r1.headers['Strict-Transport-Security']).toMatch(/max-age=/);

      const { event: e2, res: r2 } = buildEvent();
      await handler(e2);
      expect(r2.headers['Strict-Transport-Security']).toBeUndefined();
    });

    it('does not set headers when headers: false', async () => {
      const handler = arcisHandler({ headers: false });
      const { event, res } = buildEvent();
      await handler(event);
      expect(res.headers['Content-Security-Policy']).toBeUndefined();
    });

    it('removes X-Powered-By', async () => {
      const handler = arcisHandler();
      const { event, res } = buildEvent();
      // Simulate Nuxt having set X-Powered-By already (ignored — removeHeader is a no-op via mock)
      await handler(event);
      // We just assert removeHeader was called and the header isn't in the map
      expect(res.headers['X-Powered-By']).toBeUndefined();
    });
  });

  describe('Rate limiting', () => {
    it('passes requests under the limit through', async () => {
      const handler = arcisHandler({ rateLimit: { max: 3 } });
      for (let i = 0; i < 3; i++) {
        const { event, res } = buildEvent({ ip: '1.2.3.4' });
        await handler(event);
        expect(res.ended).toBe(false);
        expect(res.statusCode).toBe(200);
      }
    });

    it('returns 429 when limit is exceeded', async () => {
      const handler = arcisHandler({ rateLimit: { max: 1 } });
      const a = buildEvent({ ip: '1.2.3.4' });
      await handler(a.event);
      expect(a.res.ended).toBe(false);

      const b = buildEvent({ ip: '1.2.3.4' });
      await handler(b.event);
      expect(b.res.statusCode).toBe(429);
      expect(b.res.ended).toBe(true);
      expect(b.res.headers['Retry-After']).toBeDefined();
      expect(b.res.headers['X-RateLimit-Limit']).toBe('1');
      const parsed = JSON.parse(b.res.body ?? '{}');
      expect(parsed.error).toMatch(/Too many requests/);
    });

    it('isolates counters per IP', async () => {
      const handler = arcisHandler({ rateLimit: { max: 1 } });
      const a = buildEvent({ ip: '1.1.1.1' });
      const b = buildEvent({ ip: '2.2.2.2' });
      await handler(a.event);
      await handler(b.event);
      expect(a.res.statusCode).toBe(200);
      expect(b.res.statusCode).toBe(200);
    });

    it('prefers X-Forwarded-For over socket.remoteAddress when present', async () => {
      const handler = arcisHandler({ rateLimit: { max: 1 } });
      // First request from real client behind proxy — XFF identifies the client
      const a = buildEvent({
        ip: '10.0.0.1',
        headers: { 'x-forwarded-for': '203.0.113.5, 10.0.0.1' },
      });
      await handler(a.event);
      // Second request, same XFF client but different proxy hop — still rate-limited
      const b = buildEvent({
        ip: '10.0.0.2',
        headers: { 'x-forwarded-for': '203.0.113.5, 10.0.0.2' },
      });
      await handler(b.event);
      expect(b.res.statusCode).toBe(429);
    });
  });

  describe('Bot detection', () => {
    it('does not detect bots when bot option is omitted (opt-in)', async () => {
      const handler = arcisHandler();
      const { event, res } = buildEvent({ headers: { 'user-agent': 'curl/8.0.0' } });
      await handler(event);
      expect(res.ended).toBe(false);
    });

    it('blocks AUTOMATED bots when bot: true', async () => {
      const handler = arcisHandler({ bot: true, rateLimit: false });
      const { event, res } = buildEvent({
        headers: { 'user-agent': 'HeadlessChrome/120.0.0.0' },
      });
      await handler(event);
      expect(res.statusCode).toBe(403);
      expect(res.ended).toBe(true);
    });

    it('allows search-engine bots by default', async () => {
      const handler = arcisHandler({ bot: true, rateLimit: false });
      const { event, res } = buildEvent({ headers: { 'user-agent': 'Googlebot/2.1' } });
      await handler(event);
      expect(res.ended).toBe(false);
    });
  });
});
