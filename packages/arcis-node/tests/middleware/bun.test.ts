/**
 * Bun + Hono Adapter Tests
 * Tests for src/middleware/bun.ts (arcisBun + arcisHono)
 */

import { describe, it, expect, vi } from 'vitest';
import {
  arcisBun,
  arcisHono,
  type BunServerLike,
  type HonoContextLike,
} from '../../src/middleware/bun';

// ─── arcisBun (Bun.serve fetch wrapper) ─────────────────────────────────────

interface BunCallOpts {
  ip?: string;
  url?: string;
  headers?: Record<string, string>;
}

function callBun(
  options: Parameters<typeof arcisBun>[0],
  inner: (req: Request, server?: BunServerLike) => Promise<Response> | Response,
  call: BunCallOpts = {},
): Promise<Response> {
  const wrapped = arcisBun(options, inner);
  const url = call.url ?? 'https://example.test/';
  const req = new Request(url, { headers: new Headers(call.headers ?? {}) });
  const server: BunServerLike = {
    requestIP: () => ({ address: call.ip ?? '127.0.0.1' }),
  };
  return Promise.resolve(wrapped(req, server));
}

describe('arcisBun (Bun.serve fetch wrapper)', () => {
  it('forwards the user handler response when allowed', async () => {
    const inner = vi.fn(async () => new Response('hello', { status: 200 }));
    const response = await callBun({}, inner);
    expect(await response.text()).toBe('hello');
    expect(inner).toHaveBeenCalledTimes(1);
  });

  it('sets security headers on the wrapped response by default', async () => {
    const response = await callBun({}, async () => new Response('ok'));
    expect(response.headers.get('Content-Security-Policy')).toBeTruthy();
    expect(response.headers.get('X-Frame-Options')).toBe('DENY');
    expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });

  it('returns 429 when rate limit is exceeded for the same IP', async () => {
    const handler = arcisBun({ rateLimit: { max: 1 } }, async () => new Response('ok'));
    const url = 'https://example.test/';
    const server: BunServerLike = { requestIP: () => ({ address: '1.2.3.4' }) };
    const r1 = await handler(new Request(url), server);
    expect(r1.status).toBe(200);
    const r2 = await handler(new Request(url), server);
    expect(r2.status).toBe(429);
    expect(r2.headers.get('Retry-After')).toBeTruthy();
  });

  it('isolates counters per IP', async () => {
    const handler = arcisBun({ rateLimit: { max: 1 } }, async () => new Response('ok'));
    const url = 'https://example.test/';
    const r1 = await handler(new Request(url), { requestIP: () => ({ address: '1.1.1.1' }) });
    const r2 = await handler(new Request(url), { requestIP: () => ({ address: '2.2.2.2' }) });
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
  });

  it('blocks AUTOMATED bots when bot: true', async () => {
    const inner = vi.fn(async () => new Response('ok'));
    const response = await callBun({ bot: true, rateLimit: false }, inner, {
      headers: { 'user-agent': 'HeadlessChrome/120.0.0.0' },
    });
    expect(response.status).toBe(403);
    expect(inner).not.toHaveBeenCalled();
  });

  it('allows search-engine bots by default', async () => {
    const inner = vi.fn(async () => new Response('ok'));
    const response = await callBun({ bot: true, rateLimit: false }, inner, {
      headers: { 'user-agent': 'Googlebot/2.1' },
    });
    expect(response.status).toBe(200);
    expect(inner).toHaveBeenCalled();
  });

  it('prefers X-Forwarded-For over server.requestIP() when present', async () => {
    const handler = arcisBun({ rateLimit: { max: 1 } }, async () => new Response('ok'));
    const url = 'https://example.test/';
    const server: BunServerLike = { requestIP: () => ({ address: '10.0.0.5' }) };

    // First request: XFF identifies real client
    await handler(
      new Request(url, { headers: { 'x-forwarded-for': '203.0.113.5, 10.0.0.5' } }),
      server,
    );
    // Second from same XFF client (different proxy hop): rate-limited
    const blocked = await handler(
      new Request(url, { headers: { 'x-forwarded-for': '203.0.113.5, 10.0.0.6' } }),
      { requestIP: () => ({ address: '10.0.0.6' }) },
    );
    expect(blocked.status).toBe(429);
  });
});

// ─── arcisHono (Hono middleware) ─────────────────────────────────────────────

function buildHonoContext(opts: { url?: string; headers?: Record<string, string> } = {}): {
  c: HonoContextLike;
  setRes: (r: Response) => void;
} {
  const url = opts.url ?? 'https://example.test/';
  const raw = new Request(url, { headers: new Headers(opts.headers ?? {}) });
  let res = new Response('default', { status: 200 });
  const c: HonoContextLike = {
    req: {
      raw,
      url: raw.url,
      header: (n) => raw.headers.get(n) ?? undefined,
    },
    get res(): Response {
      return res;
    },
    set res(r: Response) {
      res = r;
    },
    json: (body, status) =>
      new Response(JSON.stringify(body), {
        status: status ?? 200,
        headers: { 'Content-Type': 'application/json' },
      }),
  };
  return { c, setRes: (r) => (res = r) };
}

describe('arcisHono (Hono middleware)', () => {
  it('sets security headers on c.res after next()', async () => {
    const middleware = arcisHono();
    const { c, setRes } = buildHonoContext();
    const next = async () => {
      setRes(new Response('downstream', { status: 200 }));
    };

    await middleware(c, next);

    expect(c.res.headers.get('Content-Security-Policy')).toBeTruthy();
    expect(c.res.headers.get('X-Frame-Options')).toBe('DENY');
    expect(await c.res.text()).toBe('downstream');
  });

  it('returns 429 directly when rate limit is exceeded (next is NOT called)', async () => {
    const middleware = arcisHono({ rateLimit: { max: 1 } });
    const next = vi.fn(async () => {});

    // First call passes
    const ctx1 = buildHonoContext({ headers: { 'x-forwarded-for': '1.2.3.4' } });
    const r1 = await middleware(ctx1.c, next);
    expect(r1).toBeUndefined();
    expect(next).toHaveBeenCalledTimes(1);

    // Second call is blocked
    const ctx2 = buildHonoContext({ headers: { 'x-forwarded-for': '1.2.3.4' } });
    const r2 = await middleware(ctx2.c, next);
    expect(r2).toBeInstanceOf(Response);
    expect((r2 as Response).status).toBe(429);
    expect(next).toHaveBeenCalledTimes(1); // Not advanced on second call
  });

  it('blocks AUTOMATED bots when bot: true (returns 403 Response)', async () => {
    const middleware = arcisHono({ bot: true, rateLimit: false });
    const next = vi.fn(async () => {});
    const { c } = buildHonoContext({ headers: { 'user-agent': 'HeadlessChrome/120.0.0.0' } });

    const result = await middleware(c, next);
    expect(result).toBeInstanceOf(Response);
    expect((result as Response).status).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  it('does not detect bots when bot option omitted', async () => {
    const middleware = arcisHono();
    const next = vi.fn(async () => {});
    const { c } = buildHonoContext({ headers: { 'user-agent': 'curl/8.0.0' } });

    const result = await middleware(c, next);
    expect(result).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });

  it('does not set headers when headers: false', async () => {
    const middleware = arcisHono({ headers: false });
    const { c, setRes } = buildHonoContext();
    const next = async () => {
      setRes(new Response('downstream'));
    };
    await middleware(c, next);
    expect(c.res.headers.get('Content-Security-Policy')).toBeNull();
  });
});
