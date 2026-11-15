/**
 * The baseline header profile must produce identical headers through every
 * Node adapter, not only Express. Each adapter runs through its public entry
 * point with the shared fixtures; rate limiting and bot checks are off so
 * only the header pass is exercised.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Request as ExpressRequest, Response as ExpressResponse } from 'express';
import { createHeaders } from '../../src/middleware/headers';
import { arcisFastify, type FastifyOnSendHandler, type FastifyInstanceLike, type FastifyReplyLike } from '../../src/middleware/fastify';
import { arcisKoa, type KoaContextLike } from '../../src/middleware/koa';
import { arcisHono } from '../../src/middleware/hono';
import { arcisProtect } from '../../src/middleware/nextjs';
import { arcisHandle, type SvelteKitRequestEvent } from '../../src/middleware/sveltekit';
import { onRequest, type AstroAPIContext } from '../../src/middleware/astro';
import { arcisHandler, type H3EventLike } from '../../src/middleware/nuxt';
import { arcisBun } from '../../src/middleware/bun';
import type { HeaderOptions } from '../../src/core/types';

interface FixtureCase {
  name: string;
  options: Record<string, unknown>;
  expected_headers: Record<string, string>;
  expected_absent: string[];
}

const vectors = JSON.parse(readFileSync(resolve(__dirname, '../../../../spec/TEST_VECTORS.json'), 'utf-8'));
const fixtures = vectors.security_headers.baseline.cases as FixtureCase[];
const routeWins = vectors.security_headers.baseline.route_header_wins as {
  route_sets: Record<string, string>;
  expected_headers: Record<string, string>;
};

const URL_HTTPS = 'https://example.test/';
type Headers = Record<string, string>;
/** Runs one request through an adapter and returns the response headers (lowercased names). */
type Runner = (headers: HeaderOptions, routeSets?: Headers) => Promise<Headers>;

const lower = (entries: Iterable<[string, string]>): Headers =>
  Object.fromEntries([...entries].map(([k, v]) => [k.toLowerCase(), v]));

function fetchResponse(routeSets: Headers = {}): Response {
  return new Response('ok', { status: 200, headers: { 'Content-Type': 'text/plain', ...routeSets } });
}

const common = { rateLimit: false, bot: false } as const;

const runners: Record<string, Runner> = {
  async express(headers, routeSets = {}) {
    const set = new Map<string, string>();
    const res = {
      locals: {},
      setHeader: (n: string, v: string) => set.set(n.toLowerCase(), v),
      removeHeader: (n: string) => set.delete(n.toLowerCase()),
    } as unknown as ExpressResponse;
    createHeaders(headers)({ headers: {}, secure: true } as ExpressRequest, res, () => {
      for (const [n, v] of Object.entries(routeSets)) set.set(n.toLowerCase(), v);
    });
    return Object.fromEntries(set);
  },

  async fastify(headers, routeSets = {}) {
    const onSend: FastifyOnSendHandler[] = [];
    const app = {
      addHook: (name: string, handler: unknown) => {
        if (name === 'onSend') onSend.push(handler as FastifyOnSendHandler);
        return app;
      },
    } as unknown as FastifyInstanceLike;
    await arcisFastify(app, { ...common, headers });
    const set = new Map<string, string>(Object.entries(routeSets).map(([n, v]) => [n.toLowerCase(), v]));
    const reply: FastifyReplyLike = {
      status: () => reply,
      send: () => reply,
      header: (n, v) => (set.set(n.toLowerCase(), v), reply),
      hasHeader: (n) => set.has(n.toLowerCase()),
      removeHeader: (n) => (set.delete(n.toLowerCase()), reply),
    };
    await onSend[0]!({ headers: { 'x-forwarded-proto': 'https' }, url: '/', method: 'GET' }, reply, 'ok');
    return Object.fromEntries(set);
  },

  async koa(headers, routeSets = {}) {
    const set = new Map<string, string>();
    const ctx = {
      request: { headers: { 'x-forwarded-proto': 'https' }, url: '/', method: 'GET' },
      response: {
        status: 200,
        body: undefined,
        set: (n: string, v: string) => set.set(n.toLowerCase(), v),
        has: (n: string) => set.has(n.toLowerCase()),
      },
      set: (n: string, v: string) => set.set(n.toLowerCase(), v),
      remove: (n: string) => set.delete(n.toLowerCase()),
      status: 200,
      body: undefined,
    } as unknown as KoaContextLike;
    await arcisKoa({ ...common, headers })(ctx, async () => {
      for (const [n, v] of Object.entries(routeSets)) set.set(n.toLowerCase(), v);
    });
    return Object.fromEntries(set);
  },

  async hono(headers, routeSets = {}) {
    const ctx = { req: { raw: new Request(URL_HTTPS) }, res: fetchResponse() };
    const middleware = arcisHono({ ...common, headers }) as unknown as (c: typeof ctx, next: () => Promise<void>) => Promise<unknown>;
    await middleware(ctx, async () => {
      ctx.res = fetchResponse(routeSets);
    });
    return lower(ctx.res.headers);
  },

  async nextjs(headers, routeSets = {}) {
    const response = await arcisProtect(async () => fetchResponse(routeSets), { ...common, headers })(new Request(URL_HTTPS));
    return lower(response.headers);
  },

  async sveltekit(headers, routeSets = {}) {
    const url = new URL(URL_HTTPS);
    const event = {
      request: new Request(url),
      url,
      cookies: { get: () => undefined, set: () => {}, delete: () => {} },
      getClientAddress: () => '127.0.0.1',
    } as SvelteKitRequestEvent;
    const response = await arcisHandle({ ...common, headers })({ event, resolve: async () => fetchResponse(routeSets) });
    return lower(response.headers);
  },

  async astro(headers, routeSets = {}) {
    const url = new URL(URL_HTTPS);
    const context = {
      request: new Request(url),
      url,
      cookies: { get: () => undefined, set: () => {}, delete: () => {} },
      clientAddress: '127.0.0.1',
    } as AstroAPIContext;
    const response = await onRequest({ ...common, headers })(context, async () => fetchResponse(routeSets));
    return lower((response as Response).headers);
  },

  async nuxt(headers, routeSets = {}) {
    const set = new Map<string, string>();
    const res = {
      statusCode: 200,
      writableEnded: false,
      setHeader: (n: string, v: string) => set.set(n.toLowerCase(), String(v)),
      removeHeader: (n: string) => set.delete(n.toLowerCase()),
      end: () => {},
    };
    const event = {
      node: { req: { headers: { 'x-forwarded-proto': 'https' }, socket: { remoteAddress: '127.0.0.1' }, method: 'GET', url: '/' }, res },
    } as unknown as H3EventLike;
    await arcisHandler({ ...common, headers })(event);
    // Nuxt applies headers before the route handler; the route then writes its own.
    for (const [n, v] of Object.entries(routeSets)) set.set(n.toLowerCase(), v);
    return Object.fromEntries(set);
  },

  async bun(headers, routeSets = {}) {
    const wrapped = arcisBun({ ...common, headers }, async () => fetchResponse(routeSets));
    const response = await wrapped(new Request(URL_HTTPS), { requestIP: () => ({ address: '127.0.0.1' }) });
    return lower(response.headers);
  },
};

const adapters = Object.keys(runners);

describe.each(adapters)('baseline profile through %s', (adapter) => {
  const runner = runners[adapter]!;

  it.each(fixtures.map((f) => [f.name, f] as const))('%s', async (_name, fixture) => {
    const got = await runner({ profile: 'baseline', ...fixture.options } as HeaderOptions);
    for (const [name, value] of Object.entries(fixture.expected_headers)) {
      expect(got[name.toLowerCase()], name).toBe(value);
    }
    for (const name of fixture.expected_absent) {
      expect(got[name.toLowerCase()], name).toBeUndefined();
    }
  });

  it('keeps headers the route set itself', async () => {
    const got = await runner({ profile: 'baseline' }, routeWins.route_sets);
    for (const [name, value] of Object.entries(routeWins.expected_headers)) {
      expect(got[name.toLowerCase()], name).toBe(value);
    }
  });
});

describe('nonce support outside Express', () => {
  const nonce = { profile: 'baseline', contentSecurityPolicy: { nonce: true } } as HeaderOptions;
  const factories: Array<[string, () => unknown]> = [
    ['Koa', () => arcisKoa({ headers: nonce })],
    ['Hono', () => arcisHono({ headers: nonce })],
    ['Next.js', () => arcisProtect(async () => new Response(), { headers: nonce })],
    ['SvelteKit', () => arcisHandle({ headers: nonce })],
    ['Astro', () => onRequest({ headers: nonce })],
    ['Nuxt', () => arcisHandler({ headers: nonce })],
    ['Bun', () => arcisBun({ headers: nonce }, async () => new Response())],
  ];

  it.each(factories)('%s rejects it at construction', (label, factory) => {
    expect(factory).toThrow(`not available in the ${label} adapter`);
  });

  it('Fastify rejects it at registration', async () => {
    const app = { addHook: () => app } as unknown as FastifyInstanceLike;
    await expect(arcisFastify(app, { headers: nonce })).rejects.toThrow('not available in the Fastify adapter');
  });
});

describe('legacy profile keeps overwriting route headers in post-handler adapters', () => {
  it('Hono still applies its X-Frame-Options over the route value', async () => {
    const got = await runners.hono!({}, { 'X-Frame-Options': 'SAMEORIGIN' });
    expect(got['x-frame-options']).toBe('DENY');
  });
});
