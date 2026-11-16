/**
 * Real-server regression for the rotating X-Forwarded-For bypass
 * (spec/API_SPEC.md, "Client IP resolution").
 *
 * Each adapter that exposes a socket runs behind a real Node HTTP server.
 * The test client connects from 127.0.0.1, so:
 *   - with `trustedProxies: []` the peer is untrusted, standing in for a
 *     public client: rotating X-Forwarded-For must stay in ONE bucket;
 *   - with the default trust set the loopback peer is a trusted proxy:
 *     distinct forwarded client IPs must get distinct buckets.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import express from 'express';
import { createRateLimiter } from '../../src/middleware/rate-limit';
import { arcis } from '../../src/middleware/main';
import { bruteForceProtection } from '../../src/middleware/brute-force';
import {
  arcisFastify,
  type FastifyHookHandler,
  type FastifyInstanceLike,
  type FastifyReplyLike,
} from '../../src/middleware/fastify';
import { arcisKoa, type KoaContextLike } from '../../src/middleware/koa';
import { arcisHandler } from '../../src/middleware/nuxt';
import { arcisBun, type BunServerLike } from '../../src/middleware/bun';
import { _resetClientIpWarnings, type ClientIpOptions } from '../../src/utils/client-ip';

type NodeHandler = (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;

const servers: Server[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  _resetClientIpWarnings();
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
});

async function listen(handler: NodeHandler | express.Express): Promise<string> {
  const server = createServer(handler as NodeHandler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const { port } = server.address() as { port: number };
  return `http://127.0.0.1:${port}/`;
}

async function statuses(url: string, forwardedFor: string[]): Promise<number[]> {
  const out: number[] = [];
  for (const xff of forwardedFor) {
    const res = await fetch(url, { headers: { 'x-forwarded-for': xff, 'user-agent': 'Mozilla/5.0' } });
    await res.arrayBuffer();
    out.push(res.status);
  }
  return out;
}

const ROTATING = ['198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4', '198.51.100.5'];
const DISTINCT_THEN_REPEAT = ['198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.1'];

// ─── Server builders, one per adapter ───────────────────────────────────────

function expressServer(trust: ClientIpOptions, max: number): Promise<string> {
  const app = express();
  app.use(createRateLimiter({ max, windowMs: 60_000, ...trust }));
  app.get('/', (_req, res) => res.send('ok'));
  return listen(app);
}

function arcisStackServer(trust: ClientIpOptions, max: number): Promise<string> {
  const app = express();
  app.use(...arcis({ ...trust, rateLimit: { max, windowMs: 60_000 }, bot: false }));
  app.get('/', (_req, res) => res.send('ok'));
  return listen(app);
}

function bruteForceServer(trust: ClientIpOptions, max: number): Promise<string> {
  const app = express();
  app.use(bruteForceProtection({ fastPoints: max, slowPoints: 100, ...trust }));
  app.get('/', (_req, res) => res.send('ok'));
  return listen(app);
}

async function fastifyServer(trust: ClientIpOptions, max: number): Promise<string> {
  let onRequest: FastifyHookHandler | undefined;
  const app: FastifyInstanceLike = {
    addHook: ((name: string, handler: FastifyHookHandler) => {
      if (name === 'onRequest') onRequest = handler;
      return app;
    }) as FastifyInstanceLike['addHook'],
  };
  await arcisFastify(app, { ...trust, headers: false, rateLimit: { max, windowMs: 60_000 } });
  return listen(async (req, res) => {
    let sent = false;
    const reply: FastifyReplyLike = {
      status(code) { res.statusCode = code; return reply; },
      header(name, value) { res.setHeader(name, value); return reply; },
      send(payload) { sent = true; res.end(JSON.stringify(payload)); return reply; },
    };
    // Shaped like a FastifyRequest without trustProxy: ip is the socket address.
    await onRequest!({ headers: req.headers, url: req.url, method: req.method, ip: req.socket.remoteAddress, socket: req.socket, raw: req }, reply);
    if (!sent) res.end('ok');
  });
}

function koaServer(trust: ClientIpOptions, max: number): Promise<string> {
  const middleware = arcisKoa({ ...trust, headers: false, rateLimit: { max, windowMs: 60_000 } });
  return listen(async (req, res) => {
    const ctx: KoaContextLike = {
      request: { headers: req.headers, url: req.url, method: req.method, ip: req.socket.remoteAddress, socket: req.socket },
      response: { status: 404, body: undefined, set: (n, v) => res.setHeader(n, v) },
      ip: req.socket.remoteAddress,
      req,
      app: { proxy: false },
      set: (n, v) => res.setHeader(n, v),
      status: 404,
      body: undefined,
    };
    await middleware(ctx, async () => {
      ctx.status = 200;
      ctx.body = 'ok';
    });
    res.statusCode = ctx.status;
    res.end(typeof ctx.body === 'string' ? ctx.body : JSON.stringify(ctx.body));
  });
}

function nuxtServer(trust: ClientIpOptions, max: number): Promise<string> {
  const handler = arcisHandler({ ...trust, headers: false, rateLimit: { max, windowMs: 60_000 } });
  return listen(async (req, res) => {
    await handler({ node: { req, res } });
    if (!res.writableEnded) res.end('ok');
  });
}

function bunStyleServer(trust: ClientIpOptions, max: number): Promise<string> {
  // A Node server bridged to the Bun fetch-handler contract: the peer comes
  // from server.requestIP(), exactly as Bun.serve provides it.
  const handler = arcisBun({ ...trust, headers: false, rateLimit: { max, windowMs: 60_000 } }, () => new Response('ok'));
  return listen(async (req, res) => {
    const request = new Request(`http://127.0.0.1${req.url}`, { headers: req.headers as Record<string, string> });
    const server: BunServerLike = { requestIP: () => ({ address: req.socket.remoteAddress ?? '' }) };
    const response = await handler(request, server);
    res.statusCode = response.status;
    res.end(await response.text());
  });
}

const ADAPTERS: Array<[string, (trust: ClientIpOptions, max: number) => Promise<string>]> = [
  ['Express createRateLimiter', expressServer],
  ['Express arcis()', arcisStackServer],
  ['Express bruteForceProtection', bruteForceServer],
  ['Fastify', fastifyServer],
  ['Koa', koaServer],
  ['Nuxt / h3', nuxtServer],
  ['Bun', bunStyleServer],
];

describe.each(ADAPTERS)('%s on a real server', (_name, build) => {
  it('a public peer rotating X-Forwarded-For stays in one bucket and gets 429 after max', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const url = await build({ trustedProxies: [] }, 2);
    expect(await statuses(url, ROTATING)).toEqual([200, 200, 429, 429, 429]);
  });

  it('behind a trusted private peer, distinct client IPs get distinct buckets', async () => {
    const url = await build({}, 1);
    expect(await statuses(url, DISTINCT_THEN_REPEAT)).toEqual([200, 200, 200, 429]);
  });
});

describe('Express trust proxy setting', () => {
  it("uses Express's req.ip when trust proxy is configured and trustedProxies is not", async () => {
    const app = express();
    app.set('trust proxy', 'loopback');
    app.use(createRateLimiter({ max: 1, windowMs: 60_000 }));
    app.get('/', (_req, res) => res.send('ok'));
    const url = await listen(app);
    expect(await statuses(url, DISTINCT_THEN_REPEAT)).toEqual([200, 200, 200, 429]);
  });

  it('explicit trustedProxies overrides trust proxy', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const app = express();
    app.set('trust proxy', true);
    app.use(createRateLimiter({ max: 2, windowMs: 60_000, trustedProxies: [] }));
    app.get('/', (_req, res) => res.send('ok'));
    const url = await listen(app);
    expect(await statuses(url, ROTATING)).toEqual([200, 200, 429, 429, 429]);
  });
});
