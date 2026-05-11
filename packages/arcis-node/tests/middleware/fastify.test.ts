/**
 * Fastify Plugin Tests
 * Tests for src/middleware/fastify.ts (arcisFastify)
 *
 * Drives the plugin through a duck-typed FastifyInstance / Reply pair so
 * the tests don't depend on a real Fastify install. The duck contracts
 * exposed by the adapter are exactly what these tests assert against.
 */

import { describe, it, expect } from 'vitest';
import {
  arcisFastify,
  type FastifyHookHandler,
  type FastifyInstanceLike,
  type FastifyOnSendHandler,
  type FastifyReplyLike,
  type FastifyRequestLike,
} from '../../src/middleware/fastify';

interface FakeReplyState {
  status: number | null;
  headers: Record<string, string>;
  body: unknown;
  sent: boolean;
}

function createFakeReply(): { reply: FastifyReplyLike; state: FakeReplyState } {
  const state: FakeReplyState = {
    status: null,
    headers: {},
    body: undefined,
    sent: false,
  };
  const reply: FastifyReplyLike = {
    status(code) {
      state.status = code;
      return reply;
    },
    header(name, value) {
      state.headers[name] = value;
      return reply;
    },
    send(payload) {
      state.body = payload;
      state.sent = true;
      return reply;
    },
  };
  return { reply, state };
}

interface RegisteredHooks {
  onRequest: FastifyHookHandler[];
  onSend: FastifyOnSendHandler[];
}

function createFakeFastify(): { app: FastifyInstanceLike; hooks: RegisteredHooks } {
  const hooks: RegisteredHooks = { onRequest: [], onSend: [] };
  const app: FastifyInstanceLike = {
    addHook: ((name: 'onRequest' | 'onSend', handler: unknown) => {
      if (name === 'onRequest') hooks.onRequest.push(handler as FastifyHookHandler);
      else if (name === 'onSend') hooks.onSend.push(handler as FastifyOnSendHandler);
      return app;
    }) as FastifyInstanceLike['addHook'],
  };
  return { app, hooks };
}

interface BuildReqOpts {
  ip?: string;
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  socketRemoteAddress?: string;
}

function buildRequest(opts: BuildReqOpts = {}): FastifyRequestLike {
  const headers: Record<string, string | string[] | undefined> = { ...(opts.headers ?? {}) };
  return {
    headers,
    url: opts.url ?? '/',
    method: opts.method ?? 'GET',
    ip: opts.ip,
    socket: { remoteAddress: opts.socketRemoteAddress },
  };
}

describe('arcisFastify (Fastify plugin)', () => {
  describe('Hook registration', () => {
    it('registers onRequest + onSend hooks under default config', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app);
      expect(hooks.onRequest).toHaveLength(1);
      expect(hooks.onSend).toHaveLength(1);
    });

    it('does not register onSend when headers: false', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app, { headers: false });
      expect(hooks.onRequest).toHaveLength(1);
      expect(hooks.onSend).toHaveLength(0);
    });
  });

  describe('Rate limiting (onRequest hook)', () => {
    it('allows requests under the limit and emits X-RateLimit-* headers', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app, { rateLimit: { max: 3, windowMs: 60_000 } });
      const onRequest = hooks.onRequest[0];

      const { reply, state } = createFakeReply();
      await onRequest(buildRequest({ ip: '1.2.3.4' }), reply);

      expect(state.sent).toBe(false);
      expect(state.status).toBeNull();
      expect(state.headers['X-RateLimit-Limit']).toBe('3');
      expect(state.headers['X-RateLimit-Remaining']).toBe('2');
      expect(state.headers['X-RateLimit-Reset']).toBeTruthy();
    });

    it('returns 429 when the limit is exceeded for the same IP', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app, { rateLimit: { max: 2, windowMs: 60_000 } });
      const onRequest = hooks.onRequest[0];

      const r1 = createFakeReply();
      await onRequest(buildRequest({ ip: '1.2.3.4' }), r1.reply);
      const r2 = createFakeReply();
      await onRequest(buildRequest({ ip: '1.2.3.4' }), r2.reply);
      const r3 = createFakeReply();
      await onRequest(buildRequest({ ip: '1.2.3.4' }), r3.reply);

      expect(r1.state.sent).toBe(false);
      expect(r2.state.sent).toBe(false);
      expect(r3.state.sent).toBe(true);
      expect(r3.state.status).toBe(429);
      expect(r3.state.headers['Retry-After']).toBeTruthy();
      expect(r3.state.headers['X-RateLimit-Remaining']).toBe('0');
    });

    it('rate-limits per-IP, not globally', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app, { rateLimit: { max: 1, windowMs: 60_000 } });
      const onRequest = hooks.onRequest[0];

      const alice1 = createFakeReply();
      const bob1 = createFakeReply();
      await onRequest(buildRequest({ ip: '1.1.1.1' }), alice1.reply);
      await onRequest(buildRequest({ ip: '2.2.2.2' }), bob1.reply);
      expect(alice1.state.sent).toBe(false);
      expect(bob1.state.sent).toBe(false);

      const alice2 = createFakeReply();
      await onRequest(buildRequest({ ip: '1.1.1.1' }), alice2.reply);
      expect(alice2.state.sent).toBe(true);
      expect(alice2.state.status).toBe(429);
    });

    it('falls back to X-Forwarded-For when request.ip is absent', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app, { rateLimit: { max: 1, windowMs: 60_000 } });
      const onRequest = hooks.onRequest[0];

      const r1 = createFakeReply();
      await onRequest(
        buildRequest({ headers: { 'x-forwarded-for': '9.9.9.9, 1.1.1.1' } }),
        r1.reply,
      );
      const r2 = createFakeReply();
      await onRequest(
        buildRequest({ headers: { 'x-forwarded-for': '9.9.9.9, 1.1.1.1' } }),
        r2.reply,
      );
      expect(r1.state.sent).toBe(false);
      expect(r2.state.sent).toBe(true);
      expect(r2.state.status).toBe(429);
    });

    it('falls back to socket.remoteAddress when no IP header is present', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app, { rateLimit: { max: 1, windowMs: 60_000 } });
      const onRequest = hooks.onRequest[0];

      const r1 = createFakeReply();
      await onRequest(buildRequest({ socketRemoteAddress: '5.5.5.5' }), r1.reply);
      const r2 = createFakeReply();
      await onRequest(buildRequest({ socketRemoteAddress: '5.5.5.5' }), r2.reply);
      expect(r1.state.sent).toBe(false);
      expect(r2.state.sent).toBe(true);
    });

    it('rate-limits to the literal "unknown" key when no IP info is present', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app, { rateLimit: { max: 1, windowMs: 60_000 } });
      const onRequest = hooks.onRequest[0];

      const r1 = createFakeReply();
      await onRequest(buildRequest(), r1.reply);
      const r2 = createFakeReply();
      await onRequest(buildRequest(), r2.reply);
      expect(r1.state.sent).toBe(false);
      expect(r2.state.sent).toBe(true);
    });

    it('does not engage the limiter when rateLimit: false', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app, { rateLimit: false });
      const onRequest = hooks.onRequest[0];

      // Hammer past any reasonable limit; nothing should ever 429.
      for (let i = 0; i < 50; i++) {
        const { reply, state } = createFakeReply();
        await onRequest(buildRequest({ ip: '1.1.1.1' }), reply);
        expect(state.sent).toBe(false);
      }
    });
  });

  describe('Bot detection (onRequest hook)', () => {
    it('blocks denied bot categories with 403 by default', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app, {
        rateLimit: false,
        bot: { deny: ['AUTOMATED'] },
      });
      const onRequest = hooks.onRequest[0];

      const { reply, state } = createFakeReply();
      await onRequest(
        buildRequest({ headers: { 'user-agent': 'HeadlessChrome/120.0.0.0' } }),
        reply,
      );
      expect(state.sent).toBe(true);
      expect(state.status).toBe(403);
    });

    it('passes browsers through when bot: true', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app, { rateLimit: false, bot: true });
      const onRequest = hooks.onRequest[0];

      const { reply, state } = createFakeReply();
      await onRequest(
        buildRequest({
          headers: {
            'user-agent':
              'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            accept: 'text/html,application/xhtml+xml',
            'accept-language': 'en-US,en;q=0.9',
            'accept-encoding': 'gzip, deflate, br',
          },
        }),
        reply,
      );
      expect(state.sent).toBe(false);
    });

    it('honors a custom statusCode + message', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app, {
        rateLimit: false,
        bot: { deny: ['AUTOMATED'], statusCode: 418, message: 'Bot teapot' },
      });
      const onRequest = hooks.onRequest[0];

      const { reply, state } = createFakeReply();
      await onRequest(
        buildRequest({ headers: { 'user-agent': 'HeadlessChrome/120.0.0.0' } }),
        reply,
      );
      expect(state.status).toBe(418);
      expect(state.body).toMatchObject({ error: 'Bot teapot' });
    });
  });

  describe('Security headers (onSend hook)', () => {
    it('sets the standard headers by default', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app);
      const onSend = hooks.onSend[0];

      const { reply, state } = createFakeReply();
      await onSend(buildRequest(), reply, 'payload');

      expect(state.headers['Content-Security-Policy']).toBeTruthy();
      expect(state.headers['X-Content-Type-Options']).toBe('nosniff');
      expect(state.headers['X-Frame-Options']).toBe('DENY');
      expect(state.headers['Referrer-Policy']).toBe('strict-origin-when-cross-origin');
      expect(state.headers['X-Permitted-Cross-Domain-Policies']).toBe('none');
    });

    it('returns the payload unchanged so Fastify can flush it', async () => {
      // Pinning the contract: we mutate headers, we never touch the body.
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app);
      const onSend = hooks.onSend[0];

      const out = await onSend(buildRequest(), createFakeReply().reply, '{"ok":true}');
      expect(out).toBe('{"ok":true}');
    });

    it('sets HSTS only when X-Forwarded-Proto: https is set', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app);
      const onSend = hooks.onSend[0];

      const httpReq = buildRequest({});
      const httpResp = createFakeReply();
      await onSend(httpReq, httpResp.reply, 'p');
      expect(httpResp.state.headers['Strict-Transport-Security']).toBeUndefined();

      const httpsReq = buildRequest({ headers: { 'x-forwarded-proto': 'https' } });
      const httpsResp = createFakeReply();
      await onSend(httpsReq, httpsResp.reply, 'p');
      expect(httpsResp.state.headers['Strict-Transport-Security']).toMatch(/max-age=/);
    });

    it('respects custom headers config (frameOptions: SAMEORIGIN)', async () => {
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app, { headers: { frameOptions: 'SAMEORIGIN' } });
      const onSend = hooks.onSend[0];

      const { reply, state } = createFakeReply();
      await onSend(buildRequest(), reply, 'p');
      expect(state.headers['X-Frame-Options']).toBe('SAMEORIGIN');
    });

    it('does NOT set headers when headers: false (no onSend hook)', async () => {
      // Combined with the no-onSend-when-headers-false hook-registration
      // test above. Here we cover the plumbing path: even if a caller
      // somehow held a reference to onSend, headers: false means it's
      // not registered, so no wiring runs.
      const { app, hooks } = createFakeFastify();
      await arcisFastify(app, { headers: false });
      expect(hooks.onSend).toHaveLength(0);
    });
  });

  describe('Allocation isolation', () => {
    it('two plugin registrations have independent rate-limit counters', async () => {
      // Pin: each `arcisFastify` call builds its own limiter store.
      const a = createFakeFastify();
      const b = createFakeFastify();
      await arcisFastify(a.app, { rateLimit: { max: 1, windowMs: 60_000 } });
      await arcisFastify(b.app, { rateLimit: { max: 1, windowMs: 60_000 } });

      const aHook = a.hooks.onRequest[0];
      const bHook = b.hooks.onRequest[0];

      const a1 = createFakeReply();
      const a2 = createFakeReply();
      await aHook(buildRequest({ ip: '1.1.1.1' }), a1.reply);
      await aHook(buildRequest({ ip: '1.1.1.1' }), a2.reply);
      expect(a2.state.status).toBe(429);

      // Plugin B is independent — same IP, fresh counter.
      const b1 = createFakeReply();
      await bHook(buildRequest({ ip: '1.1.1.1' }), b1.reply);
      expect(b1.state.sent).toBe(false);
    });
  });
});
