/**
 * Phase 8: middleware integration — verifies arcis() emits TelemetryEvents
 * for allow / rate-limit deny / sanitizer deny decisions.
 */

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import express from 'express';
import { createServer, type Server } from 'http';
import type { AddressInfo } from 'net';
import arcis from '../../src/index';
import type { TelemetryEvent } from '../../src/telemetry/types';

function buildIngestServer(received: TelemetryEvent[]): Promise<{ url: string; close: () => Promise<void> }> {
  const app = express();
  app.use(express.json());
  app.post('/v1/events', (req, res) => {
    const body = req.body as { events: TelemetryEvent[] };
    for (const e of body.events ?? []) received.push(e);
    res.json({ inserted: body.events?.length ?? 0 });
  });
  return new Promise((resolve) => {
    const server = createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        url: `http://127.0.0.1:${port}/v1/events`,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

function buildAppServer(setup: (app: express.Express) => void): Promise<{ url: string; close: () => Promise<void> }> {
  const app = express();
  app.use(express.json());
  setup(app);
  // Express error handler so SecurityThreatError → 400, not 500
  app.use((err: { statusCode?: number; message?: string }, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(err.statusCode ?? 500).json({ error: err.message ?? 'error' });
  });
  return new Promise((resolve) => {
    const server: Server = createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  for (const fn of cleanups.splice(0)) await fn();
});

describe('Phase 8: telemetry middleware integration', () => {
  it('emits an allow event for a clean request', async () => {
    const received: TelemetryEvent[] = [];
    const ingest = await buildIngestServer(received);
    cleanups.push(ingest.close);

    const stack = arcis({
      rateLimit: { max: 100 },
      telemetry: { endpoint: ingest.url, batchSize: 1, flushIntervalMs: 500 },
    });
    cleanups.push(() => stack.close());

    const app = await buildAppServer((a) => {
      a.use(...stack);
      a.get('/ping', (_req, res) => res.json({ ok: true }));
    });
    cleanups.push(app.close);

    const res = await fetch(`${app.url}/ping`);
    expect(res.status).toBe(200);

    // wait for the batch=1 flush
    await vi.waitFor(() => expect(received).toHaveLength(1));

    expect(received[0]).toMatchObject({
      decision: 'allow',
      method: 'GET',
      path: '/ping',
      status: 200,
    });
    expect(received[0].latencyMs).toBeGreaterThanOrEqual(0);
  });

  it('emits a deny event with vector="rate-limit" when limit is exceeded', async () => {
    const received: TelemetryEvent[] = [];
    const ingest = await buildIngestServer(received);
    cleanups.push(ingest.close);

    const stack = arcis({
      rateLimit: { max: 1, windowMs: 60_000 },
      telemetry: { endpoint: ingest.url, batchSize: 1, flushIntervalMs: 500 },
    });
    cleanups.push(() => stack.close());

    const app = await buildAppServer((a) => {
      a.use(...stack);
      a.get('/x', (_req, res) => res.json({ ok: true }));
    });
    cleanups.push(app.close);

    await fetch(`${app.url}/x`); // first allowed
    const denied = await fetch(`${app.url}/x`); // second blocked
    expect(denied.status).toBe(429);

    await vi.waitFor(() =>
      expect(received.find((e) => e.decision === 'deny')).toBeDefined(),
    );

    const denyEvent = received.find((e) => e.decision === 'deny');
    expect(denyEvent).toMatchObject({
      decision: 'deny',
      vector: 'rate-limit',
      rule: 'rate-limit/exceeded',
      severity: 'medium',
      status: 429,
    });
  });

  it('emits a deny event with vector="sql" when sanitizer rejects SQL injection', async () => {
    const received: TelemetryEvent[] = [];
    const ingest = await buildIngestServer(received);
    cleanups.push(ingest.close);

    const stack = arcis({
      rateLimit: false,
      sanitize: { mode: 'reject' },
      telemetry: { endpoint: ingest.url, batchSize: 1, flushIntervalMs: 500 },
    });
    cleanups.push(() => stack.close());

    const app = await buildAppServer((a) => {
      a.use(...stack);
      a.post('/login', (_req, res) => res.json({ ok: true }));
    });
    cleanups.push(app.close);

    const res = await fetch(`${app.url}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user: "admin' UNION SELECT * FROM users --" }),
    });
    expect(res.status).toBe(400);

    await vi.waitFor(() =>
      expect(received.find((e) => e.decision === 'deny')).toBeDefined(),
    );

    const denyEvent = received.find((e) => e.decision === 'deny');
    expect(denyEvent?.vector).toBe('sql');
    expect(denyEvent?.severity).toBe('high');
    expect(denyEvent?.matchedPattern).toBeTruthy();
  });

  it('zero overhead when telemetry option is omitted (no client created)', async () => {
    const received: TelemetryEvent[] = [];
    const ingest = await buildIngestServer(received);
    cleanups.push(ingest.close);

    // No telemetry option = no emitter, no client, no fetch to ingest
    const stack = arcis({ rateLimit: { max: 100 } });
    cleanups.push(() => stack.close());

    const app = await buildAppServer((a) => {
      a.use(...stack);
      a.get('/ping', (_req, res) => res.json({ ok: true }));
    });
    cleanups.push(app.close);

    await fetch(`${app.url}/ping`);
    // Negative assertion: keep a fixed wait — vi.waitFor cannot prove non-emission.
    await new Promise((r) => setTimeout(r, 100));

    expect(received).toHaveLength(0);
  });

  it('stack.close() drains the telemetry queue', async () => {
    const received: TelemetryEvent[] = [];
    const ingest = await buildIngestServer(received);
    cleanups.push(ingest.close);

    const stack = arcis({
      telemetry: { endpoint: ingest.url, batchSize: 100, flushIntervalMs: 60_000 },
    });

    const app = await buildAppServer((a) => {
      a.use(...stack);
      a.get('/ping', (_req, res) => res.json({ ok: true }));
    });
    cleanups.push(app.close);

    await fetch(`${app.url}/ping`);
    await fetch(`${app.url}/ping`);

    // Without close(), the batch=100 + 60s interval means nothing has shipped yet.
    expect(received).toHaveLength(0);

    stack.close();
    await vi.waitFor(() => expect(received).toHaveLength(2));

    expect(received).toHaveLength(2);
    for (const e of received) expect(e.decision).toBe('allow');
  });
});
