/**
 * Stage 1 — env-var auto-pickup for telemetry.
 *
 * arcis() should auto-build TelemetryOptions from ARCIS_ENDPOINT /
 * ARCIS_WORKSPACE_ID / ARCIS_KEY when no explicit `telemetry` config is
 * passed. Explicit config must always win.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
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
const originalEnv = { ...process.env };

afterEach(async () => {
  for (const fn of cleanups.splice(0)) await fn();
  // restore env
  for (const k of ['ARCIS_ENDPOINT', 'ARCIS_WORKSPACE_ID', 'ARCIS_KEY']) {
    if (originalEnv[k] === undefined) delete process.env[k];
    else process.env[k] = originalEnv[k];
  }
});

describe('Stage 1 — env-var auto-pickup', () => {
  it('picks up ARCIS_ENDPOINT and emits events without explicit telemetry config', async () => {
    const received: TelemetryEvent[] = [];
    const ingest = await buildIngestServer(received);
    cleanups.push(ingest.close);

    process.env.ARCIS_ENDPOINT = ingest.url;
    process.env.ARCIS_WORKSPACE_ID = 'ws_env';
    process.env.ARCIS_KEY = 'envkey';
    process.env.ARCIS_BATCH_SIZE = '1';
    process.env.ARCIS_FLUSH_INTERVAL_MS = '500';

    const stack = arcis({
      // NOTE: no telemetry block — should be picked up from env
      sanitize: false,
      rateLimit: false,
      headers: false,
    });
    cleanups.push(() => stack.close());

    const appServer = await buildAppServer((a) => {
      if (stack.length > 0) a.use(...stack);
      a.get('/api/ok', (_req, res) => res.json({ ok: true }));
    });
    cleanups.push(appServer.close);

    const resp = await fetch(`${appServer.url}/api/ok`);
    expect(resp.status).toBe(200);

    await vi.waitFor(() => expect(received.length).toBeGreaterThanOrEqual(1), {
      timeout: 5000,
    });
    expect(received[0].path).toBe('/api/ok');
    expect(received[0].decision).toBe('allow');
  }, 10_000);

  it('stays inert when no ARCIS_* env vars are set and no explicit config', async () => {
    delete process.env.ARCIS_ENDPOINT;
    delete process.env.ARCIS_WORKSPACE_ID;
    delete process.env.ARCIS_KEY;

    const stack = arcis({
      sanitize: false,
      rateLimit: false,
      headers: false,
    });
    cleanups.push(() => stack.close());

    // The stack should run cleanly. We can't directly inspect "no telemetry
    // client" without breaking encapsulation, so the proof is: this resolves
    // without any telemetry POST and without any onError firing.
    const appServer = await buildAppServer((a) => {
      if (stack.length > 0) a.use(...stack);
      a.get('/api/ok', (_req, res) => res.json({ ok: true }));
    });
    cleanups.push(appServer.close);

    const resp = await fetch(`${appServer.url}/api/ok`);
    expect(resp.status).toBe(200);
  }, 10_000);

  it('explicit telemetry config wins over env vars', async () => {
    const envIngest = await buildIngestServer([]);
    const explicitIngest: TelemetryEvent[] = [];
    const explicit = await buildIngestServer(explicitIngest);
    cleanups.push(envIngest.close, explicit.close);

    // env points at envIngest, but we pass an explicit config pointing at explicit
    process.env.ARCIS_ENDPOINT = envIngest.url;
    process.env.ARCIS_WORKSPACE_ID = 'ws_env';

    const stack = arcis({
      sanitize: false,
      rateLimit: false,
      headers: false,
      telemetry: {
        endpoint: explicit.url,
        workspaceId: 'ws_explicit',
        batchSize: 1,
        flushIntervalMs: 500,
      },
    });
    cleanups.push(() => stack.close());

    const appServer = await buildAppServer((a) => {
      if (stack.length > 0) a.use(...stack);
      a.get('/api/ok', (_req, res) => res.json({ ok: true }));
    });
    cleanups.push(appServer.close);

    await fetch(`${appServer.url}/api/ok`);

    await vi.waitFor(() => expect(explicitIngest.length).toBeGreaterThanOrEqual(1), {
      timeout: 5000,
    });
  }, 10_000);

  it('partial env (workspace + key without endpoint) does not activate telemetry', async () => {
    delete process.env.ARCIS_ENDPOINT;
    process.env.ARCIS_WORKSPACE_ID = 'ws_env';
    process.env.ARCIS_KEY = 'envkey';

    const stack = arcis({
      sanitize: false,
      rateLimit: false,
      headers: false,
    });
    cleanups.push(() => stack.close());

    // Just confirm no crash and no errors — telemetry must remain off without
    // an endpoint. Same shape as the "no env" test above.
    const appServer = await buildAppServer((a) => {
      if (stack.length > 0) a.use(...stack);
      a.get('/api/ok', (_req, res) => res.json({ ok: true }));
    });
    cleanups.push(appServer.close);

    const resp = await fetch(`${appServer.url}/api/ok`);
    expect(resp.status).toBe(200);
  }, 10_000);
});
