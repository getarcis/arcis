/**
 * Phase 9: cross-SDK parity vectors.
 * Loads spec/TEST_VECTORS.json → telemetry.middleware_emission and runs each
 * case through arcis(). Python and Go SDKs replay the same cases.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { createServer } from 'http';
import type { AddressInfo } from 'net';
import arcis from '../../src/index';
import type { TelemetryEvent } from '../../src/telemetry/types';

interface ParityCase {
  name: string;
  config: Record<string, unknown>;
  request: {
    method: string;
    path: string;
    body?: Record<string, unknown>;
    repeat?: number;
  };
  compare_event_index?: number;
  expected_event: Partial<TelemetryEvent>;
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH = resolve(__dirname, '..', '..', '..', '..', 'spec', 'TEST_VECTORS.json');

const vectors = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as {
  telemetry: { middleware_emission: { compared_fields: string[]; cases: ParityCase[] } };
};

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  for (const fn of cleanups.splice(0)) await fn();
});

async function buildIngest(received: TelemetryEvent[]) {
  const app = express();
  app.use(express.json());
  app.post('/v1/events', (req, res) => {
    for (const e of (req.body as { events: TelemetryEvent[] }).events ?? []) received.push(e);
    res.json({ inserted: 1 });
  });
  return new Promise<{ url: string; close: () => Promise<void> }>((resolve) => {
    const server = createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        url: `http://127.0.0.1:${port}/v1/events`,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

async function buildAppWithArcis(arcisConfig: Record<string, unknown>) {
  const stack = arcis(arcisConfig);
  const app = express();
  app.use(express.json());
  app.use(...stack);
  app.use((_req, res) => res.json({ ok: true }));
  app.use((err: { statusCode?: number; message?: string }, _req: express.Request, res: express.Response, _n: express.NextFunction) => {
    res.status(err.statusCode ?? 500).json({ error: err.message ?? 'error' });
  });
  return new Promise<{ url: string; close: () => Promise<void>; stack: typeof stack }>((resolve) => {
    const server = createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        url: `http://127.0.0.1:${port}`,
        stack,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

describe('Phase 9: cross-SDK parity (middleware_emission)', () => {
  const compared = vectors.telemetry.middleware_emission.compared_fields;

  for (const c of vectors.telemetry.middleware_emission.cases) {
    it(`emits expected event for "${c.name}"`, async () => {
      const received: TelemetryEvent[] = [];
      const ingest = await buildIngest(received);
      cleanups.push(ingest.close);

      const config = {
        ...c.config,
        telemetry: { endpoint: ingest.url, batchSize: 1, flushIntervalMs: 500 },
      };
      const app = await buildAppWithArcis(config);
      cleanups.push(() => app.stack.close());
      cleanups.push(app.close);

      const repeat = c.request.repeat ?? 1;
      for (let i = 0; i < repeat; i++) {
        await fetch(`${app.url}${c.request.path}`, {
          method: c.request.method,
          headers: c.request.body ? { 'content-type': 'application/json' } : undefined,
          body: c.request.body ? JSON.stringify(c.request.body) : undefined,
        });
      }

      const idx = c.compare_event_index ?? 0;
      await vi.waitFor(
        () =>
          expect(
            received[idx],
            `no event at index ${idx} (received ${received.length})`,
          ).toBeDefined(),
      );
      const event = received[idx]!;

      for (const field of compared) {
        const expected = (c.expected_event as Record<string, unknown>)[field];
        if (expected === undefined) continue;
        expect(event[field as keyof TelemetryEvent]).toBe(expected);
      }
    });
  }
});
