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
import { TelemetryClient } from '../../src/telemetry/client';

interface ParityCase {
  name: string;
  config: Record<string, unknown>;
  request: {
    method: string;
    path: string;
    body?: Record<string, unknown>;
    headers?: Record<string, string>;
    repeat?: number;
  };
  compare_event_index?: number;
  application_status?: number;
  expected_request_unchanged?: boolean;
  expected_absent_fields?: (keyof TelemetryEvent)[];
  expected_event: Partial<TelemetryEvent>;
}

interface ApplicationErrorCase extends ParityCase {
  error_status: number;
  application_status: number;
  expected_body: string;
  expected_status_by_adapter: { express: number };
}

interface FindingCase {
  name: string;
  config: ParityCase['config'];
  request: ParityCase['request'];
  expected_finding: Partial<TelemetryEvent>;
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH = resolve(__dirname, '..', '..', '..', '..', 'spec', 'TEST_VECTORS.json');

const vectors = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as {
  telemetry: {
    middleware_emission: { compared_fields: string[]; cases: ParityCase[] };
    application_errors: { cases: ApplicationErrorCase[] };
    finding_attribution: { cases: FindingCase[] };
    privacy: {
      invalid_labels: string[];
      metadata: { config: { routeId: string; policyId: string }; expected: Record<string, string> };
      expected_path: string;
      absent_fields: string[];
      cases: (FindingCase & { forbidden_values: string[] })[];
    };
  };
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

async function buildAppWithArcis(
  arcisConfig: Record<string, unknown>,
  applicationStatus = 200,
  applicationError?: ApplicationErrorCase,
) {
  const stack = arcis(arcisConfig);
  const app = express();
  app.use(express.json());
  app.use(...stack);
  const failure = new Error('private application detail');
  Object.assign(failure, { statusCode: applicationError?.error_status });
  app.use((req, res, next) => {
    if (applicationError) return next(failure);
    res.status(applicationStatus).json({ body: req.body });
  });
  app.use((err: { statusCode?: number; message?: string }, _req: express.Request, res: express.Response, _n: express.NextFunction) => {
    if (applicationError) {
      if (err === failure) res.setHeader('X-Error-Propagated', 'yes');
      res.status(applicationError.application_status).send(applicationError.expected_body);
      return;
    }
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
      const app = await buildAppWithArcis(config, c.application_status);
      cleanups.push(() => app.stack.close());
      cleanups.push(app.close);

      const repeat = c.request.repeat ?? 1;
      let lastResponseBody: { body?: Record<string, unknown> } | undefined;
      for (let i = 0; i < repeat; i++) {
        const response = await fetch(`${app.url}${c.request.path}`, {
          method: c.request.method,
          headers: c.request.body ? { 'content-type': 'application/json' } : undefined,
          body: c.request.body ? JSON.stringify(c.request.body) : undefined,
        });
        if (c.application_status) expect(response.status).toBe(c.application_status);
        if (c.expected_request_unchanged) {
          lastResponseBody = await response.json() as { body?: Record<string, unknown> };
        }
      }

      if (c.expected_request_unchanged) {
        expect(lastResponseBody?.body).toEqual(c.request.body);
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

      for (const field of c.expected_absent_fields ?? []) {
        expect(event).not.toHaveProperty(field);
      }

      for (const field of compared) {
        const expected = (c.expected_event as Record<string, unknown>)[field];
        if (expected === undefined) continue;
        expect(event[field as keyof TelemetryEvent]).toBe(expected);
      }
    });
  }

  it.each([
    { dryRun: false, status: 451, decision: 'deny' },
    { dryRun: true, status: 200, decision: 'would_deny' },
  ])('reports a custom rate-limit rejection with dryRun=$dryRun', async ({ dryRun, status, decision }) => {
    const received: TelemetryEvent[] = [];
    const ingest = await buildIngest(received);
    cleanups.push(ingest.close);
    const app = await buildAppWithArcis({
      dryRun,
      rateLimit: { max: 1, statusCode: 451 },
      telemetry: { endpoint: ingest.url, batchSize: 1 },
    });
    cleanups.push(() => app.stack.close());
    cleanups.push(app.close);

    expect((await fetch(`${app.url}/ping`)).status).toBe(200);
    expect((await fetch(`${app.url}/ping`)).status).toBe(status);
    await vi.waitFor(() => expect(received).toHaveLength(2));
    expect(received[0].decision).toBe('allow');
    expect(received[1]).toMatchObject({
      decision, status, vector: 'rate-limit', rule: 'rate-limit/exceeded', severity: 'medium',
    });
  });
});

describe('application errors preserve decisions and response ownership', () => {
  it.each(vectors.telemetry.application_errors.cases)('$name', async (c) => {
    const received: TelemetryEvent[] = [];
    const ingest = await buildIngest(received);
    cleanups.push(ingest.close);
    const app = await buildAppWithArcis({
      ...c.config,
      telemetry: { endpoint: ingest.url, batchSize: 1 },
    }, c.application_status, c);
    cleanups.push(() => app.stack.close());
    cleanups.push(app.close);
    const response = await fetch(`${app.url}${c.request.path}`, {
      method: c.request.method,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(c.request.body),
    });
    expect(response.status).toBe(c.application_status);
    expect(await response.text()).toBe(c.expected_body);
    expect(response.headers.get('X-Error-Propagated')).toBe('yes');
    await vi.waitFor(() => expect(received).toHaveLength(1));
    expect(received[0]).toMatchObject({
      ...c.expected_event, status: c.expected_status_by_adapter.express,
    });
  });
});

describe.each([false, true])('finding attribution with dryRun=%s', (dryRun) => {
  it.each(vectors.telemetry.finding_attribution.cases)('$name', async (c) => {
    const received: TelemetryEvent[] = [];
    const ingest = await buildIngest(received);
    cleanups.push(ingest.close);
    const app = await buildAppWithArcis({
      ...c.config, dryRun,
      telemetry: { endpoint: ingest.url, batchSize: 1 },
    });
    cleanups.push(() => app.stack.close());
    cleanups.push(app.close);
    const response = await fetch(`${app.url}${c.request.path}`, {
      method: c.request.method,
      headers: { 'content-type': 'application/json', ...c.request.headers },
      body: JSON.stringify(c.request.body),
    });
    expect(response.status).toBe(dryRun ? 200 : 403);
    if (dryRun) expect((await response.json()).body).toEqual(c.request.body);
    await vi.waitFor(() => expect(received).toHaveLength(1));
    expect(received[0]).toMatchObject({
      ...c.expected_finding, decision: dryRun ? 'would_deny' : 'deny',
      status: dryRun ? 200 : 403,
    });
  });
});

describe.each([false, true])('telemetry privacy with dryRun=%s', (dryRun) => {
  it.each(vectors.telemetry.privacy.cases)('$name', async (c) => {
    const received: TelemetryEvent[] = [];
    const ingest = await buildIngest(received);
    cleanups.push(ingest.close);
    const app = await buildAppWithArcis({
      block: true, rateLimit: false, dryRun,
      telemetry: { endpoint: ingest.url, batchSize: 1, ...vectors.telemetry.privacy.metadata.config },
    });
    cleanups.push(() => app.stack.close());
    cleanups.push(app.close);
    const response = await fetch(`${app.url}${c.request.path}`, {
      method: c.request.method,
      headers: { 'content-type': 'application/json', ...c.request.headers },
      body: JSON.stringify(c.request.body),
    });
    expect(response.status).toBe(dryRun ? 200 : 403);
    if (dryRun) expect((await response.json()).body).toEqual(c.request.body);
    await vi.waitFor(() => expect(received).toHaveLength(1));
    const event = received[0];
    expect(event).toMatchObject({
      ...c.expected_finding, path: vectors.telemetry.privacy.expected_path,
      ...vectors.telemetry.privacy.metadata.expected, sdk: 'node',
      decision: dryRun ? 'would_deny' : 'deny', status: dryRun ? 200 : 403,
    });
    for (const field of vectors.telemetry.privacy.absent_fields) {
      expect(event).not.toHaveProperty(field);
    }
    for (const secret of c.forbidden_values) {
      expect(JSON.stringify(event)).not.toContain(secret);
    }
  });
});

it.each(['allow', 'deny', 'challenge', 'would_deny'] as const)(
  'snapshots safe metadata for manually recorded %s events', async (decision) => {
    const received: TelemetryEvent[] = [];
    const ingest = await buildIngest(received);
    cleanups.push(ingest.close);
    const client = new TelemetryClient({ endpoint: ingest.url, batchSize: 500, flushIntervalMs: 60_000 });
    cleanups.push(() => client.close());
    const original = {
      ip: 'forwarded-secret-201', method: 'POST', path: '/reset/path-secret-201',
      decision, status: 422, vector: 'xss', rule: 'xss/match', severity: 'high' as const,
      userAgent: 'ua-secret-201', reason: 'body-secret-201',
      matchedPattern: 'body-secret-201', body: { token: 'extra-secret-201' },
      routeId: 'route-secret-201', policyId: 'policy-secret-201', sdk: 'go' as const,
    };
    client.record(original);
    expect(original.path).toBe('/reset/path-secret-201');
    expect(original.matchedPattern).toBe('body-secret-201');
    original.rule = 'changed-after-record';
    await client.flush();
    await vi.waitFor(() => expect(received).toHaveLength(1));
    expect(received[0]).toMatchObject({
      ip: '0.0.0.0', path: '[redacted]', method: 'POST', decision, status: 422,
      vector: 'xss', rule: 'xss/match', severity: 'high',
    });
    expect(JSON.stringify(received[0])).not.toContain('secret-201');
    expect(received[0]).toMatchObject({ schemaVersion: '1.1', sdk: 'node' });
    expect(received[0]).not.toHaveProperty('routeId');
    expect(received[0]).not.toHaveProperty('policyId');
    for (const field of vectors.telemetry.privacy.absent_fields) {
      expect(received[0]).not.toHaveProperty(field);
    }
  },
);

describe.each(['routeId', 'policyId'] as const)('invalid %s telemetry label', (field) => {
  it.each(vectors.telemetry.privacy.invalid_labels)('rejects %j without echoing it', (label) => {
    expect(() => {
      const client = new TelemetryClient({ endpoint: 'http://127.0.0.1/v1/events', [field]: label });
      cleanups.push(() => client.close());
    }).toThrow(`TelemetryClient: invalid ${field}`);
  });
});
