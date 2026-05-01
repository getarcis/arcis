import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { TelemetryClient, TelemetryHttpError } from '../../src/telemetry/client';
import type { TelemetryEvent } from '../../src/telemetry/types';

const ENDPOINT = 'http://localhost:3333/v1/events';

function sampleEvent(overrides: Partial<TelemetryEvent> = {}): TelemetryEvent {
  return {
    ip: '1.2.3.4',
    method: 'POST',
    path: '/api/login',
    decision: 'deny',
    vector: 'sql',
    rule: 'sql/union-select',
    severity: 'critical',
    userAgent: 'sqlmap/1.8',
    status: 403,
    matchedPattern: 'UNION SELECT',
    latencyMs: 0.42,
    ...overrides,
  };
}

function okResponse(): Response {
  return new Response(JSON.stringify({ inserted: 1 }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

describe('TelemetryClient', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn().mockResolvedValue(okResponse());
    vi.stubGlobal('fetch', fetchSpy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('construction', () => {
    it('throws if endpoint is missing', () => {
      expect(() => new TelemetryClient({ endpoint: '' })).toThrow(/endpoint/);
    });

    it('clamps batchSize into [1, 500]', async () => {
      const tooBig = new TelemetryClient({ endpoint: ENDPOINT, batchSize: 99_999 });
      // push 501 — should still only flush 500 at a time since we clamp
      for (let i = 0; i < 501; i++) tooBig.record(sampleEvent());
      await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalled());
      const [, init] = fetchSpy.mock.calls[0]!;
      const body = JSON.parse(init.body as string);
      expect(body.events.length).toBe(500);
      await tooBig.close();
    });

    it('clamps flushIntervalMs to minimum 500ms', () => {
      const c = new TelemetryClient({ endpoint: ENDPOINT, flushIntervalMs: 10 });
      expect((c as unknown as { flushIntervalMs: number }).flushIntervalMs).toBe(500);
    });
  });

  describe('record + batch flush', () => {
    it('flushes when queue reaches batchSize', async () => {
      const client = new TelemetryClient({ endpoint: ENDPOINT, batchSize: 3 });
      client.record(sampleEvent({ ip: '1.1.1.1' }));
      client.record(sampleEvent({ ip: '2.2.2.2' }));
      expect(fetchSpy).not.toHaveBeenCalled();
      client.record(sampleEvent({ ip: '3.3.3.3' }));

      await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));
      const [url, init] = fetchSpy.mock.calls[0]!;
      expect(url).toBe(ENDPOINT);
      expect(init.method).toBe('POST');
      const body = JSON.parse(init.body as string);
      expect(body.events).toHaveLength(3);
      expect(body.events[0].ip).toBe('1.1.1.1');
      await client.close();
    });

    it('includes authorization and workspace headers when configured', async () => {
      const client = new TelemetryClient({
        endpoint: ENDPOINT,
        apiKey: 'secret-token',
        workspaceId: 'team-alpha',
        batchSize: 1,
      });
      client.record(sampleEvent());
      await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalled());
      const [, init] = fetchSpy.mock.calls[0]!;
      expect(init.headers['authorization']).toBe('Bearer secret-token');
      expect(init.headers['x-workspace-id']).toBe('team-alpha');
      expect(init.headers['content-type']).toBe('application/json');
      await client.close();
    });

    it('omits optional headers when not configured', async () => {
      const client = new TelemetryClient({ endpoint: ENDPOINT, batchSize: 1 });
      client.record(sampleEvent());
      await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalled());
      const [, init] = fetchSpy.mock.calls[0]!;
      expect(init.headers['authorization']).toBeUndefined();
      expect(init.headers['x-workspace-id']).toBeUndefined();
      await client.close();
    });

    it('record is synchronous and does not throw even with bad endpoint', () => {
      const client = new TelemetryClient({
        endpoint: 'http://127.0.0.1:1/does-not-exist',
        batchSize: 1,
      });
      expect(() => client.record(sampleEvent())).not.toThrow();
      void client.close();
    });
  });

  describe('interval flush', () => {
    it('flushes partial batch when flushIntervalMs elapses', async () => {
      vi.useFakeTimers();
      const client = new TelemetryClient({
        endpoint: ENDPOINT,
        batchSize: 100,
        flushIntervalMs: 500,
      });
      client.record(sampleEvent());
      expect(fetchSpy).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(500);

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const [, init] = fetchSpy.mock.calls[0]!;
      const body = JSON.parse(init.body as string);
      expect(body.events).toHaveLength(1);

      await client.close();
    });

    it('does not fire the timer when queue is empty', async () => {
      vi.useFakeTimers();
      const client = new TelemetryClient({
        endpoint: ENDPOINT,
        batchSize: 100,
        flushIntervalMs: 500,
      });
      await vi.advanceTimersByTimeAsync(2000);
      expect(fetchSpy).not.toHaveBeenCalled();
      await client.close();
    });
  });

  describe('fail-open on errors', () => {
    it('invokes onError on non-2xx response and drops the batch', async () => {
      fetchSpy.mockResolvedValueOnce(
        new Response('server exploded', { status: 500 }),
      );
      const onError = vi.fn();
      const client = new TelemetryClient({ endpoint: ENDPOINT, batchSize: 1, onError });

      client.record(sampleEvent());

      await vi.waitFor(() => expect(onError).toHaveBeenCalledTimes(1));
      const err = onError.mock.calls[0]![0] as Error;
      expect(err).toBeInstanceOf(TelemetryHttpError);
      expect((err as TelemetryHttpError).status).toBe(500);
      expect(client.pendingCount).toBe(0);
      await client.close();
    });

    it('invokes onError on network rejection', async () => {
      fetchSpy.mockRejectedValueOnce(new Error('ECONNREFUSED'));
      const onError = vi.fn();
      const client = new TelemetryClient({ endpoint: ENDPOINT, batchSize: 1, onError });

      client.record(sampleEvent());

      await vi.waitFor(() => expect(onError).toHaveBeenCalledTimes(1));
      const err = onError.mock.calls[0]![0] as Error;
      expect(err.message).toContain('ECONNREFUSED');
      await client.close();
    });

    it('silently swallows errors when no onError is provided', async () => {
      fetchSpy.mockRejectedValueOnce(new Error('network down'));
      const client = new TelemetryClient({ endpoint: ENDPOINT, batchSize: 1 });
      client.record(sampleEvent());

      // no exception — and queue is drained
      await vi.waitFor(() => expect(client.pendingCount).toBe(0));
      await client.close();
    });

    it('swallows exceptions thrown from a user onError hook', async () => {
      fetchSpy.mockRejectedValueOnce(new Error('boom'));
      const client = new TelemetryClient({
        endpoint: ENDPOINT,
        batchSize: 1,
        onError: () => {
          throw new Error('user hook exploded');
        },
      });

      // must not throw
      expect(() => client.record(sampleEvent())).not.toThrow();
      await vi.waitFor(() => expect(client.pendingCount).toBe(0));
      await client.close();
    });
  });

  describe('close()', () => {
    it('attempts a final flush', async () => {
      const client = new TelemetryClient({ endpoint: ENDPOINT, batchSize: 100 });
      client.record(sampleEvent());
      client.record(sampleEvent());
      expect(fetchSpy).not.toHaveBeenCalled();

      await client.close();

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const [, init] = fetchSpy.mock.calls[0]!;
      const body = JSON.parse(init.body as string);
      expect(body.events).toHaveLength(2);
    });

    it('stops the interval timer', async () => {
      vi.useFakeTimers();
      const client = new TelemetryClient({
        endpoint: ENDPOINT,
        batchSize: 100,
        flushIntervalMs: 500,
      });
      await client.close();

      // queue an event after close — the timer should not fire again
      // (we also don't allow record to add after close)
      client.record(sampleEvent());
      await vi.advanceTimersByTimeAsync(2000);
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('is safe to call more than once', async () => {
      const client = new TelemetryClient({ endpoint: ENDPOINT, batchSize: 100 });
      await client.close();
      await client.close();
      await client.close();
      // no assertion — the test passes if no throw happens
    });

    it('ignores record() calls made after close', () => {
      const client = new TelemetryClient({ endpoint: ENDPOINT, batchSize: 1 });
      void client.close();
      client.record(sampleEvent());
      expect(client.pendingCount).toBe(0);
    });
  });

  describe('installShutdownHooks()', () => {
    it('flushes pending events when SIGTERM fires', async () => {
      const client = new TelemetryClient({ endpoint: ENDPOINT, batchSize: 100 });
      client.installShutdownHooks();
      client.record(sampleEvent());
      expect(fetchSpy).not.toHaveBeenCalled();

      process.emit('SIGTERM');

      await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));
      // close() was called by the handler — calling again is a no-op
      await client.close();
    });

    it('detaches handlers on close to avoid leaks', async () => {
      const before = process.listenerCount('SIGTERM');
      const client = new TelemetryClient({ endpoint: ENDPOINT });
      client.installShutdownHooks();
      expect(process.listenerCount('SIGTERM')).toBe(before + 1);
      await client.close();
      expect(process.listenerCount('SIGTERM')).toBe(before);
    });

    it('is idempotent when called multiple times', async () => {
      const before = process.listenerCount('SIGTERM');
      const client = new TelemetryClient({ endpoint: ENDPOINT });
      client.installShutdownHooks();
      client.installShutdownHooks();
      client.installShutdownHooks();
      expect(process.listenerCount('SIGTERM')).toBe(before + 1);
      await client.close();
    });
  });

  describe('event body shape', () => {
    it('wraps events in { events: [...] } to match server Zod schema', async () => {
      const client = new TelemetryClient({ endpoint: ENDPOINT, batchSize: 1 });
      const evt = sampleEvent({
        ts: '2026-04-23T04:00:00.000Z',
        country: 'RU',
        reason: 'UNION SELECT pattern in body',
      });
      client.record(evt);

      await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalled());
      const [, init] = fetchSpy.mock.calls[0]!;
      const body = JSON.parse(init.body as string);

      expect(body).toHaveProperty('events');
      expect(Array.isArray(body.events)).toBe(true);
      expect(body.events).toHaveLength(1);
      expect(body.events[0]).toMatchObject({
        ts: '2026-04-23T04:00:00.000Z',
        ip: '1.2.3.4',
        method: 'POST',
        path: '/api/login',
        decision: 'deny',
        vector: 'sql',
        rule: 'sql/union-select',
        severity: 'critical',
        country: 'RU',
        reason: 'UNION SELECT pattern in body',
        status: 403,
        matchedPattern: 'UNION SELECT',
        latencyMs: 0.42,
      });
      await client.close();
    });

    it('does not drop a spec-defined field from TelemetryEvent', async () => {
      const client = new TelemetryClient({ endpoint: ENDPOINT, batchSize: 1 });
      const allFields: TelemetryEvent = {
        ts: '2026-04-23T04:00:00.000Z',
        ip: '9.9.9.9',
        method: 'PUT',
        path: '/api/x',
        decision: 'challenge',
        vector: 'bot',
        rule: 'bot/scanner',
        severity: 'medium',
        country: 'DE',
        userAgent: 'nikto',
        reason: 'scanner ua',
        status: 429,
        matchedPattern: 'Nikto',
        latencyMs: 0.77,
      };
      client.record(allFields);

      await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalled());
      const body = JSON.parse(fetchSpy.mock.calls[0]![1].body as string);
      // every key we wrote must round-trip through JSON.stringify intact
      expect(body.events[0]).toEqual(allFields);
      await client.close();
    });
  });
});
