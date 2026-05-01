import type { TelemetryEvent, TelemetryOptions } from './types';

const DEFAULT_BATCH_SIZE = 50;
const MAX_BATCH_SIZE = 500; // matches server Zod schema upper bound
const DEFAULT_FLUSH_INTERVAL_MS = 5000;
const MIN_FLUSH_INTERVAL_MS = 500;
const FLUSH_TIMEOUT_MS = 10_000;

type Listener = (err: Error) => void;

/**
 * In-memory batching client that ships `TelemetryEvent` objects to an
 * Arcis dashboard server.
 *
 * Design rules (spec/API_SPEC.md §9):
 *   1. `record()` is synchronous and never throws — safe to call from hot paths.
 *   2. Flushes trigger on batchSize OR flushIntervalMs, whichever comes first.
 *   3. Network errors are fail-open: they call `onError` (if provided) and
 *      drop the batch. No retry, no disk persistence, no backpressure.
 *   4. `close()` attempts one final flush; safe to call multiple times.
 *   5. Interval timer uses `unref()` so it never holds the process open.
 */
export class TelemetryClient {
  private queue: TelemetryEvent[] = [];
  private readonly endpoint: string;
  private readonly apiKey: string | undefined;
  private readonly workspaceId: string | undefined;
  private readonly batchSize: number;
  private readonly flushIntervalMs: number;
  private readonly onError: Listener;
  private timer: ReturnType<typeof setInterval> | undefined;
  private flushing = false;
  private closed = false;
  private signalHandler: (() => void) | undefined;

  constructor(options: TelemetryOptions) {
    if (!options.endpoint || typeof options.endpoint !== 'string') {
      throw new TypeError('TelemetryClient: `endpoint` is required');
    }

    this.endpoint = options.endpoint;
    this.apiKey = options.apiKey;
    this.workspaceId = options.workspaceId;
    this.batchSize = clamp(
      options.batchSize ?? DEFAULT_BATCH_SIZE,
      1,
      MAX_BATCH_SIZE,
    );
    this.flushIntervalMs = Math.max(
      options.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS,
      MIN_FLUSH_INTERVAL_MS,
    );
    this.onError = options.onError ?? (() => {
      // default: swallow silently (fail-open)
    });

    this.startTimer();
  }

  /**
   * Enqueue an event. Fast, synchronous, cannot throw.
   * Triggers a flush if the queue has reached `batchSize`.
   */
  record(event: TelemetryEvent): void {
    if (this.closed) return;
    this.queue.push(event);
    if (this.queue.length >= this.batchSize) {
      // fire and forget
      void this.flush();
    }
  }

  /**
   * Manually flush the queue. Pulls up to `batchSize` events into a batch and
   * POSTs them. Returns a resolved promise on success OR on handled failure.
   * Never throws.
   */
  async flush(): Promise<void> {
    if (this.flushing) return;
    if (this.queue.length === 0) return;

    this.flushing = true;
    try {
      const batch = this.queue.splice(0, this.batchSize);
      await this.send(batch);
    } catch (err) {
      this.safeNotify(err);
    } finally {
      this.flushing = false;
    }

    // Drain anything that arrived while we were flushing.
    if (!this.closed && this.queue.length > 0) {
      void this.flush();
    }
  }

  /**
   * Shut down: stop the interval timer and attempt one final flush.
   * Safe to call multiple times.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;

    if (this.timer !== undefined) {
      clearInterval(this.timer);
      this.timer = undefined;
    }

    if (this.signalHandler !== undefined) {
      process.off('SIGTERM', this.signalHandler);
      process.off('SIGINT', this.signalHandler);
      this.signalHandler = undefined;
    }

    // final best-effort flush
    try {
      await this.flush();
    } catch {
      // fail-open on shutdown
    }
  }

  /**
   * Register `SIGTERM` / `SIGINT` handlers that call `close()` to drain
   * the queue on graceful shutdown. Opt-in — libraries should not silently
   * attach global signal handlers. Safe to call multiple times.
   */
  installShutdownHooks(): void {
    if (this.signalHandler !== undefined || this.closed) return;
    const handler = (): void => {
      void this.close();
    };
    this.signalHandler = handler;
    process.once('SIGTERM', handler);
    process.once('SIGINT', handler);
  }

  /** Count of events currently waiting to be sent. Useful for tests. */
  get pendingCount(): number {
    return this.queue.length;
  }

  // ── internals ─────────────────────────────────────────────────────────

  private async send(batch: TelemetryEvent[]): Promise<void> {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
    };
    if (this.apiKey) headers['authorization'] = `Bearer ${this.apiKey}`;
    if (this.workspaceId) headers['x-workspace-id'] = this.workspaceId;

    const controller = new AbortController();
    const abortTimer = setTimeout(() => controller.abort(), FLUSH_TIMEOUT_MS);

    try {
      const res = await fetch(this.endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify({ events: batch }),
        signal: controller.signal,
      });

      if (!res.ok) {
        const text = await safeReadBody(res);
        throw new TelemetryHttpError(res.status, text);
      }
    } finally {
      clearTimeout(abortTimer);
    }
  }

  private startTimer(): void {
    this.timer = setInterval(() => {
      void this.flush();
    }, this.flushIntervalMs);

    // node-only: don't block process exit
    (this.timer as { unref?: () => void }).unref?.();
  }

  private safeNotify(err: unknown): void {
    try {
      this.onError(err instanceof Error ? err : new Error(String(err)));
    } catch {
      // user-provided hook must never bubble up
    }
  }
}

export class TelemetryHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly responseBody: string,
  ) {
    super(`Telemetry ingest returned HTTP ${status}`);
    this.name = 'TelemetryHttpError';
  }
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.max(min, Math.min(max, Math.trunc(value)));
}

async function safeReadBody(res: Response): Promise<string> {
  try {
    const text = await res.text();
    return text.slice(0, 500);
  } catch {
    return '';
  }
}
