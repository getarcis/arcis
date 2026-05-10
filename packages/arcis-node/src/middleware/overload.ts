/**
 * @module @arcis/node/middleware/overload
 *
 * Event-loop overload protection (sdk-vectors.md tier 1 #30, issue #51).
 *
 * Rate limiting caps per-client load; this middleware caps **total server
 * load** by sampling event-loop lag and shedding new requests with 503
 * when the loop is saturated. Pairs with rate-limit (per-client) +
 * `methodAllowlist` (per-route) to give Arcis three orthogonal layers
 * of "this server is healthy enough to do work" gating.
 *
 * ```ts
 * import { eventLoopProtection } from '@arcis/node';
 *
 * app.use(eventLoopProtection({
 *   maxLagMs: 500,         // 503 above this smoothed lag
 *   sampleIntervalMs: 250, // measure every 250ms
 * }));
 * ```
 *
 * Sampling strategy:
 *   - `setInterval(fn, sampleIntervalMs)` is scheduled; the callback
 *     compares wall-clock elapsed against the configured interval. Lag
 *     IS the difference: when the loop is busy, the timer fires late.
 *   - The interval handle is `.unref()`-ed so the process can exit
 *     cleanly even if the caller forgets to call `close()`.
 *   - Exponential moving average (`smoothed = 0.7 * smoothed + 0.3 *
 *     measured`) smooths out single-sample spikes — a 600ms GC pause
 *     shouldn't cause every request to 503 for the next sample window.
 *
 * Implementation deliberately picks `setTimeout` measurement over
 * `perf_hooks.monitorEventLoopDelay` (Node 12+ alternative) for two
 * reasons: (1) it works on every supported Node version with no feature
 * detection branch, (2) the perf_hooks histogram returns nanosecond
 * lag from a 10ms-resolution sampler, but applying the spec's EMA
 * formula on that signal would skew toward unreal lag values that the
 * sampler smoothed away. Keeping the sampler the spec calls for keeps
 * the math testable.
 */

import type { RequestHandler, Response } from 'express';

export interface EventLoopProtectionOptions {
  /** Smoothed lag threshold in ms above which the middleware returns 503. Default: 500. */
  maxLagMs?: number;
  /** Sample frequency in ms. Default: 250. Lower = more responsive, higher = less overhead. */
  sampleIntervalMs?: number;
  /** Status code to return when overloaded. Default: 503. */
  statusCode?: number;
  /** Error message in the response body. Default: "Server overloaded, please retry". */
  message?: string;
  /** Retry-After header value in seconds. Default: 5. */
  retryAfterSeconds?: number;
  /**
   * EMA smoothing factor for the new measurement. Default: 0.3 (per
   * issue #51 spec). Must be in (0, 1]; lower values smooth harder
   * (longer memory of past samples), higher values track more reactively.
   */
  alpha?: number;
  /**
   * When true, every response gets `X-EventLoop-Lag: <ms>` so monitoring
   * can graph saturation independent of the deny decision. Off by default
   * because most apps don't need it and an extra header on every response
   * adds noise.
   */
  exposeLagHeader?: boolean;
}

export interface EventLoopProtectionMiddleware extends RequestHandler {
  /**
   * Stop the sampler. Call from a SIGTERM handler so the interval doesn't
   * keep a misconfigured process alive. Idempotent: subsequent calls are
   * no-ops.
   */
  close(): void;
  /**
   * Read the current smoothed lag in ms. Useful for tests that want to
   * assert the smoothing math without mocking timers, and for callers
   * who want to expose the value through a different surface (Prometheus,
   * dashboard panel, etc.).
   */
  currentLagMs(): number;
}

const DEFAULTS = {
  maxLagMs: 500,
  sampleIntervalMs: 250,
  statusCode: 503,
  message: 'Server overloaded, please retry',
  retryAfterSeconds: 5,
  alpha: 0.3,
} as const;

/**
 * Build an event-loop protection middleware. Returns a request handler
 * with `close()` and `currentLagMs()` attached (Pattern 6 in the
 * monorepo's middleware conventions: factories return a callable
 * augmented with cleanup helpers).
 */
export function eventLoopProtection(
  options: EventLoopProtectionOptions = {},
): EventLoopProtectionMiddleware {
  const maxLagMs = options.maxLagMs ?? DEFAULTS.maxLagMs;
  const sampleIntervalMs = options.sampleIntervalMs ?? DEFAULTS.sampleIntervalMs;
  const statusCode = options.statusCode ?? DEFAULTS.statusCode;
  const message = options.message ?? DEFAULTS.message;
  const retryAfterSeconds = options.retryAfterSeconds ?? DEFAULTS.retryAfterSeconds;
  const alpha = options.alpha ?? DEFAULTS.alpha;
  const exposeLagHeader = options.exposeLagHeader === true;

  // Validate up-front so misconfiguration surfaces at app boot, not on
  // the first overloaded request.
  if (maxLagMs <= 0) {
    throw new RangeError('eventLoopProtection: maxLagMs must be > 0');
  }
  if (sampleIntervalMs <= 0) {
    throw new RangeError('eventLoopProtection: sampleIntervalMs must be > 0');
  }
  if (alpha <= 0 || alpha > 1) {
    throw new RangeError('eventLoopProtection: alpha must be in (0, 1]');
  }

  let smoothedLag = 0;
  let lastTickTime = Date.now();
  let stopped = false;

  // Sampler: each tick measures elapsed time vs the configured interval.
  // The difference is the lag — on a healthy loop it's ~0; on a saturated
  // loop the timer fires late. Apply the EMA after every measurement so
  // the value the middleware reads on the NEXT request is smoothed.
  const interval = setInterval(() => {
    const now = Date.now();
    const elapsed = now - lastTickTime;
    const measuredLag = Math.max(0, elapsed - sampleIntervalMs);
    smoothedLag = (1 - alpha) * smoothedLag + alpha * measuredLag;
    lastTickTime = now;
  }, sampleIntervalMs);

  // Don't pin the process alive. The Node `Timer.unref()` returns the
  // handle so we can chain it; behavior is well-known across versions.
  if (typeof interval.unref === 'function') {
    interval.unref();
  }

  const middleware = ((_req, res, next) => {
    if (exposeLagHeader) {
      // Round to ms for header sanity — float values render awkwardly.
      res.setHeader('X-EventLoop-Lag', Math.round(smoothedLag).toString());
    }
    if (!stopped && smoothedLag > maxLagMs) {
      (res as Response).setHeader('Retry-After', retryAfterSeconds.toString());
      res.status(statusCode).json({
        error: message,
        retryAfter: retryAfterSeconds,
      });
      return;
    }
    next();
  }) as EventLoopProtectionMiddleware;

  middleware.close = () => {
    if (stopped) return;
    stopped = true;
    clearInterval(interval);
  };

  middleware.currentLagMs = () => smoothedLag;

  return middleware;
}

export default eventLoopProtection;

// Test-only export so tests can drive the smoother without spinning real
// timers. Computes one EMA step against the supplied prior + measurement.
export const __test = {
  ema(prior: number, measured: number, alpha: number): number {
    return (1 - alpha) * prior + alpha * measured;
  },
};
