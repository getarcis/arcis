/**
 * @module @arcis/node/middleware/main
 * Main arcis() middleware factory
 */

import type { RequestHandler } from 'express';
import type {
  ArcisOptions,
  ArcisFunction,
  ArcisMiddlewareStack,
  HeaderOptions,
  RateLimitOptions,
  SanitizeOptions,
} from '../core/types';
import { createHeaders } from './headers';
import { createRateLimiter } from './rate-limit';
import { createErrorHandler } from './error-handler';
import { createTelemetryEmitter, tapSanitizerThreats } from './telemetry';
import { createSanitizer } from '../sanitizers';
import { validate } from '../validation';
import { createSafeLogger } from '../logging';
import { TelemetryClient } from '../telemetry/client';
import type { TelemetryOptions } from '../telemetry/types';

/**
 * Build TelemetryOptions from `ARCIS_*` environment variables when the user
 * didn't pass `telemetry` in `arcis({...})`. Returns undefined if `ARCIS_ENDPOINT`
 * isn't set — preserving zero-overhead opt-in.
 *
 * Recognized env vars:
 *   - `ARCIS_ENDPOINT`           (required to activate)
 *   - `ARCIS_WORKSPACE_ID`       (optional; sent as x-workspace-id)
 *   - `ARCIS_KEY`                (optional; sent as Authorization: Bearer <key>)
 *   - `ARCIS_BATCH_SIZE`         (optional integer; default 50)
 *   - `ARCIS_FLUSH_INTERVAL_MS`  (optional integer; default 5000)
 *
 * Explicit `options.telemetry` always wins over env. This preserves the
 * existing opt-in contract and lets callers override env in tests.
 */
function buildTelemetryFromEnv(): TelemetryOptions | undefined {
  const env = typeof process !== 'undefined' ? process.env : undefined;
  const endpoint = env?.ARCIS_ENDPOINT;
  if (!endpoint) return undefined;
  const opts: TelemetryOptions = { endpoint };
  if (env?.ARCIS_WORKSPACE_ID) opts.workspaceId = env.ARCIS_WORKSPACE_ID;
  if (env?.ARCIS_KEY) opts.apiKey = env.ARCIS_KEY;
  const batch = env?.ARCIS_BATCH_SIZE ? parseInt(env.ARCIS_BATCH_SIZE, 10) : NaN;
  if (!Number.isNaN(batch)) opts.batchSize = batch;
  const flush = env?.ARCIS_FLUSH_INTERVAL_MS ? parseInt(env.ARCIS_FLUSH_INTERVAL_MS, 10) : NaN;
  if (!Number.isNaN(flush)) opts.flushIntervalMs = flush;
  return opts;
}

/**
 * Create Arcis middleware with all protections enabled.
 * 
 * @param options - Configuration options
 * @returns Array of Express middleware
 * 
 * @example
 * // Full protection (recommended)
 * app.use(arcis());
 * 
 * @example
 * // Custom configuration
 * app.use(arcis({
 *   rateLimit: { max: 50 },
 *   headers: { frameOptions: 'SAMEORIGIN' }
 * }));
 * 
 * @example
 * // Disable specific features
 * app.use(arcis({
 *   rateLimit: false,
 *   sanitize: { sql: false }
 * }));
 * 
 * @example
 * // Cleanup on shutdown
 * const middleware = arcis();
 * app.use(middleware);
 * process.on('SIGTERM', () => middleware.close());
 */
export function arcis(options: ArcisOptions = {}): ArcisMiddlewareStack {
  const middlewares: RequestHandler[] = [];
  const cleanupFns: (() => void)[] = [];

  // Telemetry emitter — first, so latency includes the full middleware chain.
  // Opt-in: zero overhead unless options.telemetry.endpoint is set, OR
  // ARCIS_ENDPOINT is present in the environment. Explicit options win.
  let telemetryClient: TelemetryClient | undefined;
  const telemetryOpts = options.telemetry?.endpoint
    ? options.telemetry
    : buildTelemetryFromEnv();
  if (telemetryOpts) {
    const client = new TelemetryClient(telemetryOpts);
    telemetryClient = client;
    middlewares.push(createTelemetryEmitter(client));
    cleanupFns.push(() => {
      void client.close();
    });
  }

  // Security headers (always before rate-limit/sanitize)
  if (options.headers !== false) {
    const headerOpts: HeaderOptions = typeof options.headers === 'object'
      ? options.headers
      : {};
    middlewares.push(createHeaders(headerOpts));
  }

  // Rate limiting — emitter detects 429 from response status, no wrap needed.
  if (options.rateLimit !== false) {
    const rateLimitOpts: RateLimitOptions = typeof options.rateLimit === 'object'
      ? options.rateLimit
      : {};
    const rateLimiter = createRateLimiter(rateLimitOpts);
    middlewares.push(rateLimiter);
    cleanupFns.push(() => rateLimiter.close());
  }

  // Input sanitization — wrap with telemetry tap so SecurityThreatError
  // populates req.__arcis with vector/rule/severity for the emitter.
  if (options.sanitize !== false) {
    const sanitizeOpts: SanitizeOptions = typeof options.sanitize === 'object'
      ? { ...options.sanitize }
      : {};
    if (options.block && sanitizeOpts.block === undefined) {
      sanitizeOpts.block = true;
    }
    const sanitizer = createSanitizer(sanitizeOpts);
    middlewares.push(telemetryClient ? tapSanitizerThreats(sanitizer) : sanitizer);
  }

  // Attach close() directly on the array so callers can clean up without any-casts.
  const result = middlewares as ArcisMiddlewareStack;
  result.close = () => {
    for (const fn of cleanupFns) {
      fn();
    }
  };

  return result;
}

// Attach individual functions for granular use
const arcisWithMethods = arcis as ArcisFunction;
arcisWithMethods.sanitize = createSanitizer;
arcisWithMethods.rateLimit = createRateLimiter;
arcisWithMethods.headers = createHeaders;
arcisWithMethods.validate = validate;
arcisWithMethods.logger = createSafeLogger;
arcisWithMethods.errorHandler = createErrorHandler;

export { arcisWithMethods as arcisFunction };
export default arcisWithMethods;
