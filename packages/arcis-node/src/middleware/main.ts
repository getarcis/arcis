/**
 * @module @arcis/node/middleware/main
 * Main arcis() middleware factory
 */

import type { Request, RequestHandler, Response, NextFunction } from 'express';
import type {
  ArcisOptions,
  ArcisFunction,
  ArcisMiddlewareStack,
  HeaderOptions,
  RateLimitOptions,
  SanitizeEvent,
  SanitizeOptions,
} from '../core/types';
import { createHeaders } from './headers';
import { createRateLimiter } from './rate-limit';
import { createErrorHandler } from './error-handler';
import { createTelemetryEmitter, tapSanitizerThreats } from './telemetry';
import { botProtection, type BotProtectionOptions } from './bot-detection';
import { scannerPathProtection, type ScannerPathsOptions } from './sensitive-paths';
import { inspectGraphqlQuery, type GraphqlGuardOptions } from '../sanitizers/graphql';
import { detectMassAssignment, type MassAssignDetectOptions } from '../sanitizers/mass-assignment';
import { scanForSsrf, type ValidateUrlOptions } from '../validation/url';
import { detectPromptInjection, type PromptInjectionSeverity } from '../sanitizers/prompt-injection';
import { createSanitizer, scanThreats } from '../sanitizers';
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
/**
 * Issue #47 — observer middleware. Pre-scans `req.body / req.query /
 * req.params / req.path` for threats and fires `onSanitize` for each hit.
 * Always calls `next()` (no blocking, no mutation) — control flow is
 * owned by the rate-limit and sanitizer middlewares downstream.
 *
 * Errors thrown from the user callback are caught and swallowed so a
 * buggy observer can't take down the request path.
 */
function createSanitizeObserver(
  onSanitize: (event: SanitizeEvent) => void,
): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    const fields: ReadonlyArray<readonly [string, unknown]> = [
      ['body', req.body],
      ['query', req.query],
      ['params', req.params],
      ['path', req.path],
    ];
    for (const [name, value] of fields) {
      const hit = scanThreats(value);
      if (!hit) continue;
      try {
        onSanitize({
          type: hit.vector,
          field: name,
          original: hit.matchedPattern,
          pattern: hit.matchedPattern,
        });
      } catch {
        // Observer must never break the response — fail-open.
      }
    }
    next();
  };
}

/**
 * Issue #47 — wraps a 429-emitting middleware so the response body is
 * suppressed in dry-run mode. The X-RateLimit-* headers the limiter set
 * BEFORE deciding to 429 still flow through (they were attached to the
 * response Header map by the limiter), giving observability without
 * actually blocking the request.
 *
 * The rate-limit middleware's 429 path is `res.status(429).json({...})`
 * followed by an early return (no `next()` call). To suppress, we
 * intercept `res.status` and on 429:
 *   - flag `suppressed`,
 *   - swallow the chained `.json(...)` (no body write),
 *   - restore the originals,
 *   - call `next()` ourselves so the rest of the middleware stack runs.
 *
 * This is monkey-patching with a tightly-scoped lifetime — restored
 * the moment we hand control downstream so no other middleware sees
 * the patched methods.
 */
function suppressRateLimit429(handler: RequestHandler): RequestHandler {
  return (req, res, next) => {
    const originalStatus = res.status.bind(res);
    const originalJson = res.json.bind(res);
    let suppressed = false;
    let nextCalled = false;

    const restore = (): void => {
      res.status = originalStatus;
      res.json = originalJson;
    };

    res.status = ((code: number): Response => {
      if (code === 429) {
        suppressed = true;
        return res; // chainable; the .json below no-ops.
      }
      return originalStatus(code);
    }) as Response['status'];

    res.json = ((body: unknown): Response => {
      if (suppressed) {
        // Limiter's 429 path: it called .status(429).json(...) and then
        // returned without next(). Hand control to the rest of the chain
        // ourselves. Restore originals first so downstream sees a clean
        // ResponseWriter.
        restore();
        if (!nextCalled) {
          nextCalled = true;
          next();
        }
        return res;
      }
      return originalJson(body);
    }) as Response['json'];

    handler(req, res, (err) => {
      // Allow path: handler called next() itself. Restore methods so
      // downstream middleware operates on the unwrapped response.
      restore();
      if (!nextCalled) {
        nextCalled = true;
        next(err);
      }
    });
  };
}

export function arcis(options: ArcisOptions = {}): ArcisMiddlewareStack {
  const middlewares: RequestHandler[] = [];
  const cleanupFns: (() => void)[] = [];
  const dryRun = options.dryRun === true;

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

  // Scanner-path probe blocking (v1.7 W2). Runs BEFORE bot detection because
  // some scanner UAs forge a browser UA but still hit dotfile / WordPress
  // probe paths. Dry-run skips the block.
  if (options.scannerPaths !== false && !dryRun) {
    const scannerOpts: ScannerPathsOptions = typeof options.scannerPaths === 'object'
      ? options.scannerPaths
      : {};
    middlewares.push(scannerPathProtection(scannerOpts));
  }

  // Forwarded-header inspection (v1.7 W7). Flags a loopback address in a
  // forwarded / client-IP header (spoofing to bypass IP allowlists), and
  // optionally rejects Host / X-Forwarded-Host not in a trustedHosts
  // allowlist. Runs early (header read, no body needed). Skipped in dry-run.
  if (options.forwardedHeaders !== false && !dryRun) {
    const FORWARDED = ['x-forwarded-for', 'x-forwarded-host', 'x-real-ip', 'forwarded', 'client-ip', 'true-client-ip'];
    const LOOPBACK = /(?:^|[\s,@=])(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|0\.0\.0\.0|localhost)(?::\d+)?(?:$|[\s,;])/i;
    const trustedHosts = typeof options.forwardedHeaders === 'object' && options.forwardedHeaders.trustedHosts
      ? options.forwardedHeaders.trustedHosts.map((h) => h.toLowerCase())
      : null;
    middlewares.push((req, res, next): void => {
      for (const name of FORWARDED) {
        const raw = req.headers[name];
        const value = Array.isArray(raw) ? raw.join(',') : raw;
        if (typeof value === 'string' && LOOPBACK.test(value)) {
          res.status(403).json({
            error: 'Request blocked for security reasons',
            code: 'SECURITY_THREAT',
            vector: 'header',
            rule: 'header/forwarded-loopback-spoof',
          });
          return;
        }
      }
      if (trustedHosts) {
        for (const name of ['host', 'x-forwarded-host']) {
          const raw = req.headers[name];
          const value = Array.isArray(raw) ? raw[0] : raw;
          if (typeof value === 'string' && value) {
            const host = value.split(':')[0].toLowerCase();
            if (!trustedHosts.includes(host)) {
              res.status(403).json({
                error: 'Request blocked for security reasons',
                code: 'SECURITY_THREAT',
                vector: 'header',
                rule: 'header/untrusted-host',
              });
              return;
            }
          }
        }
      }
      next();
    });
  }

  // Bot UA classification — runs BEFORE rate-limit so bots don't consume
  // legitimate-traffic rate-limit quota. v1.7 W1 wire-up (was opt-in via
  // standalone botProtection() factory; now default-on). Dry-run mode skips
  // the deny step (detection still attaches result to req.botDetection) so
  // dashboards can see "would have blocked" decisions.
  if (options.bot !== false) {
    const userBotOpts: BotProtectionOptions = typeof options.bot === 'object'
      ? options.bot
      : {};
    const botOpts: BotProtectionOptions = {
      // Default deny is more aggressive than the standalone factory:
      // AUTOMATED catches the small handful of explicit bot tooling,
      // SCRAPER catches curl / python-requests / sqlmap / nikto / nuclei
      // (the bench bot corpus and most "I just want to hit your API" tools).
      deny: userBotOpts.deny ?? ['AUTOMATED', 'SCRAPER'],
      allow: userBotOpts.allow,
      defaultAction: userBotOpts.defaultAction,
      statusCode: userBotOpts.statusCode,
      message: userBotOpts.message,
      detectBehavior: userBotOpts.detectBehavior,
      onDetected: userBotOpts.onDetected,
    };
    if (dryRun) {
      // Dry-run: classify + attach to req for observation, but never deny.
      const classifyOnly: BotProtectionOptions = {
        ...botOpts,
        deny: [],
        defaultAction: 'allow',
      };
      middlewares.push(botProtection(classifyOnly));
    } else {
      middlewares.push(botProtection(botOpts));
    }
  }

  // Issue #47 — observer pre-scan. Sits BEFORE the rate-limit + sanitizer so
  // the callback fires on every request that contains a threat, not just
  // those that survive rate-limiting. Skipped when no callback is set so
  // the default zero-overhead path is preserved.
  if (options.onSanitize) {
    middlewares.push(createSanitizeObserver(options.onSanitize));
  }

  // Rate limiting — emitter detects 429 from response status, no wrap needed.
  // Dry-run wraps the limiter so the limiter's 429 decision is silently
  // dropped (headers still set; request continues). X-RateLimit-* headers
  // surface either way so dashboards see the would-have-been decision.
  if (options.rateLimit !== false) {
    const rateLimitOpts: RateLimitOptions = typeof options.rateLimit === 'object'
      ? options.rateLimit
      : {};
    const rateLimiter = createRateLimiter(rateLimitOpts);
    middlewares.push(dryRun ? suppressRateLimit429(rateLimiter) : rateLimiter);
    cleanupFns.push(() => rateLimiter.close());
  }

  // GraphQL inspection (v1.7 W3). When the JSON body has a `query`
  // field, treat it as a GraphQL document and run the inspector. Sits
  // between rate-limit and sanitizer so the depth/alias-bomb check
  // happens BEFORE the regex-heavy body sanitizer chews on it. Skipped
  // in dry-run mode.
  if (options.graphql !== false && !dryRun) {
    const userGqlOpts: GraphqlGuardOptions = typeof options.graphql === 'object'
      ? options.graphql
      : {};
    // Tighter defaults than the standalone factory: 12-alias bombs
    // bypass the standalone default of 50, and most legit queries
    // never need >10 aliases. Users running Apollo Studio in dev
    // pass blockIntrospection: false explicitly.
    const gqlOpts: GraphqlGuardOptions = {
      maxDepth: userGqlOpts.maxDepth ?? 10,
      maxLength: userGqlOpts.maxLength ?? 10000,
      blockIntrospection: userGqlOpts.blockIntrospection ?? true,
      maxAliases: userGqlOpts.maxAliases ?? 10,
      blockFragmentCycles: userGqlOpts.blockFragmentCycles ?? true,
    };
    middlewares.push((req, res, next) => {
      const body = req.body as Record<string, unknown> | undefined;
      const query = body && typeof body === 'object' ? body.query : undefined;
      if (typeof query !== 'string' || query.length === 0) {
        return next();
      }
      const result = inspectGraphqlQuery(query, gqlOpts);
      if (!result.blocked) {
        return next();
      }
      res.status(403).json({
        error: 'Request blocked for security reasons',
        code: 'SECURITY_THREAT',
        vector: 'graphql',
        rule: `graphql/${result.reason}`,
      });
    });
  }

  // Mass-assignment field detection (v1.7 W4). Scan the JSON body for
  // privilege-escalation field names. Runs after GraphQL (cheap key walk
  // vs the GraphQL string parse) and before the sanitizer. Skipped in
  // dry-run.
  if (options.massAssign !== false && !dryRun) {
    const massAssignOpts: MassAssignDetectOptions = typeof options.massAssign === 'object'
      ? options.massAssign
      : {};
    middlewares.push((req, res, next) => {
      const result = detectMassAssignment(req.body, massAssignOpts);
      if (!result.detected) {
        return next();
      }
      res.status(403).json({
        error: 'Request blocked for security reasons',
        code: 'SECURITY_THREAT',
        vector: 'mass-assignment',
        rule: 'mass-assignment/sensitive-field',
      });
    });
  }

  // SSRF body-URL validation (v1.7 W5). Walk the JSON body for URL-shaped
  // strings and validate each. Skipped in dry-run.
  if (options.ssrf !== false && !dryRun) {
    const ssrfOpts: ValidateUrlOptions = typeof options.ssrf === 'object'
      ? options.ssrf
      : {};
    middlewares.push((req, res, next) => {
      const result = scanForSsrf(req.body, ssrfOpts);
      if (!result.detected) {
        return next();
      }
      res.status(403).json({
        error: 'Request blocked for security reasons',
        code: 'SECURITY_THREAT',
        vector: 'ssrf',
        rule: 'ssrf/blocked-url',
      });
    });
  }

  // Prompt-injection detection on body strings (v1.7 W6). Walk the JSON
  // body for string values and run the prompt-injection detector; block
  // when a match at or above the configured severity is found. Skipped
  // in dry-run.
  if (options.promptInjection !== false && !dryRun) {
    const piRank: Record<string, number> = { none: 0, low: 1, medium: 2, high: 3 };
    const minSeverity: PromptInjectionSeverity =
      typeof options.promptInjection === 'object' && options.promptInjection.minSeverity
        ? options.promptInjection.minSeverity
        : 'medium';
    const minRank = piRank[minSeverity];
    const scanPromptInjection = (value: unknown, depth: number): boolean => {
      if (depth > 8 || value === null) return false;
      if (typeof value === 'string') {
        const r = detectPromptInjection(value);
        return r.detected && piRank[r.severity] >= minRank;
      }
      if (typeof value !== 'object') return false;
      if (Array.isArray(value)) {
        return value.some((v) => scanPromptInjection(v, depth + 1));
      }
      return Object.values(value as Record<string, unknown>).some((v) =>
        scanPromptInjection(v, depth + 1),
      );
    };
    middlewares.push((req, res, next) => {
      if (!scanPromptInjection(req.body, 0)) {
        return next();
      }
      res.status(403).json({
        error: 'Request blocked for security reasons',
        code: 'SECURITY_THREAT',
        vector: 'prompt-injection',
        rule: 'prompt-injection/detected',
      });
    });
  }

  // Input sanitization — wrap with telemetry tap so SecurityThreatError
  // populates req.__arcis with vector/rule/severity for the emitter.
  // Dry-run forces block: false so the sanitizer can never short-circuit
  // with a 403; detection still happens via the observer above.
  if (options.sanitize !== false) {
    const sanitizeOpts: SanitizeOptions = typeof options.sanitize === 'object'
      ? { ...options.sanitize }
      : {};
    if (options.block && sanitizeOpts.block === undefined) {
      sanitizeOpts.block = true;
    }
    if (dryRun) {
      sanitizeOpts.block = false;
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
