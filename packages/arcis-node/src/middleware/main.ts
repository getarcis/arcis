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
import { botProtection, mergeBotPatterns, type BotProtectionOptions } from './bot-detection';
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
import { IntelligenceClient, reputationSeverityTier } from '../intelligence/client';
import { detectClientIp } from '../utils/ip';
import type { IpReputation, IntelligenceOptions, CloudDecision } from '../intelligence/types';

/**
 * Resolve cloud-intelligence config from in-code options or `ARCIS_INTEL_*`
 * env vars. The env fallback lets 12-factor apps turn on cloud intelligence
 * with no code change (mirrors the telemetry env pickup). In-code options win
 * when an endpoint is set both ways.
 *
 *   ARCIS_INTEL_ENDPOINT   required to activate the env path
 *   ARCIS_INTEL_KEY        optional bearer token
 *   ARCIS_INTEL_WORKSPACE        optional workspace id
 *   ARCIS_INTEL_DECISIONS        comma list: "ip-rep,bot-corpus"
 *   ARCIS_INTEL_BLOCK_THRESHOLD  optional int; reputation severity at/above
 *                                which to block (omit = annotate only)
 */
function resolveIntelligenceOptions(opt?: IntelligenceOptions): IntelligenceOptions | undefined {
  if (opt?.endpoint) return opt;
  const endpoint = process.env.ARCIS_INTEL_ENDPOINT;
  if (!endpoint) return undefined;
  const valid: CloudDecision[] = ['ip-rep', 'bot-corpus'];
  const cloudDecisions = (process.env.ARCIS_INTEL_DECISIONS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s): s is CloudDecision => (valid as string[]).includes(s));
  const rawThreshold = process.env.ARCIS_INTEL_BLOCK_THRESHOLD;
  const blockThreshold =
    rawThreshold && Number.isFinite(Number(rawThreshold)) ? Number(rawThreshold) : undefined;
  return {
    endpoint,
    apiKey: process.env.ARCIS_INTEL_KEY,
    workspaceId: process.env.ARCIS_INTEL_WORKSPACE,
    cloudDecisions,
    blockThreshold,
  };
}

declare module 'express-serve-static-core' {
  interface Request {
    /** IP reputation verdict attached by the intelligence middleware, when enabled. */
    arcisIpReputation?: IpReputation;
  }
}

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
  onSanitize?: (event: SanitizeEvent) => void,
  markWouldDeny = false,
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
      if (markWouldDeny) {
        req.__arcis = {
          vector: hit.vector,
          rule: `${hit.vector}/match`,
          severity: 'high',
          matchedPattern: hit.matchedPattern,
          reason: `Detected ${hit.vector} pattern`,
          decision: 'would_deny',
        };
      }
      if (onSanitize) {
        try {
          onSanitize({
            type: hit.vector,
            field: name,
            original: hit.matchedPattern,
            pattern: hit.matchedPattern,
          });
        } catch {
          // Observer must never break the response. Fail open.
        }
      }
    }
    next();
  };
}

/**
 * Issue #47: wraps a rate limiter so its rejection response body is
 * suppressed in dry-run mode. The X-RateLimit-* headers the limiter set
 * BEFORE deciding to reject still flow through (they were attached to the
 * response Header map by the limiter), giving observability without
 * actually blocking the request.
 *
 * The rate-limit rejection path is `res.status(rejectionStatus).json({...})`
 * followed by an early return (no `next()` call). To suppress, we
 * intercept `res.status` and on the configured rejection status:
 *   - flag `suppressed`,
 *   - swallow the chained `.json(...)` (no body write),
 *   - restore the originals,
 *   - call `next()` ourselves so the rest of the middleware stack runs.
 *
 * This is monkey-patching with a tightly-scoped lifetime — restored
 * the moment we hand control downstream so no other middleware sees
 * the patched methods.
 */
function observeRateLimitRejection(handler: RequestHandler, rejectionStatus = 429): RequestHandler {
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
      if (code === rejectionStatus) {
        suppressed = true;
        req.__arcis = {
          vector: 'rate-limit',
          rule: 'rate-limit/exceeded',
          severity: 'medium',
          reason: 'Rate limit would have been exceeded in dry-run mode',
          decision: 'would_deny',
        };
        return res; // chainable; the .json below no-ops.
      }
      return originalStatus(code);
    }) as Response['status'];

    res.json = ((body: unknown): Response => {
      if (suppressed) {
        // Limiter's rejection path: it called .status(...).json(...) and then
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
  // probe paths. Dry-run evaluates matches without writing a response.
  if (options.scannerPaths !== false) {
    const userScannerOpts: ScannerPathsOptions = typeof options.scannerPaths === 'object'
      ? options.scannerPaths
      : {};
    middlewares.push(scannerPathProtection({ ...userScannerOpts, dryRun }));
  }

  // Forwarded-header inspection (v1.7 W7). Flags a loopback address in a
  // forwarded / client-IP header (spoofing to bypass IP allowlists), and
  // optionally rejects Host / X-Forwarded-Host not in a trustedHosts
  // allowlist. Runs early because it only reads headers. Dry-run records the
  // same finding without writing a response or changing request headers.
  if (options.forwardedHeaders !== false) {
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
          req.__arcis = {
            vector: 'header',
            rule: 'header/forwarded-loopback-spoof',
            severity: 'high',
            reason: `Loopback address detected in ${name}`,
            decision: dryRun ? 'would_deny' : 'deny',
          };
          if (dryRun) return next();
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
              req.__arcis = {
                vector: 'header',
                rule: 'header/untrusted-host',
                severity: 'high',
                reason: `Untrusted host detected in ${name}`,
                decision: dryRun ? 'would_deny' : 'deny',
              };
              if (dryRun) return next();
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

  // Cloud intelligence (opt-in). One client serves both capabilities; created
  // when an endpoint is set and cloudDecisions names at least one.
  const intel = resolveIntelligenceOptions(options.intelligence);
  const intelDecisions = intel?.endpoint ? intel.cloudDecisions ?? [] : [];
  if (intelDecisions.length > 0 && intel) {
    const intelClient = new IntelligenceClient(intel);
    cleanupFns.push(() => intelClient.close());

    // Bot-corpus cloud refresh: fetch on startup + on an interval, merging the
    // curated additions on top of the bundled corpus so new scanners / AI
    // crawlers are classified without an SDK release. Fail-open: fetchBotCorpus
    // returns [] on any error, so the bundled corpus is never disturbed.
    if (intelDecisions.includes('bot-corpus')) {
      const refresh = (): void => {
        void intelClient.fetchBotCorpus().then((entries) => {
          if (entries.length > 0) mergeBotPatterns(entries);
        });
      };
      refresh();
      const refreshMs = Math.max(
        60_000,
        intel.botCorpusRefreshMs ?? 7 * 24 * 60 * 60 * 1000,
      );
      const timer = setInterval(refresh, refreshMs);
      (timer as { unref?: () => void }).unref?.();
      cleanupFns.push(() => clearInterval(timer));
    }

    // Cloud IP reputation per-request lookup. Runs early (IP-level, no body
    // needed), after forwarded-header inspection and before bot/rate-limit so a
    // known-bad IP is blocked before consuming quota. Cache-first and
    // non-blocking: a miss never adds latency, and an unreachable service fails
    // open.
    if (intelDecisions.includes('ip-rep')) {
      const blockThreshold = intel.blockThreshold;
      middlewares.push((req, res, next): void => {
        const ip = detectClientIp(req);
        const rep = intelClient.check(ip);
        req.arcisIpReputation = rep;
        const wouldBlock =
          rep.found &&
          typeof blockThreshold === 'number' &&
          (rep.severity ?? 0) >= blockThreshold;
        if (wouldBlock) {
          req.__arcis = {
            vector: 'ip-reputation',
            rule: 'ip-reputation/known-bad',
            severity: reputationSeverityTier(rep.severity),
            reason: `IP reputation severity ${rep.severity} >= ${blockThreshold}`,
            decision: dryRun ? 'would_deny' : 'deny',
          };
          if (dryRun) return next();
          res.status(403).json({
            error: 'Request blocked for security reasons',
            code: 'SECURITY_THREAT',
            vector: 'ip-reputation',
            rule: 'ip-reputation/known-bad',
          });
          return;
        }
        next();
      });
    }
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
      // Default deny: AUTOMATED (headless browser automation: Selenium /
      // Puppeteer / Playwright / PhantomJS / WebDriver / Headless Chrome) and
      // SECURITY_SCANNER (offensive scanners: sqlmap / nikto / nuclei / nmap /
      // masscan / wpscan / Acunetix / Nessus / dirbuster). SCRAPER is NOT
      // default-denied: it also covers curl / wget / python-requests /
      // monitoring and other legitimate non-browser clients, so blocking it by
      // default would break health checks and server-to-server traffic. Add it
      // explicitly with arcis({ bot: { deny: ['AUTOMATED', 'SCRAPER'] } }).
      deny: userBotOpts.deny ?? ['AUTOMATED', 'SECURITY_SCANNER'],
      allow: userBotOpts.allow,
      defaultAction: userBotOpts.defaultAction,
      statusCode: userBotOpts.statusCode,
      message: userBotOpts.message,
      detectBehavior: userBotOpts.detectBehavior,
      onDetected: userBotOpts.onDetected,
      dryRun,
    };
    middlewares.push(botProtection(botOpts));
  }

  // Issue #47 — observer pre-scan. Sits BEFORE the rate-limit + sanitizer so
  // the callback fires on every request that contains a threat, not just
  // those that survive rate-limiting. Skipped when no callback is set so
  // the default zero-overhead path is preserved.
  const sanitizeWouldReject = options.block === true || (
    typeof options.sanitize === 'object' && options.sanitize.mode === 'reject'
  );
  if (options.onSanitize || (dryRun && options.sanitize !== false)) {
    middlewares.push(createSanitizeObserver(
      options.onSanitize,
      dryRun && sanitizeWouldReject,
    ));
  }

  // Rate limiting writes an explicit decision for telemetry attribution.
  // Dry-run records the limiter's rejection without enforcing it
  // (headers still set; request continues). X-RateLimit-* headers
  // surface either way so dashboards see the would-have-been decision.
  if (options.rateLimit !== false) {
    const rateLimitOpts: RateLimitOptions = typeof options.rateLimit === 'object'
      ? options.rateLimit
      : {};
    const rateLimiter = createRateLimiter(rateLimitOpts);
    middlewares.push(dryRun ? observeRateLimitRejection(rateLimiter, rateLimitOpts.statusCode) : rateLimiter);
    cleanupFns.push(() => rateLimiter.close());
  }

  // GraphQL inspection (v1.7 W3). When the JSON body has a `query`
  // field, treat it as a GraphQL document and run the inspector. Sits
  // between rate-limit and sanitizer so the depth/alias-bomb check
  // happens BEFORE the regex-heavy body sanitizer chews on it. Dry-run keeps
  // the parsed body unchanged and records the decision without responding.
  if (options.graphql !== false) {
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
      req.__arcis = {
        vector: 'graphql',
        rule: `graphql/${result.reason}`,
        severity: 'high',
        reason: result.reason,
        decision: dryRun ? 'would_deny' : 'deny',
      };
      if (dryRun) return next();
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
  // vs the GraphQL string parse) and before the sanitizer. Dry-run records
  // the finding but never removes or rewrites the fields.
  if (options.massAssign !== false) {
    const massAssignOpts: MassAssignDetectOptions = typeof options.massAssign === 'object'
      ? options.massAssign
      : {};
    middlewares.push((req, res, next) => {
      const result = detectMassAssignment(req.body, massAssignOpts);
      if (!result.detected) {
        return next();
      }
      req.__arcis = {
        vector: 'mass-assignment',
        rule: 'mass-assignment/sensitive-field',
        severity: 'high',
        reason: 'Sensitive mass-assignment field detected',
        decision: dryRun ? 'would_deny' : 'deny',
      };
      if (dryRun) return next();
      res.status(403).json({
        error: 'Request blocked for security reasons',
        code: 'SECURITY_THREAT',
        vector: 'mass-assignment',
        rule: 'mass-assignment/sensitive-field',
      });
    });
  }

  // SSRF body-URL validation (v1.7 W5). Walk the JSON body for URL-shaped
  // strings and validate each. Dry-run records a finding without replacing
  // the URL or writing a response.
  if (options.ssrf !== false) {
    const ssrfOpts: ValidateUrlOptions = typeof options.ssrf === 'object'
      ? options.ssrf
      : {};
    middlewares.push((req, res, next) => {
      const result = scanForSsrf(req.body, ssrfOpts);
      if (!result.detected) {
        return next();
      }
      req.__arcis = {
        vector: 'ssrf',
        rule: 'ssrf/blocked-url',
        severity: 'high',
        reason: 'Blocked URL detected in request body',
        decision: dryRun ? 'would_deny' : 'deny',
      };
      if (dryRun) return next();
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
  // when a match at or above the configured severity is found. Dry-run
  // reports the same match without changing the original prompt.
  if (options.promptInjection !== false) {
    const piRank: Record<string, number> = { none: 0, low: 1, medium: 2, high: 3 };
    const minSeverity: PromptInjectionSeverity =
      typeof options.promptInjection === 'object' && options.promptInjection.minSeverity
        ? options.promptInjection.minSeverity
        : 'medium';
    const minRank = piRank[minSeverity];
    const scanPromptInjection = (
      value: unknown,
      depth: number,
    ): PromptInjectionSeverity | undefined => {
      if (depth > 8 || value === null) return undefined;
      if (typeof value === 'string') {
        const r = detectPromptInjection(value);
        return r.detected && r.severity !== 'none' && piRank[r.severity] >= minRank
          ? r.severity
          : undefined;
      }
      if (typeof value !== 'object') return undefined;
      let highest: PromptInjectionSeverity | undefined;
      const children = Array.isArray(value)
        ? value
        : Object.values(value as Record<string, unknown>);
      for (const child of children) {
        const severity = scanPromptInjection(child, depth + 1);
        if (severity && (!highest || piRank[severity] > piRank[highest])) {
          highest = severity;
        }
      }
      return highest;
    };
    middlewares.push((req, res, next) => {
      const severity = scanPromptInjection(req.body, 0);
      if (!severity) {
        return next();
      }
      req.__arcis = {
        vector: 'prompt-injection',
        rule: 'prompt-injection/detected',
        severity,
        reason: 'Prompt injection detected in request body',
        decision: dryRun ? 'would_deny' : 'deny',
      };
      if (dryRun) return next();
      res.status(403).json({
        error: 'Request blocked for security reasons',
        code: 'SECURITY_THREAT',
        vector: 'prompt-injection',
        rule: 'prompt-injection/detected',
      });
    });
  }

  // Input sanitization. Dry-run uses the observer above and never installs
  // the transforming sanitizer, so request data remains byte-for-byte owned
  // by the application.
  // Wrap enforcement with telemetry tap so SecurityThreatError
  // populates req.__arcis with vector/rule/severity for the emitter.
  // Dry-run omits this middleware entirely; detection still happens via
  // the immutable observer above.
  if (options.sanitize !== false && !dryRun) {
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
