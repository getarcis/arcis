/**
 * @module @arcis/node/middleware/token-budget
 *
 * Token-budget protection middleware. Caps per-key token spend over a
 * sliding window — meant for routes that proxy LLM calls, where a tight
 * 100-req/min rate limit isn't enough because a single 50KB prompt costs
 * the same as 1000 small requests.
 *
 * @example
 * import express from 'express';
 * import { tokenBudget } from '@arcis/node';
 *
 * const guard = tokenBudget({
 *   maxTokens: 100_000,            // 100K tokens per window
 *   windowMs: 60 * 60 * 1000,      // 1-hour window
 *   maxRequestTokens: 5_000,       // reject any single request over this
 *   keyGenerator: (req) => req.user?.id ?? req.ip,
 * });
 *
 * app.post('/chat', guard, chatHandler);
 *
 * The default token estimator is `Math.ceil(bytesOf(body+query) / 4)` —
 * close to OpenAI's "1 token ≈ 4 English characters" rule. Override via
 * `estimateTokens` for accurate counting (tiktoken, etc.).
 */

import type { Request, RequestHandler } from 'express';

export interface TokenBudgetOptions {
  /** Max tokens a single key can spend in one window. Default: 100,000. */
  maxTokens?: number;
  /** Window length in milliseconds. Default: 60 * 60 * 1000 (1 hour). */
  windowMs?: number;
  /**
   * Max tokens a single request may consume. Requests over this size are
   * rejected with 413 BEFORE counting against the window budget. Default:
   * unset (no per-request cap).
   */
  maxRequestTokens?: number;
  /**
   * Function that returns the budget key for a request. Default: client IP
   * (req.ip), falling back to `unknown` when unresolvable.
   */
  keyGenerator?: (req: Request) => string;
  /**
   * Function that estimates the number of tokens a request will consume.
   * Default: `Math.ceil((req.body + req.query stringified bytes) / 4)`,
   * which approximates OpenAI's "1 token ≈ 4 characters" rule. Override
   * with tiktoken/accurate counting when you need precision.
   */
  estimateTokens?: (req: Request) => number;
  /** Status code for budget-exceeded responses. Default: 429. */
  statusCode?: number;
  /** Status code for oversize-request rejections. Default: 413. */
  statusCodeOversize?: number;
  /** Error message when budget is exceeded. */
  message?: string;
  /** Error message when a single request exceeds maxRequestTokens. */
  messageOversize?: string;
  /** Skip budget enforcement for certain requests. */
  skip?: (req: Request) => boolean;
}

export interface TokenBudgetMiddleware extends RequestHandler {
  /** Release internal cleanup resources. */
  close: () => void;
  /** Inspect current usage for a key (read-only; for tests/telemetry). */
  inspect: (key: string) => { used: number; resetTime: number } | null;
}

interface Entry {
  used: number;
  resetTime: number;
}

const DEFAULT_MAX_TOKENS = 100_000;
const DEFAULT_WINDOW_MS = 60 * 60 * 1000;

function defaultKeyGenerator(req: Request): string {
  const ip = req.ip ?? req.socket?.remoteAddress;
  return ip ?? 'unknown';
}

function defaultEstimateTokens(req: Request): number {
  // Approximate OpenAI's "1 token ≈ 4 characters" rule using byte length
  // of stringified body + query. Fast, side-effect-free, no model call.
  // Returns 0 for missing payloads so safe routes don't get charged.
  let bytes = 0;
  if (req.body !== undefined && req.body !== null) {
    try {
      bytes += Buffer.byteLength(
        typeof req.body === 'string' ? req.body : JSON.stringify(req.body),
        'utf8',
      );
    } catch {
      // Circular structure or similar — treat as 0 rather than throw.
    }
  }
  if (req.query && Object.keys(req.query).length > 0) {
    try {
      bytes += Buffer.byteLength(JSON.stringify(req.query), 'utf8');
    } catch {
      // ignore
    }
  }
  return Math.ceil(bytes / 4);
}

/**
 * Build a token-budget middleware. See module-level JSDoc for usage.
 */
export function tokenBudget(options: TokenBudgetOptions = {}): TokenBudgetMiddleware {
  const maxTokens = options.maxTokens ?? DEFAULT_MAX_TOKENS;
  const windowMs = options.windowMs ?? DEFAULT_WINDOW_MS;
  const maxRequestTokens = options.maxRequestTokens;
  const keyGenerator = options.keyGenerator ?? defaultKeyGenerator;
  const estimateTokens = options.estimateTokens ?? defaultEstimateTokens;
  const statusCode = options.statusCode ?? 429;
  const statusCodeOversize = options.statusCodeOversize ?? 413;
  const message = options.message ?? 'Token budget exceeded for this window.';
  const messageOversize =
    options.messageOversize ??
    'Request exceeds the per-request token limit.';
  const skip = options.skip;

  // Object.create(null) keeps __proto__/constructor keys from corrupting
  // the store if a buggy keyGenerator returns one of those names.
  const store = Object.create(null) as Record<string, Entry>;

  // Sweep expired buckets so a long-lived process doesn't grow unbounded.
  const cleanup = setInterval(() => {
    const now = Date.now();
    for (const k of Object.keys(store)) {
      if (store[k].resetTime < now) {
        delete store[k];
      }
    }
  }, windowMs);
  if (typeof cleanup.unref === 'function') cleanup.unref();

  const handler: RequestHandler = (req, res, next) => {
    if (skip?.(req)) {
      next();
      return;
    }

    let estimated = 0;
    try {
      estimated = estimateTokens(req);
    } catch {
      estimated = 0;
    }
    if (!Number.isFinite(estimated) || estimated < 0) estimated = 0;

    // Per-request cap (rejected before counting against the budget so a
    // single oversized request can't single-handedly drain a window).
    if (maxRequestTokens !== undefined && estimated > maxRequestTokens) {
      res.setHeader('X-Token-Budget-Limit', maxTokens.toString());
      res.setHeader('X-Token-Budget-Request-Cost', estimated.toString());
      res.status(statusCodeOversize).json({
        error: messageOversize,
        requestTokens: estimated,
        maxRequestTokens,
      });
      return;
    }

    const key = keyGenerator(req);
    const now = Date.now();
    let entry = store[key];
    if (!entry || entry.resetTime < now) {
      entry = { used: 0, resetTime: now + windowMs };
      store[key] = entry;
    }

    const projected = entry.used + estimated;
    const remaining = Math.max(0, maxTokens - entry.used);
    const resetSeconds = Math.ceil((entry.resetTime - now) / 1000);

    res.setHeader('X-Token-Budget-Limit', maxTokens.toString());
    res.setHeader('X-Token-Budget-Used', entry.used.toString());
    res.setHeader('X-Token-Budget-Remaining', remaining.toString());
    res.setHeader('X-Token-Budget-Reset', resetSeconds.toString());
    res.setHeader('X-Token-Budget-Request-Cost', estimated.toString());

    if (projected > maxTokens) {
      res.setHeader('Retry-After', resetSeconds.toString());
      res.status(statusCode).json({
        error: message,
        used: entry.used,
        maxTokens,
        retryAfter: resetSeconds,
      });
      return;
    }

    // Charge the budget and continue.
    entry.used = projected;
    next();
  };

  const middleware = handler as TokenBudgetMiddleware;
  middleware.close = () => clearInterval(cleanup);
  middleware.inspect = (key: string) => {
    const e = store[key];
    if (!e) return null;
    return { used: e.used, resetTime: e.resetTime };
  };
  return middleware;
}

export default tokenBudget;
