/**
 * @module @arcis/node/middleware/signup-protection
 *
 * Composite signup-form protection: one middleware that combines email
 * validation (syntax + disposable), bot detection, and a dedicated
 * per-IP rate limit. Matches the Arcjet `protectSignup` convenience
 * primitive but stays fully local — no cloud lookups.
 *
 * @example
 *   app.post('/signup', signupProtection(), handler);
 *
 * @example
 *   app.post('/signup', signupProtection({
 *     emailField: 'email',
 *     rateLimit: { max: 5, windowMs: 60_000 },
 *     blockDisposable: true,
 *   }), handler);
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { validateEmail } from '../validation/email';
import { detectBot, type BotCategory } from './bot-detection';
import { createRateLimiter } from './rate-limit';

export type SignupBlockReason =
  | 'missing_email'
  | 'invalid_email'
  | 'disposable_email'
  | 'bot'
  | 'rate_limited';

export interface SignupCheckResult {
  allowed: boolean;
  reason: SignupBlockReason | 'ok';
  details?: Record<string, unknown>;
}

export interface SignupProtectionOptions {
  /** Request body field holding the email address. Default: 'email' */
  emailField?: string;
  /** Run email validation. Default: true */
  checkEmail?: boolean;
  /** Reject disposable email domains. Default: true */
  blockDisposable?: boolean;
  /** Run bot detection. Default: true */
  checkBot?: boolean;
  /** Bot categories allowed through (e.g. test harnesses). Default: [] — all bots blocked */
  allowedBotCategories?: BotCategory[];
  /** Per-IP rate limit on signup endpoint. Set to `false` to disable. Default: 5 requests / 60s */
  rateLimit?: { max?: number; windowMs?: number } | false;
  /** Extra email domains to allow (bypasses disposable check) */
  allowedEmailDomains?: string[];
  /** Extra email domains to block */
  blockedEmailDomains?: string[];
  /** Called when a request is blocked — for telemetry/logging */
  onBlocked?: (req: Request, result: SignupCheckResult) => void;
}

export interface SignupProtectionMiddleware extends RequestHandler {
  /** Release the rate-limiter cleanup interval */
  close: () => void;
}

/**
 * Pure signup check — no rate-limit mutation, no response writes.
 * Useful for framework adapters or custom control flow.
 */
export function checkSignup(
  req: Request,
  options: SignupProtectionOptions = {}
): SignupCheckResult {
  const {
    emailField = 'email',
    checkEmail = true,
    blockDisposable = true,
    checkBot = true,
    allowedBotCategories = [],
    allowedEmailDomains = [],
    blockedEmailDomains = [],
  } = options;

  if (checkBot) {
    const bot = detectBot(req);
    if (bot.isBot && !allowedBotCategories.includes(bot.category)) {
      return {
        allowed: false,
        reason: 'bot',
        details: { category: bot.category, name: bot.name, confidence: bot.confidence },
      };
    }
  }

  if (checkEmail) {
    const email = (req.body as Record<string, unknown> | undefined)?.[emailField];
    if (typeof email !== 'string' || email.length === 0) {
      return { allowed: false, reason: 'missing_email' };
    }
    const result = validateEmail(email, {
      checkDisposable: blockDisposable,
      allowedDomains: allowedEmailDomains,
      blockedDomains: blockedEmailDomains,
    });
    if (!result.valid) {
      const reason: SignupBlockReason =
        result.reason === 'disposable' ? 'disposable_email' : 'invalid_email';
      return { allowed: false, reason, details: { emailReason: result.reason } };
    }
  }

  return { allowed: true, reason: 'ok' };
}

/**
 * Express middleware: applies bot + email + rate-limit checks to a signup
 * endpoint. Responds 400/403/429 with a JSON body on block; otherwise
 * calls `next()`.
 */
export function signupProtection(
  options: SignupProtectionOptions = {}
): SignupProtectionMiddleware {
  const rateLimitCfg = options.rateLimit;
  const limiter =
    rateLimitCfg === false
      ? null
      : createRateLimiter({
          max: rateLimitCfg?.max ?? 5,
          windowMs: rateLimitCfg?.windowMs ?? 60_000,
          message: 'Too many signup attempts',
        });

  const handler: RequestHandler = (req, res, next) => {
    const result = checkSignup(req, options);
    if (!result.allowed) {
      options.onBlocked?.(req, result);
      const status = result.reason === 'bot' ? 403 : 400;
      res.status(status).json({ error: 'signup_blocked', reason: result.reason });
      return;
    }
    if (limiter) {
      // Delegate to rate limiter — it will respond 429 on breach or call next() otherwise.
      let rateLimited = false;
      const rateLimitNext: NextFunction = (err?: unknown) => {
        if (err) return next(err);
        if (!rateLimited) next();
      };
      const patchedRes = new Proxy(res, {
        get(target, prop) {
          if (prop === 'status') {
            return (code: number) => {
              if (code === 429) {
                rateLimited = true;
                options.onBlocked?.(req, { allowed: false, reason: 'rate_limited' });
              }
              return (target.status as (c: number) => Response).call(target, code);
            };
          }
          return Reflect.get(target, prop);
        },
      });
      limiter(req, patchedRes as Response, rateLimitNext);
      return;
    }
    next();
  };

  const middleware = handler as SignupProtectionMiddleware;
  middleware.close = () => limiter?.close();
  return middleware;
}
