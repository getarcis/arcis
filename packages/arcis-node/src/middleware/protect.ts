/**
 * @module @arcis/node/middleware/protect
 *
 * Composite protection helpers (issue #52). Pre-configured middleware
 * stacks for the three endpoint shapes that show up in every app:
 * login, signup, generic API. Each helper composes EXISTING middleware
 * with sensible defaults; no new security logic lives here.
 *
 * Express supports passing an array of middleware to a route — the
 * elements get unrolled in declaration order — so each helper returns
 * a `RequestHandler[]` that drops directly into `app.post(...)`:
 *
 * ```ts
 * import { protectLogin, protectSignup, protectApi } from '@arcis/node';
 *
 * app.post('/login',  protectLogin(),  loginHandler);
 * app.post('/signup', protectSignup(), signupHandler);
 * app.use ('/api',    protectApi());
 * ```
 *
 * Defaults (issue #52 spec):
 *
 * | Helper        | rate-limit | bot | csrf | cors | sanitize | email |
 * |---------------|------------|-----|------|------|----------|-------|
 * | protectLogin  | 5/min      | yes | yes  | -    | yes      | -     |
 * | protectSignup | 3/min      | yes | -    | -    | yes      | yes   |
 * | protectApi    | 100/min    | -   | -    | yes  | yes      | -     |
 *
 * Each option is overridable. Pass `{ rateLimit: false }` to disable a
 * specific layer; pass an options object to forward to the underlying
 * factory.
 */

import type { RequestHandler } from 'express';
import { createRateLimiter } from './rate-limit';
import { botProtection, type BotProtectionOptions } from './bot-detection';
import { csrfProtection, type CsrfOptions } from './csrf';
import { safeCors } from './cors';
import type { CorsOptions } from './cors';
import { signupProtection, type SignupProtectionOptions } from './signup-protection';
import { bruteForceProtection, type BruteForceOptions } from './brute-force';
import { createSanitizer } from '../sanitizers';
import type { RateLimitOptions, SanitizeOptions } from '../core/types';
import { CorrelationWindow } from './correlation';

/**
 * Per-protect-helper correlation-window wiring (improvements.md §1.4).
 *
 * Pass an instance of `CorrelationWindow` plus the vector tag this
 * route represents ("login" / "signup" / "api"). The middleware
 * records every request in the window and refuses the request when
 * the window flags the IP as a scanner / credential stuffer / race
 * probe. Detection-only otherwise.
 *
 * Pull-out fields:
 *  - `usernameField`: body key whose value is the distinct-value
 *    tracked for credential-stuffing detection. Defaults to
 *    `'username'`.
 *  - `route`: route label recorded in the window (so cross-route
 *    aggregation is meaningful). Defaults to the request path.
 *  - `statusCode` / `message`: response shape on a correlation block.
 */
export interface CorrelationOptions {
  window: CorrelationWindow;
  vector?: string;
  usernameField?: string;
  route?: string;
  statusCode?: number;
  message?: string;
}

function getClientIp(req: any): string {
  // Best-effort. Matches the helper Arcis uses elsewhere.
  const xff =
    req?.headers?.['x-forwarded-for'] ?? req?.headers?.['X-Forwarded-For'];
  if (typeof xff === 'string' && xff.length > 0) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  if (typeof req?.ip === 'string') return req.ip;
  const remote = req?.socket?.remoteAddress;
  return typeof remote === 'string' ? remote : '';
}

function correlationMiddleware(opts: CorrelationOptions): RequestHandler {
  const vector = opts.vector ?? 'request';
  const usernameField = opts.usernameField ?? 'username';
  const statusCode = opts.statusCode ?? 429;
  const message = opts.message ?? 'Suspicious request pattern detected.';
  return function (req, res, next) {
    const ip = getClientIp(req);
    if (!ip) return next();
    const route = opts.route ?? (req.path || req.url || '/');
    const username = req?.body?.[usernameField];
    const distinctValue =
      typeof username === 'string' && username.length > 0 ? username : undefined;
    const detections = opts.window.record(
      ip,
      vector,
      route,
      req.method || 'GET',
      distinctValue,
    );
    if (
      detections.scanner ||
      detections.credentialStuffing ||
      detections.raceWindow
    ) {
      res.status(statusCode).json({
        error: message,
        scanner: detections.scanner,
        credential_stuffing: detections.credentialStuffing,
        race_window: detections.raceWindow,
      });
      return;
    }
    next();
  };
}

/**
 * Per-layer override knob: pass `false` to disable, an options object
 * to merge into the layer's defaults, or omit to accept the helper's
 * baked-in default.
 */
type LayerOverride<T> = false | T | undefined;

export interface ProtectLoginOptions {
  rateLimit?: LayerOverride<RateLimitOptions>;
  bot?: LayerOverride<BotProtectionOptions>;
  csrf?: LayerOverride<CsrfOptions>;
  sanitize?: LayerOverride<SanitizeOptions>;
  /** Optional correlation-window wiring (improvements.md §1.4). */
  correlation?: CorrelationOptions;
  /**
   * Optional brute-force layer. When enabled, layers a bursty limiter
   * on top of the fast rate-limit window: N attempts in `slowDuration`
   * seconds trips a `blockDuration`-second semi-permanent block.
   * Defaults to disabled (preserves existing behavior); pass `true`
   * for safe defaults or an options object to customize.
   */
  bruteForce?: boolean | BruteForceOptions;
}

export interface ProtectSignupOptions {
  rateLimit?: LayerOverride<RateLimitOptions>;
  bot?: LayerOverride<BotProtectionOptions>;
  sanitize?: LayerOverride<SanitizeOptions>;
  /** signupProtection options (email-style validation, disposable-mail block, etc.). */
  signup?: LayerOverride<SignupProtectionOptions>;
  /** Optional correlation-window wiring (improvements.md §1.4). */
  correlation?: CorrelationOptions;
}

export interface ProtectApiOptions {
  rateLimit?: LayerOverride<RateLimitOptions>;
  /** CORS is required to take an Origin/Methods config — no default origin. */
  cors?: LayerOverride<CorsOptions>;
  sanitize?: LayerOverride<SanitizeOptions>;
  /** Optional correlation-window wiring (improvements.md §1.4). */
  correlation?: CorrelationOptions;
}

/**
 * Resolve a layer override against a default. Returns `null` when the
 * caller disabled the layer with `false`; otherwise the merged options
 * object the underlying factory expects.
 */
function resolve<T extends object>(override: LayerOverride<T>, defaults: T): T | null {
  if (override === false) return null;
  if (override === undefined) return defaults;
  return { ...defaults, ...override };
}

/**
 * Login endpoints get the strictest defaults: 5 req/min/IP, deny
 * AUTOMATED bots, CSRF token check, and input sanitization. Designed
 * for `app.post('/login', protectLogin(), handler)`.
 */
export function protectLogin(options: ProtectLoginOptions = {}): RequestHandler[] {
  const middlewares: RequestHandler[] = [];

  const rl = resolve<RateLimitOptions>(options.rateLimit, { max: 5, windowMs: 60_000 });
  if (rl) middlewares.push(createRateLimiter(rl));

  if (options.bruteForce) {
    const bfOpts =
      options.bruteForce === true ? {} : options.bruteForce;
    middlewares.push(bruteForceProtection(bfOpts));
  }

  const bot = resolve<BotProtectionOptions>(options.bot, {
    deny: ['AUTOMATED'],
    statusCode: 403,
    message: 'Access denied.',
  });
  if (bot) middlewares.push(botProtection(bot));

  const csrf = resolve<CsrfOptions>(options.csrf, {});
  if (csrf) middlewares.push(csrfProtection(csrf));

  const sanitize = resolve<SanitizeOptions>(options.sanitize, {});
  if (sanitize) middlewares.push(createSanitizer(sanitize));

  if (options.correlation) {
    middlewares.push(
      correlationMiddleware({ vector: 'login', ...options.correlation }),
    );
  }

  return middlewares;
}

/**
 * Signup endpoints: 3 req/min/IP, deny AUTOMATED bots, sanitize input,
 * and run signup-specific validation (email shape + disposable-domain
 * check via `signupProtection`). No CSRF here because most signup
 * forms are first-touch, no prior session to anchor a token to.
 */
export function protectSignup(options: ProtectSignupOptions = {}): RequestHandler[] {
  const middlewares: RequestHandler[] = [];

  const rl = resolve<RateLimitOptions>(options.rateLimit, { max: 3, windowMs: 60_000 });
  if (rl) middlewares.push(createRateLimiter(rl));

  const bot = resolve<BotProtectionOptions>(options.bot, {
    deny: ['AUTOMATED'],
    statusCode: 403,
    message: 'Access denied.',
  });
  if (bot) middlewares.push(botProtection(bot));

  const sanitize = resolve<SanitizeOptions>(options.sanitize, {});
  if (sanitize) middlewares.push(createSanitizer(sanitize));

  const signup = resolve<SignupProtectionOptions>(options.signup, {});
  if (signup) middlewares.push(signupProtection(signup));

  if (options.correlation) {
    middlewares.push(
      correlationMiddleware({ vector: 'signup', ...options.correlation }),
    );
  }

  return middlewares;
}

/**
 * Generic API endpoints: 100 req/min/IP, CORS, input sanitization. No
 * bot detection by default because legitimate API consumers (curl,
 * fetch, server-to-server) are often classified AUTOMATED — opt-in
 * by passing a `bot` override... wait, protectApi doesn't expose bot.
 * That's deliberate per the issue spec table. Users who want bot
 * detection on API endpoints compose `botProtection()` directly.
 *
 * CORS is the one layer with no usable default — every app's allow
 * list is different. Pass `cors: { origin: '...' }` or `cors: false`
 * to skip it explicitly.
 */
export function protectApi(options: ProtectApiOptions = {}): RequestHandler[] {
  const middlewares: RequestHandler[] = [];

  const rl = resolve<RateLimitOptions>(options.rateLimit, { max: 100, windowMs: 60_000 });
  if (rl) middlewares.push(createRateLimiter(rl));

  // CORS: no useful default, but if the user didn't pass anything we
  // default to a permissive CorsOrigin: true (reflect request Origin).
  // Documented as a starter — production apps should narrow this.
  const cors = resolve<CorsOptions>(options.cors, { origin: true });
  if (cors) middlewares.push(safeCors(cors));

  const sanitize = resolve<SanitizeOptions>(options.sanitize, {});
  if (sanitize) middlewares.push(createSanitizer(sanitize));

  if (options.correlation) {
    middlewares.push(
      correlationMiddleware({ vector: 'api', ...options.correlation }),
    );
  }

  return middlewares;
}
