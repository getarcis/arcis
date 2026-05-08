/**
 * @module @arcis/node/middleware/mass-assign
 *
 * Mass-assignment runtime guard (sdk-vectors.md tier 1 #25).
 *
 * The classic mass-assignment vulnerability:
 *
 * ```js
 * const user = await User.findOne({ id });
 * Object.assign(user, req.body);  // attacker sets req.body.is_admin = true
 * await user.save();
 * ```
 *
 * This middleware filters `req.body` to a per-route allowlist before
 * the handler runs. Two modes:
 *
 * - `'strip'` (default) — silently drop disallowed keys, continue.
 * - `'reject'` — return 400 with the offending key names.
 *
 * Pair it with the audit rule (`MASS-ASSIGN` in `arcis audit`) for the
 * static-analysis side and the route-level middleware for the runtime
 * side. Audit catches `Object.assign(target, req.body)` patterns at
 * build time; this middleware catches the runtime data flow.
 *
 * ```ts
 * import { massAssign } from '@arcis/node';
 *
 * app.post('/users',
 *   massAssign({ allow: ['email', 'password', 'name'] }),
 *   async (req, res) => {
 *     // req.body has been filtered — is_admin / role / created_at all gone.
 *     const user = await User.create(req.body);
 *     res.json(user);
 *   },
 * );
 * ```
 *
 * Default scope is top-level keys only. Nested objects pass through
 * untouched — that's deliberate: nested allowlists encourage
 * `allow: ['profile.bio', 'profile.avatar']` style strings which
 * become a parser, not a guard. Use a schema validator (Zod / Joi /
 * Arcis's `validate`) when nested filtering is required; this
 * middleware handles the 80% case of "filter req.body for an ORM
 * mass-assign call".
 */

import type { Request, RequestHandler, Response, NextFunction } from 'express';

export interface MassAssignOptions {
  /**
   * Allowlist of permitted top-level keys on `req.body`. Required —
   * a missing or empty array would silently strip every key, almost
   * certainly a configuration mistake.
   */
  allow: readonly string[];
  /**
   * Behavior when `req.body` contains a key NOT in `allow`:
   *   - `'strip'` (default): silently drop the key, continue.
   *   - `'reject'`: return `statusCode` (default 400) with a JSON
   *     body listing the disallowed keys.
   */
  mode?: 'strip' | 'reject';
  /** Status code for the reject path. Default: 400. */
  statusCode?: number;
  /** Error message in the reject body. Default: "Disallowed fields". */
  message?: string;
  /**
   * Skip the filter when `req.body` is not a plain object (string,
   * array, FormData, etc.). Default: true. Set to false to surface
   * a 400 ("body must be an object") on those payloads — useful for
   * routes that should ONLY accept JSON objects.
   */
  passThroughNonObjects?: boolean;
}

const DEFAULTS = {
  mode: 'strip' as const,
  statusCode: 400,
  message: 'Disallowed fields',
  passThroughNonObjects: true,
} as const;

/**
 * Build a mass-assignment guard middleware. Runs against `req.body`
 * before the route handler — must be installed AFTER body-parsing
 * middleware (`express.json()` / `express.urlencoded()`) so `req.body`
 * is already populated.
 */
export function massAssign(options: MassAssignOptions): RequestHandler {
  if (!options || !Array.isArray(options.allow)) {
    throw new TypeError('massAssign: options.allow must be a string array');
  }
  if (options.allow.length === 0) {
    // Empty allow list strips every key. Almost certainly a bug — fail
    // loud at boot rather than silently accept-and-strip in production.
    throw new RangeError(
      'massAssign: options.allow must contain at least one key (use sanitize: false to disable instead)',
    );
  }

  const allowSet = new Set(options.allow);
  const mode = options.mode ?? DEFAULTS.mode;
  const statusCode = options.statusCode ?? DEFAULTS.statusCode;
  const message = options.message ?? DEFAULTS.message;
  const passThroughNonObjects =
    options.passThroughNonObjects ?? DEFAULTS.passThroughNonObjects;

  return (req: Request, res: Response, next: NextFunction) => {
    const body = req.body;

    // No body: nothing to filter. Express sets req.body to {} when the
    // body parser ran but the request had no body, and to undefined
    // when no parser was wired — both flow through unchanged.
    if (body == null) {
      next();
      return;
    }

    // Non-object payload (string / array / Buffer / FormData). The
    // mass-assign vector is specifically Object.assign-style key
    // expansion; non-objects don't have keys to filter, so the default
    // is pass-through.
    if (typeof body !== 'object' || Array.isArray(body)) {
      if (passThroughNonObjects) {
        next();
        return;
      }
      res.status(statusCode).json({
        error: 'Request body must be a JSON object',
      });
      return;
    }

    const incoming = Object.keys(body as Record<string, unknown>);
    const disallowed = incoming.filter((k) => !allowSet.has(k));

    if (disallowed.length > 0 && mode === 'reject') {
      res.status(statusCode).json({
        error: message,
        fields: disallowed,
      });
      return;
    }

    if (disallowed.length > 0) {
      // Strip mode — build a fresh object with only allowed keys. Avoid
      // mutating the original `req.body` reference because some
      // frameworks freeze the body or wire it to other middleware.
      const filtered: Record<string, unknown> = {};
      for (const key of incoming) {
        if (allowSet.has(key)) {
          filtered[key] = (body as Record<string, unknown>)[key];
        }
      }
      // Express 5 / Connect 4 made req.body a getter on some versions;
      // assign via Object.defineProperty to stay safe across both. (Same
      // pattern arcis uses in `validation/schema.ts` for the same
      // reason.)
      Object.defineProperty(req, 'body', {
        value: filtered,
        writable: true,
        configurable: true,
        enumerable: true,
      });
    }

    next();
  };
}

export default massAssign;
