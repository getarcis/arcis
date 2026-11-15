/**
 * @module @arcis/node/middleware/headers
 * Security headers middleware
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { HeaderOptions } from '../core/types';
import { generateCspNonce } from './csp';
import { compileSecurityHeaders, parseForwardedProto, type SecurityHeaderPlan } from './security-headers';

/**
 * Create Express middleware for security headers.
 *
 * Without `profile`, the historical Arcis defaults apply. With
 * `profile: 'baseline'`, defaults and options match Helmet 8, so
 * `helmet(options)` can be replaced by `createHeaders({ profile: 'baseline', ...options })`.
 * Invalid options throw here, at construction.
 *
 * Headers are set before the route handler runs, so a header the route sets
 * itself takes precedence.
 *
 * @param options - Header configuration
 * @returns Express middleware
 *
 * @example
 * app.use(createHeaders());
 *
 * @example
 * app.use(createHeaders({
 *   profile: 'baseline',
 *   contentSecurityPolicy: { nonce: true },
 * }));
 * // In a view: <script nonce="<%= cspNonce %>">...</script> (res.locals.cspNonce)
 */
export function createHeaders(options: HeaderOptions = {}): RequestHandler {
  const policy = compileSecurityHeaders(options);

  return (req: Request, res: Response, next: NextFunction) => {
    let plan: SecurityHeaderPlan;
    try {
      // Expose the nonce before CSP function values run, so they can read it.
      const nonce = policy.usesNonce ? generateCspNonce() : undefined;
      if (nonce) res.locals.cspNonce = nonce;
      const forwardedProto = parseForwardedProto(req.headers['x-forwarded-proto'] as string | undefined);
      plan = policy.plan({
        isHttps: req.secure || forwardedProto === 'https',
        request: req,
        response: res,
        nonce,
      });
    } catch (err) {
      // A CSP function value threw or returned an invalid entry (as in Helmet).
      next(err);
      return;
    }

    for (const [name, value] of plan.set) res.setHeader(name, value);
    for (const name of plan.remove) res.removeHeader(name);

    next();
  };
}

/**
 * Alias for createHeaders
 * @see createHeaders
 */
export const securityHeaders = createHeaders;
