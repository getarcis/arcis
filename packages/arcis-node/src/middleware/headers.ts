/**
 * @module @arcis/node/middleware/headers
 * Security headers middleware
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { HeaderOptions } from '../core/types';
import { parseForwardedProto, planSecurityHeaders } from './security-headers';

/**
 * Create Express middleware for security headers.
 * Sets CSP, HSTS, X-Frame-Options, and other security headers.
 *
 * @param options - Header configuration
 * @returns Express middleware
 *
 * @example
 * app.use(createHeaders());
 *
 * @example
 * app.use(createHeaders({
 *   frameOptions: 'SAMEORIGIN',
 *   contentSecurityPolicy: "default-src 'self'"
 * }));
 */
export function createHeaders(options: HeaderOptions = {}): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const forwardedProto = parseForwardedProto(req.headers['x-forwarded-proto'] as string | undefined);
    const plan = planSecurityHeaders(options, {
      isHttps: req.secure || forwardedProto === 'https',
    });

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
