/**
 * @module @arcis/node/middleware/headers
 * Security headers middleware
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { HEADERS } from '../core/constants';
import type { HeaderOptions, HstsOptions } from '../core/types';

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
  const {
    contentSecurityPolicy = true,
    xssFilter = true,
    noSniff = true,
    frameOptions = HEADERS.FRAME_OPTIONS,
    hsts = true,
    referrerPolicy = HEADERS.REFERRER_POLICY,
    permissionsPolicy = HEADERS.PERMISSIONS_POLICY,
    cacheControl = true,
    crossOriginOpenerPolicy = 'same-origin',
    crossOriginResourcePolicy = 'same-origin',
    crossOriginEmbedderPolicy = 'require-corp',
    originAgentCluster = true,
    dnsPrefetchControl = true,
  } = options;

  return (req: Request, res: Response, next: NextFunction) => {
    // Content Security Policy
    if (contentSecurityPolicy) {
      const csp = typeof contentSecurityPolicy === 'string' 
        ? contentSecurityPolicy 
        : HEADERS.DEFAULT_CSP;
      res.setHeader('Content-Security-Policy', csp);
    }

    // X-XSS-Protection: 0 disables the legacy XSS auditor which was itself
    // an attack vector (could be abused to selectively block legitimate scripts)
    if (xssFilter) {
      res.setHeader('X-XSS-Protection', '0');
    }

    // Prevent MIME type sniffing
    if (noSniff) {
      res.setHeader('X-Content-Type-Options', HEADERS.CONTENT_TYPE_OPTIONS);
    }

    // Clickjacking protection
    if (frameOptions) {
      res.setHeader('X-Frame-Options', frameOptions);
    }

    // HTTPS enforcement (HSTS)
    // Only send HSTS over HTTPS — sending it over HTTP can brick HTTP-only
    // development servers and confuses browsers that cache the directive.
    // X-Forwarded-Proto is client-supplied so we validate the extracted value
    // is exactly 'https' or 'http' before trusting it.
    const forwardedProto = (req.headers['x-forwarded-proto'] as string | undefined)
      ?.split(',')[0]
      .trim()
      .toLowerCase();
    const trustedForwardedProto = forwardedProto === 'https' || forwardedProto === 'http'
      ? forwardedProto
      : undefined;
    const isHttps = req.secure || trustedForwardedProto === 'https';

    if (hsts && isHttps) {
      const hstsOpts: HstsOptions = typeof hsts === 'object' ? hsts : {};
      const maxAge = hstsOpts.maxAge ?? HEADERS.HSTS_MAX_AGE;
      const includeSubDomains = hstsOpts.includeSubDomains !== false;
      const preload = hstsOpts.preload === true;

      let hstsValue = `max-age=${maxAge}`;
      if (includeSubDomains) hstsValue += '; includeSubDomains';
      if (preload) hstsValue += '; preload';

      res.setHeader('Strict-Transport-Security', hstsValue);
    }

    // Referrer Policy
    if (referrerPolicy) {
      res.setHeader('Referrer-Policy', referrerPolicy);
    }

    // Permissions Policy
    if (permissionsPolicy) {
      res.setHeader('Permissions-Policy', permissionsPolicy);
    }

    // Cross-origin isolation headers (Spectre mitigation)
    if (crossOriginOpenerPolicy) {
      res.setHeader('Cross-Origin-Opener-Policy', crossOriginOpenerPolicy);
    }

    if (crossOriginResourcePolicy) {
      res.setHeader('Cross-Origin-Resource-Policy', crossOriginResourcePolicy);
    }

    if (crossOriginEmbedderPolicy) {
      res.setHeader('Cross-Origin-Embedder-Policy', crossOriginEmbedderPolicy);
    }

    // Request origin-keyed process isolation
    if (originAgentCluster) {
      res.setHeader('Origin-Agent-Cluster', '?1');
    }

    // Prevent DNS prefetching (privacy leak vector)
    if (dnsPrefetchControl) {
      res.setHeader('X-DNS-Prefetch-Control', 'off');
    }

    // Additional security headers
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');

    // Cache-Control headers
    if (cacheControl) {
      const cacheControlValue = typeof cacheControl === 'string'
        ? cacheControl
        : HEADERS.CACHE_CONTROL;
      res.setHeader('Cache-Control', cacheControlValue);
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }

    // Remove fingerprinting headers
    res.removeHeader('X-Powered-By');

    next();
  };
}

/**
 * Alias for createHeaders
 * @see createHeaders
 */
export const securityHeaders = createHeaders;
