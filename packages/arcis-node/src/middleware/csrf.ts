/**
 * @module @arcis/node/middleware/csrf
 * CSRF (Cross-Site Request Forgery) protection middleware
 *
 * Implements the double-submit cookie pattern:
 * 1. Server sets a CSRF token in a cookie
 * 2. Client must send the same token in a header or form field
 * 3. Middleware rejects requests where cookie token !== header/field token
 *
 * This works because an attacker's cross-origin form submission will include
 * the cookie automatically, but cannot read it (same-origin policy) to set
 * the matching header.
 */

import { randomBytes, timingSafeEqual } from 'crypto';
import type { Request, Response, NextFunction, RequestHandler } from 'express';

/** CSRF protection configuration */
export interface CsrfOptions {
  /** Cookie name for the CSRF token. Default: '_csrf' */
  cookieName?: string;
  /** Header name to check for the token. Default: 'x-csrf-token' */
  headerName?: string;
  /** Form field name to check for the token. Default: '_csrf' */
  fieldName?: string;
  /** Token byte length (hex-encoded = 2x chars). Default: 32 */
  tokenLength?: number;
  /** HTTP methods to protect. Default: ['POST', 'PUT', 'PATCH', 'DELETE'] */
  protectedMethods?: string[];
  /** Paths to exclude from CSRF checks (e.g., webhook endpoints) */
  excludePaths?: string[];
  /**
   * Per-request skip function. If it returns true, CSRF check is skipped
   * for that request. Useful for API key auth or signed webhooks.
   *
   * @example
   * skipCsrf: (req) => Boolean(req.headers['x-api-key'])
   */
  skipCsrf?: (req: Request) => boolean;
  /**
   * Use the __Host- cookie prefix for stronger cookie security.
   * When enabled, the browser enforces: Secure=true, no Domain, Path=/.
   * This prevents CSRF cookie theft across subdomains.
   * Default: false
   */
  useHostPrefix?: boolean;
  /** Cookie options */
  cookie?: {
    /** Cookie path. Default: '/' */
    path?: string;
    /** HttpOnly — set false so client JS can read it for headers. Default: false */
    httpOnly?: boolean;
    /** Secure flag (HTTPS only). Default: true in production */
    secure?: boolean;
    /** SameSite attribute. Default: 'Lax' */
    sameSite?: 'Strict' | 'Lax' | 'None';
    /** Cookie domain */
    domain?: string;
  };
  /** Custom error handler when CSRF validation fails */
  onError?: (req: Request, res: Response, next: NextFunction) => void;
  /**
   * Rotate the CSRF token after each successful validation on a protected
   * method. Defends against token-fixation attacks where an attacker plants
   * a known token before authentication. Default: false.
   *
   * When enabled, every successful POST/PUT/PATCH/DELETE causes the server to
   * issue a fresh token via Set-Cookie — the client must re-read the cookie
   * before the next mutating request.
   */
  rotateOnUse?: boolean;
}

const DEFAULTS = {
  cookieName: '_csrf',
  headerName: 'x-csrf-token',
  fieldName: '_csrf',
  tokenLength: 32,
  protectedMethods: ['POST', 'PUT', 'PATCH', 'DELETE'],
} as const;

/**
 * Generate a cryptographically random CSRF token.
 *
 * @param length - Byte length (output is hex, so 2x chars). Default: 32
 * @returns Hex-encoded random token
 *
 * @example
 * const token = generateCsrfToken(); // 64 hex chars
 */
export function generateCsrfToken(length: number = 32): string {
  return randomBytes(length).toString('hex');
}

/**
 * Validate that two CSRF tokens match using constant-time comparison.
 *
 * @param cookieToken - Token from the cookie
 * @param requestToken - Token from the header or form field
 * @returns true if tokens match
 */
export function validateCsrfToken(cookieToken: string, requestToken: string): boolean {
  if (!cookieToken || !requestToken) return false;
  if (cookieToken.length !== requestToken.length) return false;

  // SECURITY: Use Node.js built-in constant-time comparison to prevent timing attacks
  const a = Buffer.from(cookieToken);
  const b = Buffer.from(requestToken);
  return timingSafeEqual(a, b);
}

/**
 * Extract the CSRF token from a request (checks header, then body field, then query).
 */
function getRequestToken(req: Request, headerName: string, fieldName: string): string | undefined {
  // 1. Check header (most common for SPAs)
  const headerToken = req.headers[headerName.toLowerCase()];
  if (typeof headerToken === 'string' && headerToken) return headerToken;

  // 2. Check body field (form submissions)
  if (req.body && typeof req.body === 'object' && fieldName in req.body) {
    const bodyToken = req.body[fieldName];
    if (typeof bodyToken === 'string' && bodyToken) return bodyToken;
  }

  // SECURITY: Query string intentionally not supported — tokens in URLs leak
  // to server logs, Referer headers, browser history, and CDN/proxy logs.

  return undefined;
}

/**
 * Create CSRF protection middleware using double-submit cookie pattern.
 *
 * For safe methods (GET, HEAD, OPTIONS), sets a CSRF token cookie if not present.
 * For unsafe methods (POST, PUT, PATCH, DELETE), validates the token.
 *
 * @param options - CSRF configuration
 * @returns Express middleware
 *
 * @example
 * // Basic usage
 * app.use(csrfProtection());
 *
 * @example
 * // Exclude webhook paths
 * app.use(csrfProtection({
 *   excludePaths: ['/api/webhooks/stripe', '/api/webhooks/github']
 * }));
 *
 * @example
 * // Client-side: read cookie + set header
 * const token = document.cookie.match(/_csrf=([^;]+)/)?.[1];
 * fetch('/api/data', {
 *   method: 'POST',
 *   headers: { 'X-CSRF-Token': token },
 *   credentials: 'same-origin'
 * });
 */
export function csrfProtection(options: CsrfOptions = {}): RequestHandler {
  const baseCookieName = options.cookieName ?? DEFAULTS.cookieName;
  // __Host- prefix: forces browser to enforce Secure + no Domain + Path=/
  const cookieName = options.useHostPrefix ? `__Host-${baseCookieName}` : baseCookieName;
  const headerName = options.headerName ?? DEFAULTS.headerName;
  const fieldName = options.fieldName ?? DEFAULTS.fieldName;
  const tokenLength = options.tokenLength ?? DEFAULTS.tokenLength;
  const protectedMethods = options.protectedMethods ?? [...DEFAULTS.protectedMethods];
  const excludePaths = options.excludePaths ?? [];
  const skipCsrf = options.skipCsrf;

  const isProduction = process.env.NODE_ENV === 'production';
  const cookieOpts = {
    path: options.cookie?.path ?? '/',
    httpOnly: options.cookie?.httpOnly ?? false, // Must be readable by client JS
    secure: options.cookie?.secure ?? isProduction,
    sameSite: options.cookie?.sameSite ?? 'Lax',
    domain: options.cookie?.domain,
  };

  const defaultOnError = (req: Request, res: Response, _next: NextFunction) => {
    // Telemetry attribution: dashboard groups CSRF denials under vector=csrf.
    req.__arcis = {
      vector: 'csrf',
      rule: 'csrf/token-mismatch',
      severity: 'high',
      reason: 'CSRF token missing or invalid',
      decision: 'deny',
    };
    res.status(403).json({
      error: 'CSRF token validation failed',
      message: 'Invalid or missing CSRF token. Include the token from the cookie in the X-CSRF-Token header.',
    });
  };

  const onError = options.onError ?? defaultOnError;

  // Normalize protected methods to uppercase
  const protectedSet = new Set(protectedMethods.map(m => m.toUpperCase()));

  return (req: Request, res: Response, next: NextFunction) => {
    const method = req.method.toUpperCase();

    // Per-request skip callback (API keys, signed webhooks, etc.)
    if (skipCsrf && skipCsrf(req)) {
      return next();
    }

    // Check if path is excluded
    const requestPath = req.path || req.url;
    if (excludePaths.some(p => requestPath === p || requestPath.startsWith(p + '/'))) {
      return next();
    }

    // Expose token generation on the request for templates/views
    (req as unknown as Record<string, unknown>).csrfToken = () => {
      const existing = getCookieValue(req, cookieName);
      if (existing) return existing;

      const token = generateCsrfToken(tokenLength);
      setCsrfCookie(res, cookieName, token, cookieOpts);
      return token;
    };

    // For safe methods — ensure a CSRF cookie exists
    if (!protectedSet.has(method)) {
      const existing = getCookieValue(req, cookieName);
      if (!existing) {
        const token = generateCsrfToken(tokenLength);
        setCsrfCookie(res, cookieName, token, cookieOpts);
      }
      return next();
    }

    // For protected methods — validate the token
    const cookieToken = getCookieValue(req, cookieName);
    if (!cookieToken) {
      return onError(req, res, next);
    }

    const requestToken = getRequestToken(req, headerName, fieldName);
    if (!requestToken) {
      return onError(req, res, next);
    }

    if (!validateCsrfToken(cookieToken, requestToken)) {
      return onError(req, res, next);
    }

    // Optional token rotation on successful validation
    if (options.rotateOnUse) {
      const freshToken = generateCsrfToken(tokenLength);
      setCsrfCookie(res, cookieName, freshToken, cookieOpts);
    }

    next();
  };
}

/**
 * Read a cookie value from the request.
 */
function getCookieValue(req: Request, name: string): string | undefined {
  // Express parses cookies if cookie-parser is used
  if (req.cookies && typeof req.cookies === 'object' && name in req.cookies) {
    return req.cookies[name];
  }

  // Fallback: parse from raw Cookie header
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return undefined;

  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${escapeRegex(name)}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : undefined;
}

/**
 * Set the CSRF token cookie on the response.
 */
function setCsrfCookie(
  res: Response,
  name: string,
  token: string,
  opts: { path: string; httpOnly: boolean; secure: boolean; sameSite: string; domain?: string }
): void {
  const parts = [`${name}=${token}`];
  parts.push(`Path=${opts.path}`);
  if (opts.httpOnly) parts.push('HttpOnly');
  if (opts.secure) parts.push('Secure');
  parts.push(`SameSite=${opts.sameSite}`);
  if (opts.domain) parts.push(`Domain=${opts.domain}`);

  // Accumulate Set-Cookie headers to avoid overwriting cookies set by other middleware
  const newCookie = parts.join('; ');
  const existing = res.getHeader('Set-Cookie');
  if (existing === undefined) {
    res.setHeader('Set-Cookie', newCookie);
  } else if (Array.isArray(existing)) {
    res.setHeader('Set-Cookie', [...existing, newCookie]);
  } else {
    res.setHeader('Set-Cookie', [existing as string, newCookie]);
  }
}

/**
 * Escape special regex characters in a string.
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Alias for csrfProtection */
export const createCsrf = csrfProtection;
