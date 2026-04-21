/**
 * @module @arcis/node/middleware/cookies
 * Secure cookie defaults middleware
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';

/** Cookie security configuration */
export interface SecureCookieOptions {
  /** Force HttpOnly on all cookies. Default: true */
  httpOnly?: boolean;
  /** Force Secure flag (HTTPS only). Default: true in production, false in dev */
  secure?: boolean;
  /** SameSite attribute. Default: 'Lax' */
  sameSite?: 'Strict' | 'Lax' | 'None' | false;
  /** Override Path attribute. Default: undefined (keep original) */
  path?: string;
}

const COOKIE_ATTRS = {
  HTTP_ONLY: '; HttpOnly',
  SECURE: '; Secure',
  SAME_SITE_STRICT: '; SameSite=Strict',
  SAME_SITE_LAX: '; SameSite=Lax',
  SAME_SITE_NONE: '; SameSite=None',
} as const;

/**
 * Enforce secure defaults on a Set-Cookie header value.
 */
export function enforceSecureCookie(
  cookieStr: string,
  options: Required<Omit<SecureCookieOptions, 'path'>> & { path?: string }
): string {
  const lower = cookieStr.toLowerCase();
  let result = cookieStr;

  // HttpOnly — prevent JavaScript access
  if (options.httpOnly && !lower.includes('httponly')) {
    result += COOKIE_ATTRS.HTTP_ONLY;
  }

  // Secure — HTTPS only
  if (options.secure && !lower.includes('; secure')) {
    result += COOKIE_ATTRS.SECURE;
  }

  // SameSite — CSRF protection
  if (options.sameSite !== false && !lower.includes('samesite')) {
    switch (options.sameSite) {
      case 'Strict':
        result += COOKIE_ATTRS.SAME_SITE_STRICT;
        break;
      case 'None':
        result += COOKIE_ATTRS.SAME_SITE_NONE;
        // SameSite=None requires Secure
        if (!result.toLowerCase().includes('; secure')) {
          result += COOKIE_ATTRS.SECURE;
        }
        break;
      case 'Lax':
      default:
        result += COOKIE_ATTRS.SAME_SITE_LAX;
        break;
    }
  }

  // Override path if specified
  if (options.path) {
    if (lower.includes('path=')) {
      result = result.replace(/;\s*path=[^;]*/i, `; Path=${options.path}`);
    } else {
      result += `; Path=${options.path}`;
    }
  }

  return result;
}

/**
 * Create middleware that enforces secure cookie defaults.
 *
 * Intercepts Set-Cookie headers and adds missing security attributes:
 * - HttpOnly: prevents JavaScript access (XSS cookie theft)
 * - Secure: cookies only sent over HTTPS
 * - SameSite: CSRF protection
 *
 * @param options - Cookie security configuration
 * @returns Express middleware
 *
 * @example
 * // Enforce defaults on all cookies
 * app.use(secureCookieDefaults());
 *
 * @example
 * // Strict SameSite for sensitive apps
 * app.use(secureCookieDefaults({ sameSite: 'Strict' }));
 */
export function secureCookieDefaults(options: SecureCookieOptions = {}): RequestHandler {
  const isProduction = process.env.NODE_ENV === 'production';
  const resolved = {
    httpOnly: options.httpOnly ?? true,
    secure: options.secure ?? isProduction,
    sameSite: options.sameSite ?? 'Lax' as const,
    path: options.path,
  };

  // Fail loudly on incompatible combinations — silent misconfiguration is a
  // common footgun (e.g. SameSite=None without Secure is rejected by every
  // modern browser, producing a request that just silently loses cookies).
  if (resolved.sameSite === 'None' && resolved.secure === false) {
    throw new Error(
      '[arcis] secureCookieDefaults: sameSite=None requires secure=true (modern browsers reject the cookie otherwise)'
    );
  }
  if (resolved.httpOnly === false && resolved.secure === false && isProduction) {
    // Only a warning — some apps legitimately need non-HttpOnly cookies (e.g. CSRF double-submit).
    // But running both off in production is almost never intentional.
    // eslint-disable-next-line no-console
    console.warn(
      '[arcis] secureCookieDefaults: httpOnly and secure are both disabled in production — cookies will be readable by JS and sent over HTTP'
    );
  }

  return (_req: Request, res: Response, next: NextFunction) => {
    // Monkey-patch res.setHeader to intercept Set-Cookie
    const originalSetHeader = res.setHeader.bind(res);

    res.setHeader = function patchedSetHeader(name: string, value: string | number | readonly string[]) {
      if (name.toLowerCase() === 'set-cookie') {
        if (Array.isArray(value)) {
          value = value.map(v => enforceSecureCookie(String(v), resolved));
        } else {
          value = enforceSecureCookie(String(value), resolved);
        }
      }
      return originalSetHeader(name, value);
    } as typeof res.setHeader;

    next();
  };
}

/**
 * Alias for secureCookieDefaults
 * @see secureCookieDefaults
 */
export const createSecureCookies = secureCookieDefaults;
