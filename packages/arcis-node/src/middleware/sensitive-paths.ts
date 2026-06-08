/**
 * @module @arcis/node/middleware/sensitive-paths
 * v1.7 W2 wire-up. Blocks well-known scanner probe paths.
 *
 * Sensitive paths fall into three buckets and almost never have a
 * legitimate reason to be served by a typical app:
 *   1. Dotfile / VCS leaks   `/.env`, `/.git/*`, `/.svn/*`, `/.aws/`, ...
 *   2. PHP/Wordpress probes  `/wp-admin`, `/wp-login.php`, `/phpmyadmin`, ...
 *   3. Diagnostic endpoints  `/server-status`, `/phpinfo.php`, `/info.php`, ...
 *
 * Apps with legitimate routes that overlap (an actual WordPress site,
 * a custom `/admin` panel) opt out via `arcis({ scannerPaths: false })`
 * or pass a custom matcher list.
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';

export interface ScannerPathsOptions {
  /** HTTP status for blocked probes. Default: 403 */
  statusCode?: number;
  /** Error message for blocked probes. Default: 'Access denied.' */
  message?: string;
  /**
   * Custom matchers (overrides the default list entirely). Each entry
   * is matched against `req.path` with `.test()`. To EXTEND the default
   * list use `[...SENSITIVE_PATH_PATTERNS, /your-extra/]`.
   */
  patterns?: RegExp[];
}

/**
 * Default sensitive-path patterns. Each is a case-insensitive prefix
 * match anchored to the start of the request path. Conservative on
 * shapes that have any reasonable legit use; aggressive on dotfile and
 * VCS-leak paths that should never be served.
 */
export const SENSITIVE_PATH_PATTERNS: ReadonlyArray<RegExp> = Object.freeze([
  // Dotfile / VCS leaks — should never be served on any app.
  /^\/\.env(\.|\/|$)/i,
  /^\/\.git(\/|$)/i,
  /^\/\.svn(\/|$)/i,
  /^\/\.hg(\/|$)/i,
  /^\/\.bzr(\/|$)/i,
  /^\/\.aws(\/|$)/i,
  /^\/\.ssh(\/|$)/i,
  /^\/\.htaccess$/i,
  /^\/\.htpasswd$/i,
  /^\/\.npmrc$/i,
  /^\/\.dockerenv$/i,

  // WordPress + PHP probes — legit only on those platforms.
  /^\/wp-admin(\/|$)/i,
  /^\/wp-login\.php$/i,
  /^\/wp-config\.php$/i,
  /^\/wordpress\/wp-(admin|login)/i,
  /^\/xmlrpc\.php$/i,

  // Generic admin / DB-admin probes.
  /^\/admin\/?$/i,
  /^\/administrator\/?$/i,
  /^\/admin\.php$/i,
  /^\/phpmyadmin(\/|$)/i,
  /^\/pma(\/|$)/i,
  /^\/myadmin(\/|$)/i,
  /^\/dbadmin(\/|$)/i,
  /^\/adminer\.php$/i,

  // Diagnostic / info-leak endpoints.
  /^\/phpinfo\.php$/i,
  /^\/info\.php$/i,
  /^\/test\.php$/i,
  /^\/shell\.php$/i,
  /^\/server-status$/i,
  /^\/server-info$/i,

  // Backup / dump leaks.
  /^\/backup(\.|\/)/i,
  /^\/dump\.sql$/i,
  /^\/database\.sql$/i,
]);

/**
 * Test a URL path against the sensitive-path list. Returns the first
 * matching pattern's source for logging/telemetry, or `null`.
 */
export function detectSensitivePath(
  path: string,
  patterns: ReadonlyArray<RegExp> = SENSITIVE_PATH_PATTERNS,
): string | null {
  for (const re of patterns) {
    if (re.test(path)) return re.source;
  }
  return null;
}

/**
 * Build an Express middleware that blocks sensitive-path probes.
 * `arcis()` wires this on by default; users can opt out via
 * `arcis({ scannerPaths: false })`.
 */
export function scannerPathProtection(
  options: ScannerPathsOptions = {},
): RequestHandler {
  const { statusCode = 403, message = 'Access denied.' } = options;
  const patterns = options.patterns ?? SENSITIVE_PATH_PATTERNS;

  return (req: Request, res: Response, next: NextFunction) => {
    const matched = detectSensitivePath(req.path, patterns);
    if (matched === null) {
      return next();
    }
    (req as unknown as Record<string, unknown>).scannerPathHit = matched;
    res.status(statusCode).json({
      error: message,
      code: 'SECURITY_THREAT',
      vector: 'scanner-path',
    });
  };
}
