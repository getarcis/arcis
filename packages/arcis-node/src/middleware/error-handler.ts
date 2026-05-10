/**
 * @module @arcis/node/middleware/error-handler
 * Production-safe error handler middleware
 */

import type { Request, Response, NextFunction } from 'express';
import { ERRORS } from '../core/constants';
import type { ErrorHandlerOptions, HttpError } from '../core/types';

/**
 * Patterns that indicate database or infrastructure internals in error messages.
 * When detected, the message is replaced with a generic error to prevent info leakage.
 */
const SENSITIVE_ERROR_PATTERNS: RegExp[] = [
  // SQL database errors
  /\b(SQLITE_ERROR|SQLSTATE|ORA-\d|PG::|mysql_|pg_query|ECONNREFUSED)/i,
  /\b(syntax error at or near|relation ".*" does not exist)/i,
  /\b(column ".*" (does not exist|of relation))/i,
  /\b(duplicate key value violates unique constraint)/i,
  /\b(table .* doesn't exist|unknown column)/i,
  // MongoDB errors
  /\b(MongoError|MongoServerError|MongoNetworkError|E11000 duplicate key)/i,
  // Redis errors
  /\b(WRONGTYPE|CROSSSLOT|CLUSTERDOWN|READONLY|ReplyError)/i,
  // Connection strings and DSNs
  /\b(mongodb(\+srv)?:\/\/|postgres(ql)?:\/\/|mysql:\/\/|redis:\/\/)/i,
  // Stack traces with file paths
  /\bat\s+.*\.(js|ts|py|go|java):\d+/i,
  // Internal IP addresses
  /\b(127\.0\.0\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b/,
];

/**
 * Check if an error message contains sensitive infrastructure details.
 */
export function containsSensitiveInfo(message: string): boolean {
  return SENSITIVE_ERROR_PATTERNS.some(pattern => pattern.test(message));
}

/**
 * Create Express error handler that hides sensitive details in production.
 *
 * Prevents information leakage by:
 * - Hiding stack traces in production
 * - Hiding error messages unless explicitly exposed
 * - Scrubbing database errors, connection strings, and internal IPs
 *
 * @param options - Error handler configuration (or boolean for isDev)
 * @returns Express error handling middleware
 *
 * @example
 * // Production mode (default) - hides error details
 * app.use(errorHandler());
 *
 * @example
 * // Development mode - shows error details and stack traces
 * app.use(errorHandler({ isDev: true }));
 *
 * @example
 * // With custom logger
 * app.use(errorHandler({
 *   isDev: false,
 *   logger: arcis.logger()
 * }));
 */
export function errorHandler(
  options: ErrorHandlerOptions | boolean = false
): (err: Error, req: Request, res: Response, next: NextFunction) => void {
  const isDev = typeof options === 'boolean' ? options : options.isDev ?? false;
  const logErrors = typeof options === 'object' ? options.logErrors ?? true : true;
  const logger = typeof options === 'object' ? options.logger : undefined;
  const customHandler = typeof options === 'object' ? options.customHandler : undefined;

  return (err: HttpError, req: Request, res: Response, _next: NextFunction) => {
    // Clamp to a valid HTTP error range. A thrown error with a bogus
    // statusCode (negative, zero, or > 599) would otherwise be sent to
    // the client and break proxies, browsers, or compliance scanners.
    const rawStatus = err.statusCode ?? err.status ?? 500;
    const statusCode =
      Number.isFinite(rawStatus) && rawStatus >= 400 && rawStatus <= 599
        ? Math.floor(rawStatus)
        : 500;

    // Custom handler takes precedence
    if (customHandler) {
      return customHandler(err, req, res);
    }

    // Always log full error details server-side
    if (logErrors) {
      const logData = {
        error: err.message,
        stack: err.stack,
        statusCode,
        path: req.path,
        method: req.method,
      };

      if (logger) {
        logger.error('Request error', logData);
      } else {
        // eslint-disable-next-line no-console
        console.error('[arcis] Request error:', logData);
      }
    }

    // Build response
    // Only expose err.message when err.expose === true (caller opted in) or in dev mode.
    // This prevents internal details leaking through arbitrary 4xx errors that happen
    // to contain sensitive info (e.g. "DB query failed for user admin@corp.com").
    const exposeMessage = isDev || err.expose === true;

    let clientMessage: string;
    if (!exposeMessage) {
      clientMessage = ERRORS.INTERNAL_SERVER_ERROR;
    } else if (containsSensitiveInfo(err.message)) {
      // Even when expose is true, scrub DB errors and infra details
      clientMessage = isDev ? err.message : ERRORS.INTERNAL_SERVER_ERROR;
    } else {
      clientMessage = err.message;
    }

    const response: Record<string, unknown> = {
      error: clientMessage,
    };

    // Only show details in development
    if (isDev) {
      response.stack = err.stack;
      response.details = err.message;
    }

    res.status(statusCode).json(response);
  };
}

/**
 * Alias for errorHandler
 * @see errorHandler
 */
export const createErrorHandler = errorHandler;
