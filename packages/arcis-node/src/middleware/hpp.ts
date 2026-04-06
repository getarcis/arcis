/**
 * @module @arcis/node/middleware/hpp
 * HTTP Parameter Pollution (HPP) protection middleware
 *
 * Normalizes duplicate query and body parameters to their last value,
 * preventing attackers from bypassing validation by repeating parameters.
 *
 * Attack example:
 *   GET /search?role=user&role=admin
 *   Without HPP: req.query.role = ['user', 'admin']
 *   With HPP:    req.query.role = 'admin'  (last value wins)
 *
 * Originals are preserved in req.queryPolluted / req.bodyPolluted
 * for logging or auditing without blocking the request.
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';

/** HPP protection configuration */
export interface HppOptions {
  /**
   * Parameters that legitimately accept arrays and should not be normalized.
   * Example: ['tags', 'ids', 'filter']
   */
  whitelist?: string[];
  /** Normalize duplicate query string parameters. Default: true */
  checkQuery?: boolean;
  /** Normalize duplicate body parameters. Default: true */
  checkBody?: boolean;
}

/**
 * HTTP Parameter Pollution protection middleware.
 *
 * Normalizes duplicate query/body parameters to a single value (last wins).
 * Whitelisted parameters are allowed to remain as arrays.
 *
 * @param options - HPP configuration
 * @returns Express middleware
 *
 * @example
 * // Basic — normalize all duplicates
 * app.use(hpp());
 *
 * @example
 * // Allow arrays for specific params (e.g., tag filters, IDs)
 * app.use(hpp({ whitelist: ['tags', 'ids'] }));
 *
 * @example
 * // Inspect what was removed (for logging)
 * app.use((req, res, next) => {
 *   const polluted = (req as any).queryPolluted;
 *   if (Object.keys(polluted).length) logger.warn('HPP detected', polluted);
 *   next();
 * });
 */
export function hpp(options: HppOptions = {}): RequestHandler {
  const whitelist = new Set(options.whitelist ?? []);
  const checkQuery = options.checkQuery ?? true;
  const checkBody = options.checkBody ?? true;

  return (req: Request, _res: Response, next: NextFunction) => {
    // ── Query string normalization ────────────────────────────────────────
    if (checkQuery && req.query && typeof req.query === 'object') {
      const polluted: Record<string, string[]> = {};
      const clean: Record<string, string | string[]> = {};

      for (const [key, value] of Object.entries(req.query)) {
        if (Array.isArray(value)) {
          const strings = value.filter((v): v is string => typeof v === 'string');
          if (whitelist.has(key)) {
            // Whitelisted — preserve as array
            clean[key] = strings;
          } else {
            // Duplicate — record originals, use last value
            polluted[key] = strings;
            clean[key] = strings[strings.length - 1] ?? '';
          }
        } else {
          clean[key] = value as string;
        }
      }

      (req as unknown as Record<string, unknown>).queryPolluted = polluted;
      // SECURITY: Express 5 makes req.query read-only — use defineProperty
      Object.defineProperty(req, 'query', { value: clean, writable: true, configurable: true });
    }

    // ── Body normalization ────────────────────────────────────────────────
    if (checkBody && req.body && typeof req.body === 'object' && !Array.isArray(req.body)) {
      const polluted: Record<string, unknown[]> = {};
      const clean: Record<string, unknown> = {};

      for (const [key, value] of Object.entries(req.body as Record<string, unknown>)) {
        if (Array.isArray(value)) {
          if (whitelist.has(key)) {
            clean[key] = value;
          } else {
            polluted[key] = value;
            clean[key] = value[value.length - 1];
          }
        } else {
          clean[key] = value;
        }
      }

      (req as unknown as Record<string, unknown>).bodyPolluted = polluted;
      Object.defineProperty(req, 'body', { value: clean, writable: true, configurable: true });
    }

    next();
  };
}

export const createHpp = hpp;
