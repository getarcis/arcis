/**
 * @module @arcis/node/middleware/response-splitting
 *
 * HTTP response splitting prevention (sdk-vectors.md tier 1 #27).
 *
 * Response splitting is the *output* counterpart to header injection: app
 * code passes user input into `res.setHeader`, `res.writeHead`, or
 * `res.appendHeader` (Node 17+) without stripping CR/LF, and an attacker
 * uses the embedded newline to break out of the header block and forge a
 * second response. Most often weaponised against `Location:` after a
 * redirect that reflects user input (`/redirect?to=...`).
 *
 * `sanitizeHeaderValue` already covers the byte-level fix on the way in;
 * this middleware wraps the response object so every header that leaves
 * the app gets sanitised on the way out — even when the app forgets.
 *
 * ```ts
 * import { responseSplittingGuard } from '@arcis/node/middleware/response-splitting';
 *
 * app.use(responseSplittingGuard());
 *
 * // Later — even this passes through clean:
 * app.get('/r', (req, res) => res.redirect(req.query.to as string));
 * ```
 *
 * Pair with `validateRedirect` for full coverage: this middleware blocks
 * the response-splitting payload, `validateRedirect` blocks the
 * open-redirect payload.
 */

import type { RequestHandler, Response } from 'express';
import { detectHeaderInjection, sanitizeHeaderValue } from '../sanitizers/headers';

export interface ResponseSplittingGuardOptions {
  /**
   * What to do when an outgoing header value contains CR / LF / NUL.
   *
   * - `'strip'` (default) — silently sanitise the value before it reaches
   *   the wire. Preserves availability; existing routes don't break.
   * - `'reject'` — throw a `ResponseSplittingError`. Use in apps that
   *   would rather fail-closed than emit a partial response.
   *
   * Both modes invoke `onDetect` if provided.
   */
  mode?: 'strip' | 'reject';

  /**
   * Per-detection callback. Fires before strip/reject. Useful for
   * logging or alerting when an attempted split slips through into the
   * response builder.
   */
  onDetect?: (header: string, originalValue: string) => void;
}

/**
 * Thrown by `responseSplittingGuard({ mode: 'reject' })` when an
 * outgoing header value contains CR / LF / NUL. The header name is in
 * `header`; the originally attempted value is in `value` so it can be
 * logged or surfaced in an error handler.
 */
export class ResponseSplittingError extends Error {
  readonly header: string;
  readonly value: string;

  constructor(header: string, value: string) {
    super(`Response splitting attempt detected on header "${header}"`);
    this.name = 'ResponseSplittingError';
    this.header = header;
    this.value = value;
  }
}

/**
 * Re-export under the response-splitting name. Same byte pattern as
 * header injection (CR / LF / NUL) — different threat model: input
 * boundary vs output boundary.
 */
export const detectResponseSplitting = detectHeaderInjection;

/**
 * Re-export under the response-splitting name. Strips CR / LF / NUL.
 */
export const sanitizeResponseHeader = sanitizeHeaderValue;

/**
 * Sanitise both the header name and value. Header *names* with CRLF are
 * always a bug — they let an attacker overwrite arbitrary subsequent
 * headers — so they are always stripped regardless of mode.
 */
function safeName(name: unknown): string {
  return sanitizeHeaderValue(String(name ?? ''));
}

function valuesArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((v) => String(v));
  if (value === undefined || value === null) return [];
  return [String(value)];
}

/**
 * Build the response-splitting guard middleware. Wraps `res.setHeader`,
 * `res.writeHead`, and `res.appendHeader` (when present) on each
 * incoming request so every header that leaves the app gets the same
 * CRLF / NUL treatment regardless of which code path emitted it.
 *
 * Wrapping happens per-request (not on the prototype) so multiple
 * mounts with different options don't trample each other.
 */
export function responseSplittingGuard(
  options: ResponseSplittingGuardOptions = {},
): RequestHandler {
  const mode = options.mode ?? 'strip';
  const onDetect = options.onDetect;

  return (_req, res, next) => {
    const r = res as Response & {
      setHeader: Response['setHeader'];
      writeHead: Response['writeHead'];
      appendHeader?: (name: string, value: string | string[]) => Response;
    };

    const origSetHeader = r.setHeader.bind(r);
    const origWriteHead = r.writeHead.bind(r);
    const origAppendHeader = typeof r.appendHeader === 'function'
      ? r.appendHeader.bind(r)
      : undefined;

    function check(name: string, raw: unknown): unknown {
      const values = valuesArray(raw);
      const cleanedValues: string[] = [];
      for (const v of values) {
        if (detectHeaderInjection(v)) {
          if (onDetect) onDetect(name, v);
          if (mode === 'reject') {
            throw new ResponseSplittingError(name, v);
          }
          cleanedValues.push(sanitizeHeaderValue(v));
        } else {
          cleanedValues.push(v);
        }
      }
      // Preserve original cardinality: array → array, scalar → scalar.
      if (Array.isArray(raw)) return cleanedValues;
      if (raw === undefined || raw === null) return raw;
      return cleanedValues[0];
    }

    r.setHeader = function patchedSetHeader(
      name: string,
      value: number | string | readonly string[],
    ): Response {
      const safeKey = safeName(name);
      const safeValue = check(safeKey, value);
      return origSetHeader(safeKey, safeValue as number | string | readonly string[]);
    } as Response['setHeader'];

    r.writeHead = function patchedWriteHead(
      this: Response,
      statusCode: number,
      ...rest: unknown[]
    ): Response {
      let statusMessage: string | undefined;
      let headers: unknown;
      if (typeof rest[0] === 'string') {
        statusMessage = rest[0];
        headers = rest[1];
      } else {
        headers = rest[0];
      }

      let cleanedHeaders: unknown = headers;
      if (headers && typeof headers === 'object') {
        if (Array.isArray(headers)) {
          // Outgoing tuples: ['Set-Cookie', 'a=1\r\nb=2', ...]. Walk
          // pairs (Node accepts both flat and nested array shapes).
          if (headers.length > 0 && Array.isArray(headers[0])) {
            cleanedHeaders = (headers as unknown[][]).map((pair) => {
              const [k, v] = pair as [unknown, unknown];
              const sk = safeName(k);
              return [sk, check(sk, v)];
            });
          } else {
            const flat = headers as unknown[];
            const out: unknown[] = [];
            for (let i = 0; i < flat.length; i += 2) {
              const sk = safeName(flat[i]);
              out.push(sk, check(sk, flat[i + 1]));
            }
            cleanedHeaders = out;
          }
        } else {
          const out: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(headers as Record<string, unknown>)) {
            const sk = safeName(k);
            out[sk] = check(sk, v);
          }
          cleanedHeaders = out;
        }
      }

      // Express's typed writeHead drops the 3-arg http.ServerResponse
      // overload; defer to Node's runtime signature here.
      const wh = origWriteHead as unknown as (
        statusCode: number,
        statusMessageOrHeaders?: string | unknown,
        headers?: unknown,
      ) => Response;
      if (statusMessage !== undefined) {
        return wh(statusCode, statusMessage, cleanedHeaders);
      }
      return wh(statusCode, cleanedHeaders);
    } as Response['writeHead'];

    if (origAppendHeader) {
      r.appendHeader = function patchedAppendHeader(
        name: string,
        value: string | string[],
      ): Response {
        const safeKey = safeName(name);
        const safeValue = check(safeKey, value);
        return origAppendHeader(safeKey, safeValue as string | string[]);
      };
    }

    next();
  };
}

export default responseSplittingGuard;
