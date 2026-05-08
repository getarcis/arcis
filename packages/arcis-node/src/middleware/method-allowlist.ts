/**
 * @module @arcis/node/middleware/method-allowlist
 *
 * HTTP method tampering protection (sdk-vectors.md tier 1 #26).
 *
 * Two related threats:
 *
 * 1. **Disallowed methods** — TRACE leaks Authorization headers (XST);
 *    CONNECT is for proxies and shouldn't reach an application server;
 *    custom verbs slip past route-handlers that only check `if (req.method
 *    === 'POST')`. The middleware rejects anything outside an allowlist
 *    with 405.
 *
 * 2. **Method-override bypass** — frameworks that respect
 *    `X-HTTP-Method-Override` let an attacker turn a GET into a POST or
 *    DELETE, bypassing route-level method checks. The middleware strips
 *    these headers BEFORE the route handler sees them.
 *
 * Pair with the bundle middleware:
 *
 * ```ts
 * import { arcis } from '@arcis/node';
 * import { methodAllowlist } from '@arcis/node/middleware/method-allowlist';
 *
 * app.use(methodAllowlist());
 * app.use(arcis());
 * ```
 *
 * Or standalone for fine-grained mounts:
 *
 * ```ts
 * app.use('/api', methodAllowlist({ allow: ['GET', 'POST'] }));
 * ```
 */

import type { RequestHandler } from 'express';

/**
 * Headers that frameworks treat as method overrides. Each one rewrites
 * `req.method` somewhere in the stack — we strip all three so a request
 * always travels under its wire method.
 */
const METHOD_OVERRIDE_HEADERS = [
  'x-http-method-override',
  'x-method-override',
  'x-http-method',
] as const;

const DEFAULT_ALLOWED_METHODS: readonly string[] = [
  'GET',
  'POST',
  'PUT',
  'DELETE',
  'HEAD',
  'OPTIONS',
  'PATCH',
];

export interface MethodAllowlistOptions {
  /**
   * Methods to permit. Each entry is uppercased before comparison so
   * `['get', 'post']` works the same as `['GET', 'POST']`. Defaults to
   * the full standard CRUD set: GET, POST, PUT, DELETE, HEAD, OPTIONS,
   * PATCH. TRACE and CONNECT are intentionally excluded — the former
   * leaks Authorization (XST), the latter is for proxies.
   */
  allow?: readonly string[];

  /**
   * Strip method-override headers (`X-HTTP-Method-Override`,
   * `X-Method-Override`, `X-HTTP-Method`) before the request reaches the
   * route handler. Default: true. Set to false only if your stack
   * legitimately uses one of these headers for client-method tunnelling
   * AND you've verified each override target is auth-checked
   * independently.
   */
  stripOverrideHeaders?: boolean;

  /** HTTP status code for the deny response. Default: 405 Method Not Allowed. */
  statusCode?: number;

  /** Error message body. Default: "Method not allowed". */
  message?: string;
}

/**
 * Build a method-allowlist middleware. Uppercase-matches `req.method`
 * against the allow set; strips override headers so downstream code
 * can't be tricked into running a different method's logic.
 */
export function methodAllowlist(options: MethodAllowlistOptions = {}): RequestHandler {
  const allow = new Set(
    (options.allow ?? DEFAULT_ALLOWED_METHODS).map((m) => m.toUpperCase()),
  );
  const strip = options.stripOverrideHeaders !== false;
  const statusCode = options.statusCode ?? 405;
  const message = options.message ?? 'Method not allowed';

  return (req, res, next) => {
    if (strip) {
      // Remove BEFORE the allowlist check so an attacker can't slip a
      // disallowed method through via override (e.g. wire GET +
      // X-HTTP-Method-Override: TRACE — strip the header, the GET
      // passes the allowlist, the override never reaches the route).
      for (const h of METHOD_OVERRIDE_HEADERS) {
        delete req.headers[h];
      }
    }

    const method = (req.method ?? '').toUpperCase();
    if (!allow.has(method)) {
      // 405 spec wants Allow header listing accepted methods.
      res.setHeader('Allow', Array.from(allow).join(', '));
      res.status(statusCode).json({
        error: message,
        method: req.method,
      });
      return;
    }

    next();
  };
}

export default methodAllowlist;
