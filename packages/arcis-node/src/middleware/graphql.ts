/**
 * @module @arcis/node/middleware/graphql
 *
 * GraphQL request guard (sdk-vectors.md tier 1 #21). Wraps the
 * `inspectGraphqlQuery` sanitizer in an Express middleware that
 * pulls the query string from the standard places GraphQL servers
 * expect it (`req.body.query` for POST, `req.query.query` for GET)
 * and short-circuits with 400 + a structured error when the query
 * violates any configured limit.
 *
 * ```ts
 * import { graphqlGuard } from '@arcis/node';
 *
 * app.use('/graphql', graphqlGuard({
 *   maxDepth: 10,
 *   maxLength: 10000,
 *   blockIntrospection: process.env.NODE_ENV === 'production',
 * }));
 * ```
 *
 * Order with the rest of Arcis: install AFTER body-parsing
 * (`express.json()`) so `req.body.query` is populated, BEFORE the
 * GraphQL handler so the deny path short-circuits resolver work.
 */

import type { Request, RequestHandler, Response, NextFunction } from 'express';
import {
  inspectGraphqlQuery,
  type GraphqlGuardOptions,
  type GraphqlViolation,
} from '../sanitizers/graphql';

export interface GraphqlGuardMiddlewareOptions extends GraphqlGuardOptions {
  /** HTTP status to return on violation. Default: 400 (matches GraphQL spec for parse errors). */
  statusCode?: number;
  /** Custom message template. Default: built per-reason. */
  message?: string | ((reason: GraphqlViolation) => string);
}

const DEFAULT_MESSAGES: Record<GraphqlViolation, string> = {
  depth: 'Query exceeds maximum nesting depth',
  length: 'Query exceeds maximum length',
  introspection: 'Introspection queries are disabled',
  aliases: 'Query exceeds maximum alias count (alias-bomb protection)',
  fragment_cycle: 'Query contains a cyclic fragment definition',
};

/**
 * Pull the GraphQL query string from a request. Convention: POST
 * bodies carry `{ query, variables, operationName }`; GET requests
 * pass `?query=...` for persisted-query-style fetches. We check both
 * so the guard works regardless of transport.
 */
function extractQuery(req: Request): string | undefined {
  // Prefer body.query (POST is the dominant transport for GraphQL).
  const bodyQuery =
    typeof req.body === 'object' && req.body !== null
      ? (req.body as Record<string, unknown>).query
      : undefined;
  if (typeof bodyQuery === 'string') return bodyQuery;

  // Fall back to req.query.query (GET) — express stores query string
  // values as strings or arrays-of-strings.
  const qsQuery = req.query?.query;
  if (typeof qsQuery === 'string') return qsQuery;

  return undefined;
}

export function graphqlGuard(
  options: GraphqlGuardMiddlewareOptions = {},
): RequestHandler {
  const statusCode = options.statusCode ?? 400;
  const messageOption = options.message;

  return (req: Request, res: Response, next: NextFunction) => {
    const query = extractQuery(req);
    if (!query) {
      // No GraphQL query in the expected slots — could be a
      // mounted-elsewhere route or a non-GraphQL request slipping
      // through the same path. Pass through; the GraphQL handler
      // below will decide whether to error.
      next();
      return;
    }

    const result = inspectGraphqlQuery(query, options);
    if (!result.blocked) {
      next();
      return;
    }

    const reason = result.reason as GraphqlViolation;
    const message =
      typeof messageOption === 'function'
        ? messageOption(reason)
        : (messageOption ?? DEFAULT_MESSAGES[reason]);

    res.status(statusCode).json({
      error: message,
      reason,
      observed: {
        depth: result.depth,
        length: result.length,
      },
    });
  };
}

export default graphqlGuard;
