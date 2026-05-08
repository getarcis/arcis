/**
 * @module @arcis/node/sanitizers/graphql
 * GraphQL injection prevention (sdk-vectors.md tier 1 #21).
 *
 * Two threats covered:
 *
 * 1. **Depth-bomb DoS** — nested-query payloads like
 *    `query { x { x { x { ... } } } }` to ridiculous depth that explode
 *    resolver work (each `{` typically maps to a database round-trip).
 *    Even a 50-deep query against a real schema can hammer the
 *    backend; 1000-deep crashes the resolver entirely.
 *
 * 2. **Introspection abuse** — `__schema` / `__type` / `__typename`
 *    queries that let an attacker enumerate the entire schema, then
 *    use that map to find sensitive fields, deprecated mutations,
 *    or unprotected admin paths. Production GraphQL endpoints should
 *    disable introspection by default.
 *
 * v1 is regex-based: count `{` / `}` for nesting depth (no escape
 * handling — strings inside the query that contain `{` will
 * over-count). False positives are an acceptable tradeoff for v1
 * because (a) the depth threshold is well above legitimate query
 * shapes, (b) a real GraphQL parser pulls in `graphql` as a runtime
 * dep — significant for a sanitizer that ships in every Arcis
 * install. Customers running queries near the threshold can either
 * raise `maxDepth` or bring their own AST pre-pass.
 *
 * NOT included in v1:
 * - Field-count limit (some servers have this; orthogonal to depth)
 * - Alias-bomb detection (`q { f1: foo, f2: foo, ...}` — easier as
 *   a length-check than a parse)
 * - Variable rebinding attacks
 *
 * Each is a follow-up if customers ask. Documented inline.
 */

export interface GraphqlGuardOptions {
  /** Maximum allowed nesting depth. Default: 10. Most legit queries are <8. */
  maxDepth?: number;
  /** Maximum query string length in characters. Default: 10000. */
  maxLength?: number;
  /**
   * Block introspection queries (`__schema`, `__type`). Default: true.
   * Set `false` in development if you rely on GraphiQL / Apollo
   * Studio. Production should leave this on.
   */
  blockIntrospection?: boolean;
}

export type GraphqlViolation = 'depth' | 'length' | 'introspection';

export interface GraphqlGuardResult {
  /** True if the query violated any configured limit. */
  blocked: boolean;
  /** Which limit fired first (depth → introspection → length precedence). */
  reason?: GraphqlViolation;
  /** Observed nesting depth. Always returned, even on clean queries. */
  depth: number;
  /** Observed length. Always returned. */
  length: number;
}

const DEFAULTS = {
  maxDepth: 10,
  maxLength: 10000,
  blockIntrospection: true,
} as const;

/**
 * Word-boundary `__` reflection markers. GraphQL spec reserves the
 * `__` prefix for introspection — `__schema`, `__type`, `__typename`,
 * `__typeKind`, `__directive`. Matching the prefix catches them all
 * without enumerating; the boundary anchor (`\b__`) avoids
 * false-matches on user fields like `last__updated_at`.
 *
 * `__typename` is the one introspection field that's commonly used
 * legitimately (Apollo client requests it on every query). We
 * deliberately let it through by listing the others explicitly.
 */
const INTROSPECTION_PATTERN = /\b__(schema|type|typeKind|directive)\b/;

/**
 * Compute the maximum nesting depth of a GraphQL query string by
 * counting `{` and `}` runs. Strings inside the query (e.g.
 * `field(arg: "{...}")`) inflate this — accepted v1 tradeoff. A
 * future AST-mode implementation lives behind a separate flag.
 */
function computeDepth(query: string): number {
  let depth = 0;
  let max = 0;
  for (let i = 0; i < query.length; i++) {
    const c = query.charCodeAt(i);
    if (c === 123 /* { */) {
      depth++;
      if (depth > max) max = depth;
    } else if (c === 125 /* } */) {
      // Don't go negative on malformed input — clamp at 0.
      if (depth > 0) depth--;
    }
  }
  return max;
}

/**
 * Inspect a GraphQL query against the configured limits. Returns a
 * structured result; the middleware below uses this directly. Pure
 * function — no I/O, no res handle.
 */
export function inspectGraphqlQuery(
  query: string,
  options: GraphqlGuardOptions = {},
): GraphqlGuardResult {
  const maxDepth = options.maxDepth ?? DEFAULTS.maxDepth;
  const maxLength = options.maxLength ?? DEFAULTS.maxLength;
  const blockIntrospection = options.blockIntrospection ?? DEFAULTS.blockIntrospection;

  const length = query.length;
  const depth = computeDepth(query);

  // Precedence: depth > introspection > length. Depth is the most
  // expensive to surface (caller wants to know the actual number);
  // introspection is the most security-critical signal so beats
  // length; length last because it's the easiest false-positive
  // (long queries with deep inline fragments are legitimate).
  if (depth > maxDepth) {
    return { blocked: true, reason: 'depth', depth, length };
  }
  if (blockIntrospection && INTROSPECTION_PATTERN.test(query)) {
    return { blocked: true, reason: 'introspection', depth, length };
  }
  if (length > maxLength) {
    return { blocked: true, reason: 'length', depth, length };
  }

  return { blocked: false, depth, length };
}

/**
 * Detect-only API matching the rest of the sanitizer module surface
 * (`detectXss` / `detectSql` / `detectXxe` / etc.). Returns a boolean
 * for callers that just want a yes/no — use `inspectGraphqlQuery` if
 * you need the structured reason.
 */
export function detectGraphqlAbuse(
  query: string,
  options?: GraphqlGuardOptions,
): boolean {
  if (typeof query !== 'string' || query.length === 0) return false;
  return inspectGraphqlQuery(query, options).blocked;
}
