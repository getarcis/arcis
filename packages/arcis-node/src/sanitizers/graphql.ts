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
  /**
   * Maximum number of field aliases per query (`label: field`).
   * Default: 50. Alias-bomb attacks repeat the same expensive field
   * under many labels to multiply backend cost. Real queries rarely
   * use more than 20 aliases. improvements.md §1.2 V34.
   */
  maxAliases?: number;
  /**
   * Reject queries whose fragment definitions form a cycle (direct
   * self-reference `fragment A on T { ...A }` or indirect
   * `A → B → A`). Such cycles either infinite-loop a naive resolver
   * or get rejected by `graphql-core` with a 500. Default: true.
   * improvements.md §1.2 V34.
   */
  blockFragmentCycles?: boolean;
}

export type GraphqlViolation =
  | 'depth'
  | 'length'
  | 'introspection'
  | 'aliases'
  | 'fragment_cycle';

export interface GraphqlGuardResult {
  /** True if the query violated any configured limit. */
  blocked: boolean;
  /** Which limit fired first. Precedence: depth → introspection → aliases → fragment_cycle → length. */
  reason?: GraphqlViolation;
  /** Observed nesting depth. Always returned. */
  depth: number;
  /** Observed length. Always returned. */
  length: number;
  /** Observed alias count (improvements.md §1.2 V34). Always returned. */
  aliases: number;
}

const DEFAULTS = {
  maxDepth: 10,
  maxLength: 10000,
  blockIntrospection: true,
  maxAliases: 50,
  blockFragmentCycles: true,
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

// `label: field` — alias of one field to another name. Excludes
// patterns like `query Foo:` where Foo is an operation name (handled
// because the regex requires the second token to be a name AND
// alias semantics only apply inside `{...}` blocks; this is a
// lexical approximation, not a parser).
const ALIAS_PATTERN = /\b([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*([a-zA-Z_][a-zA-Z0-9_]*)\b/g;

// `fragment <name> on <type> {` — captures the fragment NAME.
const FRAGMENT_DEF_PATTERN =
  /\bfragment\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+on\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\{/g;

// `...FragmentName` spread inside a selection set.
const FRAGMENT_SPREAD_PATTERN = /\.\.\.\s*([a-zA-Z_][a-zA-Z0-9_]*)\b/g;

function countAliases(query: string): number {
  let n = 0;
  ALIAS_PATTERN.lastIndex = 0;
  while (ALIAS_PATTERN.exec(query) !== null) n++;
  return n;
}

/**
 * Detect cycles in the fragment spread graph (improvements.md §1.2 V34).
 *
 * Walks `fragment X on T { ... }` definitions, builds adjacency from
 * each fragment to the names it spreads, and runs DFS for a back-edge.
 * Body of each fragment is brace-matched so the subsequent query
 * operation's spreads don't pollute the graph.
 */
function hasFragmentCycle(query: string): boolean {
  const deps = new Map<string, Set<string>>();
  FRAGMENT_DEF_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = FRAGMENT_DEF_PATTERN.exec(query)) !== null) {
    const name = match[1];
    const bodyStart = match.index + match[0].length; // right after `{`
    // Brace-match to find the body end.
    let depth = 1;
    let i = bodyStart;
    while (i < query.length && depth > 0) {
      const ch = query[i];
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
      i++;
    }
    const bodyEnd = depth === 0 ? i - 1 : i;
    const body = query.slice(bodyStart, bodyEnd);
    const spreads = new Set<string>();
    FRAGMENT_SPREAD_PATTERN.lastIndex = 0;
    let sm: RegExpExecArray | null;
    while ((sm = FRAGMENT_SPREAD_PATTERN.exec(body)) !== null) {
      spreads.add(sm[1]);
    }
    deps.set(name, spreads);
  }
  if (deps.size === 0) return false;

  const WHITE = 0;
  const GRAY = 1;
  const BLACK = 2;
  const color = new Map<string, number>();
  for (const name of deps.keys()) color.set(name, WHITE);

  function visit(name: string): boolean {
    if (color.get(name) === GRAY) return true; // back-edge
    if (color.get(name) === BLACK) return false;
    if (!deps.has(name)) return false; // spread to undefined fragment
    color.set(name, GRAY);
    for (const child of deps.get(name)!) {
      if (visit(child)) return true;
    }
    color.set(name, BLACK);
    return false;
  }

  for (const name of deps.keys()) {
    if (visit(name)) return true;
  }
  return false;
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
  const maxAliases = options.maxAliases ?? DEFAULTS.maxAliases;
  const blockFragmentCycles =
    options.blockFragmentCycles ?? DEFAULTS.blockFragmentCycles;

  const length = query.length;
  const depth = computeDepth(query);
  const aliases = countAliases(query);

  // Precedence: depth → introspection → aliases → fragment_cycle →
  // length. Cheapest-to-explain failures first; length last because
  // it's the easiest false-positive (long queries with deep inline
  // fragments are legitimate). improvements.md §1.2 V34.
  if (depth > maxDepth) {
    return { blocked: true, reason: 'depth', depth, length, aliases };
  }
  if (blockIntrospection && INTROSPECTION_PATTERN.test(query)) {
    return { blocked: true, reason: 'introspection', depth, length, aliases };
  }
  if (aliases > maxAliases) {
    return { blocked: true, reason: 'aliases', depth, length, aliases };
  }
  if (blockFragmentCycles && hasFragmentCycle(query)) {
    return { blocked: true, reason: 'fragment_cycle', depth, length, aliases };
  }
  if (length > maxLength) {
    return { blocked: true, reason: 'length', depth, length, aliases };
  }

  return { blocked: false, depth, length, aliases };
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
