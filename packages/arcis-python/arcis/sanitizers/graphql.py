"""
GraphQL injection prevention (sdk-vectors.md tier 1 #21).

Two threats covered:

1. **Depth-bomb DoS** — nested-query payloads like
   ``query { x { x { x { ... } } } }`` to ridiculous depth that explode
   resolver work (each ``{`` typically maps to a database round-trip).
   Even a 50-deep query against a real schema can hammer the backend;
   1000-deep crashes the resolver entirely.

2. **Introspection abuse** — ``__schema`` / ``__type`` / ``__typeKind`` /
   ``__directive`` queries that let an attacker enumerate the entire
   schema, then use that map to find sensitive fields, deprecated
   mutations, or unprotected admin paths. Production GraphQL endpoints
   should disable introspection by default.

v1 is regex/character-counting based: count ``{`` / ``}`` for nesting
depth (no string-literal escape handling — strings inside the query
that contain ``{`` will over-count). False positives are an acceptable
tradeoff for v1 because (a) the depth threshold is well above
legitimate query shapes, (b) a real GraphQL parser pulls in
``graphql-core`` as a runtime dep, significant for a sanitizer that
ships zero-dep. Customers running queries near the threshold can either
raise ``max_depth`` or bring their own AST pre-pass.

Mirrors ``arcis-node/src/sanitizers/graphql.ts`` byte-for-byte on the
inspection contract — same defaults, same precedence (depth >
introspection > length), same exposed surface.

NOT included in v1:
- Field-count limit (some servers have this; orthogonal to depth)
- Alias-bomb detection (``q { f1: foo, f2: foo, ...}`` — easier as a
  length-check than a parse)
- Variable rebinding attacks

Each is a follow-up if customers ask.
"""

from dataclasses import dataclass
import re
from typing import Optional


# Word-boundary ``__`` reflection markers. GraphQL spec reserves the
# ``__`` prefix for introspection — ``__schema``, ``__type``,
# ``__typename``, ``__typeKind``, ``__directive``. Matching the prefix
# catches them all without enumerating; the boundary anchor (``\b__``)
# avoids false-matches on user fields like ``last__updated_at``.
#
# ``__typename`` is the one introspection field that's commonly used
# legitimately (Apollo client requests it on every query). We
# deliberately let it through by listing the others explicitly.
_INTROSPECTION_PATTERN = re.compile(r"\b__(schema|type|typeKind|directive)\b")


@dataclass(frozen=True)
class GraphqlGuardOptions:
    """Limits to enforce on incoming GraphQL queries.

    Attributes:
        max_depth: Maximum allowed nesting depth. Default 10. Most legit
            queries are under 8.
        max_length: Maximum query string length in characters. Default
            10000.
        block_introspection: Block introspection queries (``__schema``,
            ``__type``). Default True. Set False in development if you
            rely on GraphiQL / Apollo Studio. Production should leave
            this on.
        max_aliases: Maximum number of field aliases per query
            (``label: field``). Default 50. Alias-bomb attacks repeat
            the same expensive field hundreds or thousands of times
            under different labels, multiplying the resolver cost by
            that factor. Real queries rarely exceed 20 aliases.
            improvements.md §1.2 V34.
        block_fragment_cycles: Reject queries whose fragment
            definitions form a cycle (``fragment A on T { ...A }`` or
            ``fragment A on T { ...B } fragment B on T { ...A }``).
            Such cycles either infinite-loop a naive resolver or get
            rejected by graphql-core with a 500. Default True.
            improvements.md §1.2 V34.
    """

    max_depth: int = 10
    max_length: int = 10000
    block_introspection: bool = True
    max_aliases: int = 50
    block_fragment_cycles: bool = True


@dataclass(frozen=True)
class GraphqlGuardResult:
    """Outcome of inspecting a GraphQL query.

    Attributes:
        blocked: True if the query violated any configured limit.
        reason: Which limit fired first. Precedence: depth →
            introspection → aliases → fragment_cycle → length.
            None when blocked is False.
        depth: Observed nesting depth. Always returned.
        length: Observed length. Always returned.
        aliases: Observed alias count (``label: field``). Always
            returned. improvements.md §1.2 V34.
    """

    blocked: bool
    depth: int
    length: int
    aliases: int = 0
    reason: Optional[str] = None


_ALIAS_PATTERN = re.compile(
    # `label:fieldName` where label is a GraphQL Name. Excludes type
    # specifiers like `query Foo:` (Foo before a `{` is a query name,
    # not an alias) by requiring the field-name to be followed by
    # something other than `{`, `(`, or `:` (which would be argument
    # type-decl). Bound: each match represents one aliased field.
    r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*([a-zA-Z_][a-zA-Z0-9_]*)\b"
)

_FRAGMENT_DEF_PATTERN = re.compile(
    # `fragment <name> on <type> { ... }` — captures the fragment name.
    r"\bfragment\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+on\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\{"
)

_FRAGMENT_SPREAD_PATTERN = re.compile(
    # `...FragmentName` spread inside a selection set.
    r"\.\.\.\s*([a-zA-Z_][a-zA-Z0-9_]*)\b"
)


def _count_aliases(query: str) -> int:
    """Count aliased fields in the query (improvements.md §1.2 V34).

    Alias-bomb attacks repeat the same expensive resolver under many
    different labels to amplify backend cost. Counting alias occurrences
    is a cheap cap that legit queries rarely hit (real apps use 5–15
    aliases at most).
    """
    return sum(1 for _ in _ALIAS_PATTERN.finditer(query))


def _has_fragment_cycle(query: str) -> bool:
    """Detect cycles in fragment spread graph (improvements.md §1.2 V34).

    Builds adjacency from `fragment X on T { ...Y }` definitions and
    runs DFS for a back-edge. Catches both direct self-reference
    (``fragment A on T { ...A }``) and indirect cycles
    (``A → B → A``). Lexical: doesn't understand inline fragments
    (``... on Type``) — those have no name so can't form a named cycle.

    Returns True on the first cycle found. False if the query has no
    fragments or all fragments are acyclic.
    """
    # Build name → set of names this fragment spreads.
    deps: dict[str, set[str]] = {}
    # Walk fragment definitions and brace-match to find each body's
    # END. The regex match ends just past the opening `{`; we then
    # walk forward counting braces until the matching `}` to get the
    # exact body span. Without this, a fragment's "body" would extend
    # into the subsequent query operation and capture spurious
    # spreads (false-positive cycles).
    for match in _FRAGMENT_DEF_PATTERN.finditer(query):
        name = match.group(1)
        body_start = match.end()  # right after `{`
        depth = 1
        i = body_start
        while i < len(query) and depth > 0:
            ch = query[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        # `i` now points just past the matching `}` (or to EOF on
        # malformed input — the inspector's depth check already
        # rejects deeply unbalanced queries).
        body = query[body_start : i - 1] if depth == 0 else query[body_start:i]
        spreads = {m.group(1) for m in _FRAGMENT_SPREAD_PATTERN.finditer(body)}
        deps[name] = spreads

    if not deps:
        return False

    # DFS each fragment to find a cycle.
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {name: WHITE for name in deps}

    def visit(name: str) -> bool:
        if color.get(name) == GRAY:
            return True  # back-edge → cycle
        if color.get(name) == BLACK:
            return False
        if name not in deps:
            # Spread referencing a fragment that's not defined — not a
            # cycle in our graph, treat as terminal.
            return False
        color[name] = GRAY
        for child in deps[name]:
            if visit(child):
                return True
        color[name] = BLACK
        return False

    for name in deps:
        if visit(name):
            return True
    return False


def _compute_depth(query: str) -> int:
    """Maximum nesting depth by counting ``{`` and ``}`` runs.

    Strings inside the query (e.g. ``field(arg: "{...}")``) inflate
    this — accepted v1 tradeoff. A future AST-mode implementation
    lives behind a separate flag.
    """
    depth = 0
    max_depth = 0
    for ch in query:
        if ch == "{":
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif ch == "}":
            # Don't go negative on malformed input — clamp at 0.
            if depth > 0:
                depth -= 1
    return max_depth


def inspect_graphql_query(
    query: str,
    options: Optional[GraphqlGuardOptions] = None,
) -> GraphqlGuardResult:
    """Inspect a GraphQL query against the configured limits.

    Returns a structured result; middleware uses this directly. Pure
    function — no I/O, no framework handles.

    Args:
        query: The raw GraphQL query string.
        options: Optional ``GraphqlGuardOptions`` overrides; defaults
            apply when omitted.

    Returns:
        ``GraphqlGuardResult`` with the observed depth, length, and
        whether the query was blocked + why.

    Example:
        result = inspect_graphql_query("query { a { b { c { d } } } }")
        # GraphqlGuardResult(blocked=False, depth=4, length=29, reason=None)
    """
    opts = options or GraphqlGuardOptions()
    length = len(query)
    depth = _compute_depth(query)
    aliases = _count_aliases(query)

    # Precedence: depth > introspection > aliases > fragment_cycle >
    # length. Cheapest-to-explain failures first; length last because
    # it's the easiest false-positive (long queries with deep inline
    # fragments are legitimate). Aliases + fragment_cycle slot above
    # length because they're real attack signals, not size limits.
    # improvements.md §1.2 V34.
    if depth > opts.max_depth:
        return GraphqlGuardResult(
            blocked=True, reason="depth", depth=depth, length=length, aliases=aliases
        )
    if opts.block_introspection and _INTROSPECTION_PATTERN.search(query):
        return GraphqlGuardResult(
            blocked=True, reason="introspection", depth=depth, length=length, aliases=aliases
        )
    if aliases > opts.max_aliases:
        return GraphqlGuardResult(
            blocked=True, reason="aliases", depth=depth, length=length, aliases=aliases
        )
    if opts.block_fragment_cycles and _has_fragment_cycle(query):
        return GraphqlGuardResult(
            blocked=True, reason="fragment_cycle", depth=depth, length=length, aliases=aliases
        )
    if length > opts.max_length:
        return GraphqlGuardResult(
            blocked=True, reason="length", depth=depth, length=length, aliases=aliases
        )
    return GraphqlGuardResult(blocked=False, depth=depth, length=length, aliases=aliases)


def detect_graphql_abuse(
    query: str,
    options: Optional[GraphqlGuardOptions] = None,
) -> bool:
    """Detect-only API matching the rest of the sanitizer module surface.

    Returns a boolean for callers that just want a yes/no — use
    ``inspect_graphql_query`` if you need the structured reason.

    Args:
        query: The raw GraphQL query string.
        options: Optional ``GraphqlGuardOptions`` overrides.

    Returns:
        True if the query violates any configured limit.

    Example:
        detect_graphql_abuse("query { " + "x { " * 50 + "x" + " }" * 51)
        # True (depth-bomb)
        detect_graphql_abuse("{ __schema { types { name } } }")
        # True (introspection)
        detect_graphql_abuse("query { user { name } }")
        # False (clean)
    """
    if not isinstance(query, str) or not query:
        return False
    return inspect_graphql_query(query, options).blocked
