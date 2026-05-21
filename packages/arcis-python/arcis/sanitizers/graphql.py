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
    """

    max_depth: int = 10
    max_length: int = 10000
    block_introspection: bool = True


@dataclass(frozen=True)
class GraphqlGuardResult:
    """Outcome of inspecting a GraphQL query.

    Attributes:
        blocked: True if the query violated any configured limit.
        reason: Which limit fired first (depth → introspection →
            length precedence). None when blocked is False.
        depth: Observed nesting depth. Always returned, even on clean
            queries.
        length: Observed length. Always returned.
    """

    blocked: bool
    depth: int
    length: int
    reason: Optional[str] = None


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

    # Precedence: depth > introspection > length. Depth is the most
    # expensive to surface (caller wants the actual number);
    # introspection is the most security-critical signal so beats
    # length; length last because it's the easiest false-positive
    # (long queries with deep inline fragments are legitimate).
    if depth > opts.max_depth:
        return GraphqlGuardResult(
            blocked=True, reason="depth", depth=depth, length=length
        )
    if opts.block_introspection and _INTROSPECTION_PATTERN.search(query):
        return GraphqlGuardResult(
            blocked=True, reason="introspection", depth=depth, length=length
        )
    if length > opts.max_length:
        return GraphqlGuardResult(
            blocked=True, reason="length", depth=depth, length=length
        )
    return GraphqlGuardResult(blocked=False, depth=depth, length=length)


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
