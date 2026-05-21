"""
GraphQL inspector tests — mirrors arcis-node/__tests__/graphql.test.ts.

The contract: detect depth-bombs, introspection abuse, and over-long
queries against configurable thresholds. Precedence depth → introspection
→ length so the most security-critical signal wins when multiple fire.
"""

import pytest

from arcis.sanitizers.graphql import (
    GraphqlGuardOptions,
    detect_graphql_abuse,
    inspect_graphql_query,
)


# ── Clean queries pass through ─────────────────────────────────────────

class TestCleanQueries:
    """Legitimate GraphQL queries must not trip any limit at default
    config. Anything that's caught here is a false positive."""

    @pytest.mark.parametrize("query", [
        "query { user { name } }",
        "query GetUser($id: ID!) { user(id: $id) { name email } }",
        "{ posts(first: 10) { edges { node { title author { name } } } } }",
        "mutation { createUser(input: {name: \"jane\"}) { id name } }",
        "{ user { __typename name } }",  # __typename is the one allowed introspection field
    ])
    def test_legitimate_query_passes(self, query):
        result = inspect_graphql_query(query)
        assert result.blocked is False
        assert result.reason is None

    def test_detect_returns_false_for_clean(self):
        assert detect_graphql_abuse("query { user { name } }") is False

    def test_empty_string_returns_false(self):
        assert detect_graphql_abuse("") is False

    def test_non_string_returns_false(self):
        assert detect_graphql_abuse(None) is False  # type: ignore[arg-type]
        assert detect_graphql_abuse(123) is False  # type: ignore[arg-type]


# ── Depth-bomb detection ───────────────────────────────────────────────

class TestDepthBomb:
    """Nested-query depth-bomb is the headline v1 protection."""

    def test_default_threshold_is_10(self):
        opts = GraphqlGuardOptions()
        assert opts.max_depth == 10

    def test_query_at_depth_8_passes(self):
        # query { a { b { c { d { e { f { g { h } } } } } } } } — 8 deep
        q = "query { a { b { c { d { e { f { g { h } } } } } } } }"
        r = inspect_graphql_query(q)
        assert r.blocked is False
        assert r.depth == 8

    def test_query_at_depth_11_blocked(self):
        # 11 levels of nesting — exceeds default of 10.
        q = "query { " + "x { " * 11 + "x" + " }" * 12
        r = inspect_graphql_query(q)
        assert r.blocked is True
        assert r.reason == "depth"
        assert r.depth == 12

    def test_depth_overrides_max(self):
        # Custom max_depth=3, query at depth 4
        opts = GraphqlGuardOptions(max_depth=3)
        q = "query { a { b { c { d } } } }"
        r = inspect_graphql_query(q, opts)
        assert r.blocked is True
        assert r.reason == "depth"

    def test_unbalanced_braces_clamps_depth(self):
        # Don't go negative on malformed input
        r = inspect_graphql_query("} } } }")
        assert r.depth == 0  # clamped


# ── Introspection abuse ────────────────────────────────────────────────

class TestIntrospection:
    """Block __schema / __type / __typeKind / __directive by default.
    __typename is intentionally NOT blocked because Apollo client uses
    it on every legit query.
    """

    @pytest.mark.parametrize("query", [
        "{ __schema { types { name } } }",
        "{ __type(name: \"User\") { fields { name } } }",
        "{ __typeKind }",
        "{ __directive }",
        "query Q { __schema { queryType { name } } }",
    ])
    def test_introspection_query_blocked(self, query):
        r = inspect_graphql_query(query)
        assert r.blocked is True
        assert r.reason == "introspection"

    def test_typename_alone_not_blocked(self):
        # Apollo client embeds __typename in EVERY query. Catching it
        # would break every Apollo-using app on the first request.
        r = inspect_graphql_query("{ user { __typename name } }")
        assert r.blocked is False

    def test_introspection_can_be_disabled(self):
        # Development environments may want introspection for GraphiQL.
        opts = GraphqlGuardOptions(block_introspection=False)
        r = inspect_graphql_query("{ __schema { types { name } } }", opts)
        assert r.blocked is False

    def test_user_field_with_double_underscore_passes(self):
        # The \b__ anchor avoids false-matches on user-defined fields
        # like last__updated_at, double__column, etc.
        r = inspect_graphql_query("{ user { last__updated_at } }")
        assert r.blocked is False


# ── Length limit ───────────────────────────────────────────────────────

class TestLengthLimit:
    """Queries past the length ceiling are blocked (memory / DoS guard)."""

    def test_default_threshold_is_10000(self):
        opts = GraphqlGuardOptions()
        assert opts.max_length == 10000

    def test_overlong_query_blocked(self):
        opts = GraphqlGuardOptions(max_length=100)
        long_query = "query { user { name " + "x " * 50 + "} }"
        r = inspect_graphql_query(long_query, opts)
        assert r.blocked is True
        assert r.reason == "length"

    def test_clean_short_query_passes(self):
        opts = GraphqlGuardOptions(max_length=100)
        r = inspect_graphql_query("query { user { name } }", opts)
        assert r.blocked is False


# ── Precedence: depth > introspection > length ─────────────────────────

class TestPrecedence:
    """When multiple limits would fire on the same query, the most
    security-critical signal wins so the caller can act on the right
    reason."""

    def test_depth_beats_introspection(self):
        # Both depth-bomb (15 levels) AND introspection.
        q = "query { __schema { " + "x { " * 14 + "x" + " }" * 15 + " } }"
        r = inspect_graphql_query(q)
        assert r.blocked is True
        assert r.reason == "depth"

    def test_introspection_beats_length(self):
        # Long query that also contains __schema. Set max_length tight.
        opts = GraphqlGuardOptions(max_length=50)
        q = "query { __schema { queryType { name } } }" + " " * 100
        r = inspect_graphql_query(q, opts)
        assert r.blocked is True
        assert r.reason == "introspection"


# ── Match Node depth-counting semantics ─────────────────────────────────

class TestDepthSemantics:
    """The depth computation deliberately counts every ``{`` even inside
    string literals. This is documented in the Node sanitizer as an
    accepted v1 tradeoff (avoids dragging in a GraphQL parser dep)."""

    def test_string_literal_brace_inflates_depth(self):
        # The string "{...}" inside an argument counts as nesting.
        # This is a known v1 over-count.
        q = 'query { field(arg: "value with { brace") { id } }'
        r = inspect_graphql_query(q)
        # Depth here is 2 from the outer braces + 1 from the string-literal
        # brace that we don't escape-handle. Documented tradeoff.
        assert r.depth >= 2

    def test_balanced_braces_at_default_limit_pass(self):
        # Right at the limit — depth 10 with max_depth 10 should pass
        # (the test is `> max_depth`, not `>= max_depth`).
        q = "query { " + "x { " * 9 + "x" + " }" * 10
        r = inspect_graphql_query(q)
        assert r.depth == 10
        assert r.blocked is False
