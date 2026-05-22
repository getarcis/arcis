"""V34 — GraphQL alias bomb + fragment cycle (improvements.md §1.2).

Extends the existing GraphQL inspector with two new attack-class
guards: alias count cap (catches alias-bomb amplification) and
fragment-spread cycle detection (catches infinite-loop fragments).

Existing depth + introspection + length checks are unchanged — these
tests pin the NEW behavior.
"""
import pytest

from arcis.sanitizers.graphql import (
    GraphqlGuardOptions,
    inspect_graphql_query,
)


# ── alias bomb (improvements.md §1.2 V34) ─────────────────────────────


def test_alias_count_returned_for_clean_query():
    # Sanity: clean query reports the actual alias count without
    # blocking.
    q = "query { u1: user(id: 1) { name } u2: user(id: 2) { name } }"
    result = inspect_graphql_query(q)
    assert result.blocked is False
    assert result.aliases >= 2


def test_alias_bomb_under_threshold_passes():
    # 30 aliases — below the default 50 cap.
    parts = [f"u{i}: user(id: {i}) {{ name }}" for i in range(30)]
    q = "query { " + " ".join(parts) + " }"
    result = inspect_graphql_query(q)
    assert result.blocked is False
    assert 25 <= result.aliases <= 35


def test_alias_bomb_over_threshold_blocked():
    # 75 aliases — over the default 50 cap.
    parts = [f"u{i}: user(id: {i}) {{ name }}" for i in range(75)]
    q = "query { " + " ".join(parts) + " }"
    result = inspect_graphql_query(q)
    assert result.blocked is True
    assert result.reason == "aliases"
    assert result.aliases > 50


def test_alias_cap_can_be_relaxed():
    # Caller can raise the cap for backends that genuinely allow large
    # alias counts.
    parts = [f"u{i}: user(id: {i}) {{ name }}" for i in range(75)]
    q = "query { " + " ".join(parts) + " }"
    opts = GraphqlGuardOptions(max_aliases=200)
    result = inspect_graphql_query(q, opts)
    assert result.blocked is False


# ── fragment cycle (improvements.md §1.2 V34) ─────────────────────────


def test_direct_self_referential_fragment_blocked():
    q = "fragment A on User { ...A name } query { me { ...A } }"
    result = inspect_graphql_query(q)
    assert result.blocked is True
    assert result.reason == "fragment_cycle"


def test_indirect_fragment_cycle_blocked():
    # A → B → A. Indirect cycle through two fragments.
    q = (
        "fragment A on User { ...B } "
        "fragment B on User { ...A } "
        "query { me { ...A } }"
    )
    result = inspect_graphql_query(q)
    assert result.blocked is True
    assert result.reason == "fragment_cycle"


def test_acyclic_fragments_pass():
    # A → B → terminal. No cycle.
    q = (
        "fragment A on User { ...B name } "
        "fragment B on User { email } "
        "query { me { ...A } }"
    )
    result = inspect_graphql_query(q)
    assert result.blocked is False


def test_fragment_cycle_check_can_be_disabled():
    q = "fragment A on User { ...A name } query { me { ...A } }"
    opts = GraphqlGuardOptions(block_fragment_cycles=False)
    result = inspect_graphql_query(q, opts)
    # Still passes through other guards — should not be blocked just
    # for the cycle when the check is off.
    assert result.blocked is False or result.reason != "fragment_cycle"


def test_query_with_no_fragments_is_not_a_cycle():
    q = "query { user(id: 1) { name email } }"
    result = inspect_graphql_query(q)
    assert result.blocked is False


# ── precedence (improvements.md §1.2 V34) ─────────────────────────────


def test_depth_beats_aliases_in_precedence():
    # Deeply-nested query with also many aliases — depth fires first.
    deep = "{ " + "a: x { " * 15 + "}" * 15
    result = inspect_graphql_query(deep)
    assert result.blocked is True
    assert result.reason == "depth"


def test_aliases_beat_length():
    # Short alias-bomb that's well under the length cap.
    parts = [f"u{i}: x" for i in range(100)]
    q = "{ " + " ".join(parts) + " }"
    assert len(q) < 10000
    result = inspect_graphql_query(q)
    assert result.blocked is True
    assert result.reason == "aliases"
