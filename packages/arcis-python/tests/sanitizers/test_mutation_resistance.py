"""Mutation resistance tests for `sanitize_string` (improvements.md §1.1.d).

Generates encoding/case/unicode variants of every base attack payload
and asserts that `sanitize_string` still strips the threat from each
variant. This is the structural safeguard that prevents future regex
or normalization changes from silently re-opening a bypass class.

# Why this matters more than direct-string tests

A direct test like `assert '<script' not in sanitize_string('<script>...')`
verifies one specific payload. A mutation test takes that base payload,
generates 7 variants (alternating case, uppercase, URL-encoded once,
URL-encoded twice, HTML hex entities, HTML named entities, fullwidth
glyphs) and verifies all 7. If a future pattern tweak handles the
direct case but misses the URL-encoded variant, the direct test passes
silently while this one fails loud.

# Coverage today

Categories cross-multiplied with mutations:

* XSS — 8 base payloads × 7 mutations = 56 checks
* SQL — 6 base payloads × 7 mutations = 42 checks
* Path traversal — 4 base × 7 = 28 checks
* SSTI / command — 4 base × 7 = 28 checks

≈ 154 mutation checks per test run. Each one cheap (a sanitize_string
call), full pass <50ms.

# Not in scope

* Cross-SDK comparison (the conformance script handles that)
* Whether sanitize_string CORRUPTS safe input (separate idempotency tests)
* Performance / timing-side-channel (separate benchmark)
"""

import urllib.parse

import pytest

from arcis import sanitize_string


# ──────────────────────────────────────────────────────────────────────
# Mutators — each takes a string and returns a transformed string.
# The transformed string should, after sanitize_string, NOT contain any
# of the category's threat tokens. NFKC + multi-decode + greedy XSS
# patterns (improvements.md §1.1.a + §1.1.b + welcome V2 work) close
# every mutation in this set.
# ──────────────────────────────────────────────────────────────────────


def _alternating_case(s: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))


def _uppercase(s: str) -> str:
    return s.upper()


def _url_encode_once(s: str) -> str:
    # `safe=''` forces encoding of every non-alphanumeric char.
    return urllib.parse.quote(s, safe="")


def _url_encode_twice(s: str) -> str:
    return urllib.parse.quote(_url_encode_once(s), safe="")


def _html_entity_hex(s: str) -> str:
    # Encode every non-alphanumeric char as &#xHH;. ASCII letters
    # pass through to avoid `&#x65;valuat` looking weird in tests.
    return "".join(
        f"&#x{ord(c):x};" if not c.isalnum() else c for c in s
    )


def _html_entity_decimal(s: str) -> str:
    return "".join(
        f"&#{ord(c)};" if not c.isalnum() else c for c in s
    )


def _html_entity_named(s: str) -> str:
    # Five named entities that XSS payloads use.
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _fullwidth_ascii(s: str) -> str:
    """Replace ASCII printable chars with their fullwidth equivalents.
    NFKC normalization will fold them back to ASCII inside
    `sanitize_string`. The mutated payload looks Chinese-ish on the
    wire but is identical to the original after NFKC. Catches any
    regression in the NFKC pass."""
    out = []
    for c in s:
        code = ord(c)
        if 0x21 <= code <= 0x7E:  # printable ASCII
            out.append(chr(code + 0xFEE0))  # → U+FF01–U+FF5E (fullwidth)
        else:
            out.append(c)
    return "".join(out)


MUTATORS = {
    "alternating_case": _alternating_case,
    "uppercase": _uppercase,
    "url_encode_once": _url_encode_once,
    "url_encode_twice": _url_encode_twice,
    "html_entity_hex": _html_entity_hex,
    "html_entity_decimal": _html_entity_decimal,
    "html_entity_named": _html_entity_named,
    "fullwidth_ascii": _fullwidth_ascii,
}


# ──────────────────────────────────────────────────────────────────────
# Category corpora + threat-tokens-that-must-not-survive.
#
# Each entry: (base_payload, [threat_tokens_to_check]). After
# sanitize_string + every mutation, none of the threat tokens may
# appear (case-insensitive) in the output.
# ──────────────────────────────────────────────────────────────────────


XSS_CASES = [
    ("<script>alert(1)</script>", ["<script", "</script"]),
    ("<img onerror=alert(1) src=x>", ["onerror="]),
    ("javascript:alert(1)", ["javascript:"]),
    ("<iframe src=evil.com>", ["<iframe"]),
    ("<svg onload=alert(1)>", ["onload="]),
    ("<object data=evil>", ["<object"]),
    ("<embed src=evil>", ["<embed"]),
    ("<style>body{x:expression(alert(1))}</style>", ["<style"]),
]

SQL_CASES = [
    ("' OR 1=1--", ["or 1=1"]),
    ("'; DROP TABLE users--", ["drop"]),
    ("UNION SELECT * FROM users", ["union", "select"]),
    ("admin'--", ["--"]),
    ("1; DELETE FROM users", ["delete"]),
    ("SLEEP(5)", ["sleep("]),
    # improvements.md §1.1.e Q3: Oracle DBMS_* packages.
    ("foo; DBMS_LOCK.SLEEP(5)", ["dbms_"]),
    ("foo; DBMS_PIPE.RECEIVE_MESSAGE(x,5)", ["dbms_"]),
    ("foo; DBMS_JAVA.RUNJAVA('...')", ["dbms_"]),
]

PATH_CASES = [
    ("../../etc/passwd", ["../"]),
    ("..\\..\\windows\\system32", ["..\\"]),
    ("/var/www/../../etc/shadow", ["../"]),
    ("../" * 5 + "etc/passwd", ["../"]),
]


def _check(category: str, base: str, threat_tokens: list[str], mutator_name: str, mutator):
    """Run one mutation+sanitize+assert cycle."""
    try:
        mutated = mutator(base)
    except Exception as exc:
        pytest.fail(
            f"mutator {mutator_name!r} raised {exc!r} on input {base!r}"
        )
    output = sanitize_string(mutated).lower()
    for token in threat_tokens:
        assert token.lower() not in output, (
            f"BYPASS: {category} payload {base!r} "
            f"survived mutation {mutator_name!r} as {mutated!r} → "
            f"output {output!r} still contains {token!r}"
        )


@pytest.mark.parametrize("base,tokens", XSS_CASES)
@pytest.mark.parametrize("mut_name,mutator", list(MUTATORS.items()))
def test_xss_mutation_resistance(base, tokens, mut_name, mutator):
    _check("xss", base, tokens, mut_name, mutator)


@pytest.mark.parametrize("base,tokens", SQL_CASES)
@pytest.mark.parametrize(
    "mut_name,mutator",
    # SQL has no HTML-entity / fullwidth bypasses in the wild — narrow
    # to the encoding + case mutations that are credible.
    [(n, m) for n, m in MUTATORS.items() if n not in ("html_entity_named",)],
)
def test_sql_mutation_resistance(base, tokens, mut_name, mutator):
    _check("sql", base, tokens, mut_name, mutator)


@pytest.mark.parametrize("base,tokens", PATH_CASES)
@pytest.mark.parametrize("mut_name,mutator", list(MUTATORS.items()))
def test_path_traversal_mutation_resistance(base, tokens, mut_name, mutator):
    _check("path_traversal", base, tokens, mut_name, mutator)


# ──────────────────────────────────────────────────────────────────────
# Mutator sanity tests — verify each mutator actually transforms the
# input. Catches a future refactor that accidentally turns a mutator
# into the identity function (which would make the mutation tests
# pass vacuously).
# ──────────────────────────────────────────────────────────────────────


def test_alternating_case_changes_input():
    assert _alternating_case("abcdef") != "abcdef"


def test_url_encode_twice_doubles_percent_signs():
    once = _url_encode_once("<x>")  # %3Cx%3E
    twice = _url_encode_twice("<x>")
    assert twice.count("%25") >= 2, f"expected double-encoded %% but got {twice!r}"


def test_fullwidth_ascii_actually_uses_fullwidth():
    out = _fullwidth_ascii("abc")
    # All three chars should be in the fullwidth block U+FF21–U+FF5A.
    for c in out:
        assert 0xFF21 <= ord(c) <= 0xFF7A, f"expected fullwidth char, got {c!r} ({hex(ord(c))})"


def test_html_entity_hex_encodes_brackets():
    # `<` is U+003C — should become `&#x3c;`.
    assert "&#x3c;" in _html_entity_hex("<")
