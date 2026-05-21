"""
Request-boundary scanner coverage for v1.5 Tier-1 vectors.

These tests pin the parity behavior that Raghav's Responza FastAPI pilot
2026-05-20 caught the absence of: LDAP, XPath, and email-header attacks
should be detected and classified at the request boundary, not pass
through as `decision=allow, vector=null`.

Out of scope here:
- GraphQL depth-bomb / introspection (covered in test_graphql.py — uses
  its own contract because it returns a structured result, not a
  single boolean from scan_threats).
- Mass-assignment / method-allowlist / response-splitting (covered in
  middleware tests since those vectors aren't string-pattern detectors).
"""

import pytest

from arcis.sanitizers.ldap import (
    detect_ldap_injection,
    detect_ldap_injection_strict,
)
from arcis.sanitizers.sanitize import scan_threats
from arcis.sanitizers.xpath import (
    detect_xpath_injection,
    sanitize_xpath,
)


# ── LDAP request-boundary detection ────────────────────────────────────

class TestLdapStrict:
    """detect_ldap_injection_strict() and its scan_threats wire-up.

    The original detect_ldap_injection() uses a broad pattern that
    false-positives on any parenthesised string. The strict variant
    uses only the attack-specific ')(' shape, safe for request-boundary
    scanning.
    """

    @pytest.mark.parametrize("payload", [
        "*)(uid=*))(|(uid=*",
        "admin)(uid=*",
        "*)(&(uid=admin)",
        ")(cn=*",
        "*) (cn=admin",
    ])
    def test_ldap_attack_patterns_detected_strict(self, payload):
        assert detect_ldap_injection_strict(payload) is True

    @pytest.mark.parametrize("payload", [
        "john",
        "user@example.com",
        "call me (when you can)",
        "Acme (USA) Inc",
        "rule: a)b",
        "open-paren-(no-close",
    ])
    def test_legitimate_input_passes_strict(self, payload):
        assert detect_ldap_injection_strict(payload) is False

    def test_non_string_input_returns_false(self):
        assert detect_ldap_injection_strict(None) is False  # type: ignore[arg-type]
        assert detect_ldap_injection_strict(123) is False  # type: ignore[arg-type]
        assert detect_ldap_injection_strict({"a": 1}) is False  # type: ignore[arg-type]

    def test_loose_detect_remains_unchanged(self):
        # Backwards-compatibility: existing detect_ldap_injection() still
        # fires on broad LDAP filter chars. Callers using it at the LDAP
        # call site shouldn't have to change anything.
        assert detect_ldap_injection("user(test)") is True
        assert detect_ldap_injection("user*admin") is True


class TestLdapScanThreatsWire:
    """LDAP-strict is wired into scan_threats so the request-boundary
    scanner returns vector='ldap' instead of misclassifying as command.

    Raghav's Responza pilot 2026-05-20 fired the attack and got
    vector='command' (rule='command/match', severity HIGH) because the
    command-injection regex caught the '*' character before LDAP was
    evaluated. With LDAP-strict wired BEFORE command, that payload now
    classifies correctly.
    """

    def test_raghav_pilot_payload_classifies_as_ldap(self):
        # The literal payload Raghav fired against /api/login.
        result = scan_threats({"username": "*)(uid=*))(|(uid=*", "password": "any"})
        assert result is not None
        vector, rule, _ = result
        assert vector == "ldap"
        assert rule == "ldap/match"

    def test_other_ldap_shapes_classify_as_ldap(self):
        # Bare string at top level.
        r = scan_threats("admin)(uid=admin)")
        assert r is not None and r[0] == "ldap"
        # Nested in a list.
        r = scan_threats(["legit", "*)(cn=*"])
        assert r is not None and r[0] == "ldap"
        # Nested in a dict-of-dicts.
        r = scan_threats({"creds": {"u": ")(uid=admin"}})
        assert r is not None and r[0] == "ldap"

    def test_safe_paren_strings_do_not_trigger_ldap(self):
        # The whole reason ldap-strict exists: legitimate parenthesised
        # strings must pass clean. If this regresses, ldap-strict has
        # been broadened back to the false-positive pattern.
        for safe in [
            "Acme (USA) Inc",
            "rule: a)b",
            "call me (when you can)",
            "(this is fine)",
            "func(arg)",
        ]:
            r = scan_threats(safe)
            assert r is None or r[0] != "ldap", f"false positive: {safe!r} -> {r}"


# ── XPath request-boundary detection ──────────────────────────────────

class TestXpathSanitizer:
    """detect_xpath_injection() and sanitize_xpath() contract — mirrors
    Node arcis-node/src/sanitizers/xpath.ts byte-for-byte on detection.
    """

    @pytest.mark.parametrize("payload", [
        "' or '1'='1",
        '" or "1"="1',
        ") or (",
        "') or ('a'='a",
        '" or "1=1',
    ])
    def test_attack_patterns_detected(self, payload):
        assert detect_xpath_injection(payload) is True

    @pytest.mark.parametrize("payload", [
        "john",
        "john@example.com",
        "O'Brien",          # apostrophe alone — no boolean pattern
        "Title (subtitle)", # parens alone — no boolean
        "/path/to/node",
        "",
    ])
    def test_legitimate_input_passes(self, payload):
        assert detect_xpath_injection(payload) is False

    def test_non_string_input(self):
        assert detect_xpath_injection(None) is False  # type: ignore[arg-type]
        assert detect_xpath_injection(123) is False  # type: ignore[arg-type]

    def test_sanitize_strips_control_chars(self):
        # All quotes stripped, equals + spaces preserved.
        assert sanitize_xpath("' or '1'='1") == " or 1=1"
        assert sanitize_xpath("O'Brien") == "OBrien"
        assert sanitize_xpath('foo"bar|baz,qux') == "foobarbazqux"
        # Sanitize is idempotent (Pattern 8).
        clean = sanitize_xpath("' or '1'='1")
        assert sanitize_xpath(clean) == clean

    def test_sanitize_preserves_safe_input(self):
        for safe in ["john", "john@example.com", "/path", "no-special-chars"]:
            assert sanitize_xpath(safe) == safe


class TestXpathScanThreatsWire:
    """XPath-strict wires into scan_threats so a boolean-injection payload
    classifies as vector='xpath' rather than falling through.
    """

    def test_boolean_injection_classifies_as_xpath(self):
        r = scan_threats({"q": "' or '1'='1"})
        assert r is not None
        assert r[0] == "xpath"

    def test_function_arity_tampering_classifies_as_xpath(self):
        # ') or (' pattern is a known XPath function-tampering shape.
        r = scan_threats("admin') or ('a'='a")
        assert r is not None
        assert r[0] == "xpath"

    def test_apostrophe_alone_does_not_trigger(self):
        # XPath-strict requires the boolean PATTERN, not just a quote.
        r = scan_threats("O'Brien")
        # May still trigger another vector (unlikely for O'Brien), but
        # NOT xpath.
        assert r is None or r[0] != "xpath"


# ── Email-header (SMTP CRLF) request-boundary detection ────────────────

class TestEmailHeaderInjection:
    """The narrow email-header pattern wires into scan_threats. Catches
    payloads that combine CRLF with an SMTP header keyword, which is
    attack-specific enough to be safe at the request boundary (legit user
    input rarely contains '\\nBcc:' verbatim).
    """

    @pytest.mark.parametrize("payload", [
        "victim@example.com\r\nBcc: attacker@evil.com",
        "user\nCc: leak@evil.com",
        "support@example.com\r\nFrom: admin@example.com",
        "name\r\nReply-To: attacker@evil.com",
        "x\r\nContent-Type: text/html",
    ])
    def test_smtp_header_injection_detected(self, payload):
        r = scan_threats(payload)
        assert r is not None, f"missed: {payload!r}"
        assert r[0] == "email-header"

    @pytest.mark.parametrize("payload", [
        "victim@example.com",
        "multi-line\ntext content",       # newline, no SMTP keyword
        "first line\nsecond line",
        "From this point on",              # 'From' word, no CRLF prefix
        "Subject of conversation today",   # 'Subject' word, no CRLF prefix
    ])
    def test_safe_strings_do_not_trigger(self, payload):
        r = scan_threats(payload)
        assert r is None or r[0] != "email-header", \
            f"false positive: {payload!r} -> {r}"
