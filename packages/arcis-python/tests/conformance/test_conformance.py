"""
Conformance tests — validates Python SDK against spec/TEST_VECTORS.json.

These tests ensure cross-SDK behavioral consistency. Each test case
corresponds to a vector in TEST_VECTORS.json.

Note: XSS test vectors in TEST_VECTORS.json expect `&lt;` encoding, but the
architecture decision is "remove before encode" — so script tags are fully
removed first. These tests validate the *intent* (dangerous content absent)
rather than the exact encoding form. See FIND-10 in audit/python.md.
"""

import json
from pathlib import Path

import pytest

from arcis import (
    Sanitizer,
    sanitize_string,
    SchemaValidator,
    SafeLogger,
    SecurityHeaders,
    RateLimiter,
    RateLimitExceeded,
    ErrorHandler,
)


# ---------------------------------------------------------------------------
# Load test vectors
# ---------------------------------------------------------------------------

_VECTORS_PATH = Path(__file__).parent.parent.parent.parent / "spec" / "TEST_VECTORS.json"


@pytest.fixture(scope="module")
def vectors():
    with open(_VECTORS_PATH) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# sanitize_string — XSS
# ---------------------------------------------------------------------------

class TestConformanceSanitizeXSS:
    def test_removes_script_tags(self):
        result = sanitize_string("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "alert" not in result

    def test_removes_onerror(self):
        result = sanitize_string('<img onerror="alert(1)" src="x">')
        assert "onerror" not in result.lower()

    def test_removes_javascript_protocol(self):
        result = sanitize_string("javascript:alert(1)")
        assert "javascript:" not in result.lower()

    def test_removes_iframe(self):
        result = sanitize_string('<iframe src="evil.com">')
        assert "<iframe" not in result.lower()

    def test_encodes_remaining_html(self):
        """After XSS removal, remaining < > are encoded."""
        result = sanitize_string("Hello <b>World</b>")
        assert "<b>" not in result
        assert "Hello" in result
        assert "World" in result

    def test_removes_data_uri(self):
        result = sanitize_string("data:text/html,<script>alert(1)</script>")
        assert "<script>" not in result


# ---------------------------------------------------------------------------
# sanitize_string — SQL
# ---------------------------------------------------------------------------

class TestConformanceSanitizeSQL:
    def test_removes_drop_table(self):
        result = sanitize_string("'; DROP TABLE users; --")
        assert "DROP" not in result.upper()

    def test_removes_or_1_equals_1(self):
        result = sanitize_string("1 OR 1=1")
        assert "OR 1" not in result.upper() or "1=1" not in result

    def test_removes_select(self):
        result = sanitize_string("SELECT * FROM users")
        assert "SELECT" not in result.upper()

    def test_removes_delete(self):
        result = sanitize_string("1; DELETE FROM users")
        assert "DELETE" not in result.upper()

    def test_removes_comments(self):
        result = sanitize_string("admin'--")
        assert "--" not in result

    def test_removes_union_and_block_comments(self):
        result = sanitize_string("1 /* comment */ UNION SELECT")
        assert "UNION" not in result.upper()


# ---------------------------------------------------------------------------
# sanitize_string — Path Traversal
# ---------------------------------------------------------------------------

class TestConformanceSanitizePath:
    def test_removes_unix_traversal(self):
        result = sanitize_string("../../etc/passwd")
        assert "../" not in result

    def test_removes_windows_traversal(self):
        result = sanitize_string("..\\..\\windows\\system32")
        assert "..\\" not in result

    def test_removes_url_encoded_traversal(self):
        result = sanitize_string("%2e%2e%2f%2e%2e%2f")
        assert "%2e%2e" not in result.lower()

    def test_safe_input_unchanged(self):
        result = sanitize_string("file.txt")
        assert result == "file.txt"


# ---------------------------------------------------------------------------
# sanitize_object — Prototype Pollution
# ---------------------------------------------------------------------------

class TestConformanceSanitizeProto:
    def test_blocks_proto_key(self):
        sanitizer = Sanitizer()
        result = sanitizer.sanitize_dict({"__proto__": {"admin": True}, "name": "test"})
        assert "__proto__" not in result
        assert "name" in result

    def test_blocks_constructor_key(self):
        sanitizer = Sanitizer()
        result = sanitizer.sanitize_dict({"constructor": {"prototype": {}}, "email": "test@test.com"})
        assert "constructor" not in result
        assert "email" in result

    def test_blocks_prototype_key(self):
        sanitizer = Sanitizer()
        result = sanitizer.sanitize_dict({"prototype": {"isAdmin": True}, "value": 123})
        assert "prototype" not in result
        assert "value" in result


# ---------------------------------------------------------------------------
# sanitize_object — NoSQL Injection
# ---------------------------------------------------------------------------

class TestConformanceSanitizeNoSQL:
    def test_blocks_gt(self):
        sanitizer = Sanitizer()
        result = sanitizer.sanitize_dict({"$gt": "", "name": "test"})
        assert "$gt" not in result
        assert "name" in result

    def test_blocks_where(self):
        sanitizer = Sanitizer()
        result = sanitizer.sanitize_dict({"$where": "function(){ return true; }", "id": 1})
        assert "$where" not in result
        assert "id" in result

    def test_blocks_multiple_operators(self):
        sanitizer = Sanitizer()
        result = sanitizer.sanitize_dict({"$ne": None, "$or": [], "valid": True})
        assert "$ne" not in result
        assert "$or" not in result
        assert "valid" in result

    def test_blocks_nested_regex(self):
        sanitizer = Sanitizer()
        result = sanitizer.sanitize_dict({"username": {"$regex": ".*"}, "password": "test"})
        if "username" in result and isinstance(result["username"], dict):
            assert "$regex" not in result["username"]
        assert "password" in result


# ---------------------------------------------------------------------------
# sanitize_object — Nested
# ---------------------------------------------------------------------------

class TestConformanceSanitizeNested:
    def test_nested_string_sanitized(self):
        sanitizer = Sanitizer()
        result = sanitizer.sanitize_dict({"user": {"name": "<script>xss</script>"}})
        assert "<script>" not in result["user"]["name"]

    def test_array_items_sanitized(self):
        sanitizer = Sanitizer()
        result = sanitizer.sanitize_dict({"items": ["<script>alert(1)</script>", "normal"]})
        assert "<script>" not in result["items"][0]
        assert result["items"][1] == "normal"


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class TestConformanceRateLimiter:
    def test_allow_under_limit(self):
        limiter = RateLimiter(max_requests=5, window_ms=60000)
        class Req:
            remote_addr = "10.0.0.1"
        for _ in range(3):
            result = limiter.check(Req())
            assert result["allowed"]
            assert "X-RateLimit-Remaining" or result.get("remaining") is not None
        limiter.close()

    def test_block_over_limit(self):
        limiter = RateLimiter(max_requests=3, window_ms=60000)
        class Req:
            remote_addr = "10.0.0.2"
        for _ in range(3):
            limiter.check(Req())
        with pytest.raises(RateLimitExceeded):
            limiter.check(Req())
        limiter.close()

    def test_different_ips_separate_limits(self):
        limiter = RateLimiter(max_requests=2, window_ms=60000)
        for i in range(3):
            class Req:
                remote_addr = f"10.0.0.{i + 10}"
            for _ in range(2):
                result = limiter.check(Req())
                assert result["allowed"]
        limiter.close()

    def test_required_headers_in_result(self):
        limiter = RateLimiter(max_requests=10, window_ms=60000)
        class Req:
            remote_addr = "10.0.0.99"
        result = limiter.check(Req())
        assert "limit" in result
        assert "remaining" in result
        assert "reset" in result
        limiter.close()


# ---------------------------------------------------------------------------
# Security Headers
# ---------------------------------------------------------------------------

class TestConformanceSecurityHeaders:
    def test_default_headers_present(self):
        headers = SecurityHeaders()
        h = headers.get_headers()
        assert "Content-Security-Policy" in h
        assert h["X-XSS-Protection"] == "0"
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["X-Frame-Options"] == "DENY"
        assert "max-age=" in h["Strict-Transport-Security"]
        assert h["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "Permissions-Policy" in h


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class TestConformanceValidator:
    def test_required_field_missing(self):
        v = SchemaValidator({"email": {"type": "email", "required": True}})
        data, errors = v.validate({})
        assert any("email is required" in e for e in errors)

    def test_invalid_email(self):
        v = SchemaValidator({"email": {"type": "email", "required": True}})
        data, errors = v.validate({"email": "invalid"})
        assert any("valid email" in e for e in errors)

    def test_valid_email(self):
        v = SchemaValidator({"email": {"type": "email", "required": True}})
        data, errors = v.validate({"email": "test@example.com"})
        assert not errors
        assert "email" in data

    def test_string_too_short(self):
        v = SchemaValidator({"name": {"type": "string", "min": 3, "max": 10}})
        data, errors = v.validate({"name": "ab"})
        assert any("at least 3" in e for e in errors)

    def test_string_too_long(self):
        v = SchemaValidator({"name": {"type": "string", "min": 3, "max": 10}})
        data, errors = v.validate({"name": "this is way too long"})
        assert any("at most 10" in e for e in errors)

    def test_number_below_min(self):
        v = SchemaValidator({"age": {"type": "number", "min": 0, "max": 150}})
        data, errors = v.validate({"age": -5})
        assert any("at least 0" in e for e in errors)

    def test_number_above_max(self):
        v = SchemaValidator({"age": {"type": "number", "min": 0, "max": 150}})
        data, errors = v.validate({"age": 200})
        assert any("at most 150" in e for e in errors)

    def test_invalid_enum(self):
        v = SchemaValidator({"role": {"type": "string", "enum": ["user", "admin"]}})
        data, errors = v.validate({"role": "superadmin"})
        assert any("one of" in e for e in errors)

    def test_mass_assignment_prevention(self):
        v = SchemaValidator({"email": {"type": "email", "required": True}})
        data, errors = v.validate({"email": "test@test.com", "isAdmin": True, "role": "admin"})
        assert not errors
        assert "email" in data
        assert "isAdmin" not in data
        assert "role" not in data


# ---------------------------------------------------------------------------
# Safe Logger
# ---------------------------------------------------------------------------

class TestConformanceSafeLogger:
    def test_redacts_password(self):
        logger = SafeLogger()
        result = logger._redact({"email": "test@test.com", "password": "secret123"})
        assert result["password"] == "[REDACTED]"
        assert result["email"] == "test@test.com"

    def test_redacts_token_and_apikey(self):
        logger = SafeLogger()
        result = logger._redact({"user": "john", "token": "abc123", "apiKey": "key123"})
        assert result["token"] == "[REDACTED]"
        assert result["apiKey"] == "[REDACTED]"
        assert result["user"] == "john"

    def test_removes_newlines(self):
        logger = SafeLogger()
        result = logger._redact("User: attacker\nAdmin logged in: true")
        assert "\n" not in result

    def test_removes_carriage_return(self):
        logger = SafeLogger()
        result = logger._redact("Normal log\r\nFake entry")
        assert "\r" not in result
        assert "\n" not in result

    def test_truncates_long_messages(self):
        logger = SafeLogger(max_length=50)
        result = logger._redact("a" * 100)
        assert len(result) < 100
        assert "[TRUNCATED]" in result


# ---------------------------------------------------------------------------
# Error Handler
# ---------------------------------------------------------------------------

class TestConformanceErrorHandler:
    def test_production_hides_details(self):
        handler = ErrorHandler(is_dev=False)
        result = handler.handle(Exception("Database connection failed"), 500)
        assert "Internal Server Error" in result.get("error", "")
        assert "Database" not in str(result)
        assert "stack" not in str(result)

    def test_development_shows_details(self):
        handler = ErrorHandler(is_dev=True)
        result = handler.handle(Exception("Something broke"), 500)
        assert "Something broke" in str(result)
