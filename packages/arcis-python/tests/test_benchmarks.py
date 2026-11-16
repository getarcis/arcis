"""
Arcis Performance Benchmarks
==============================

Benchmarks for core Arcis components using pytest-benchmark.
Mirrors the Go BenchmarkXxx tests in arcis/arcis_test.go.

Run with:
    pytest tests/test_benchmarks.py -v --benchmark-only
    pytest tests/test_benchmarks.py -v --benchmark-sort=mean
    pytest tests/test_benchmarks.py --benchmark-histogram
"""

import pytest
from arcis.core import (
    Sanitizer,
    RateLimiter,
    SecurityHeaders,
    SchemaValidator,
    SafeLogger,
    InMemoryStore,
)


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture(scope="module")
def sanitizer():
    return Sanitizer()


@pytest.fixture(scope="module")
def sanitizer_xss_only():
    return Sanitizer(xss=True, sql=False, nosql=False, path=False, command=False)


@pytest.fixture
def rate_limiter():
    limiter = RateLimiter(max_requests=1000000, window_ms=60000)
    yield limiter
    limiter.close()


@pytest.fixture(scope="module")
def security_headers():
    return SecurityHeaders()


@pytest.fixture(scope="module")
def safe_logger():
    return SafeLogger()


@pytest.fixture(scope="module")
def schema_validator():
    return SchemaValidator({
        "name": {"type": "string", "required": True, "min": 2, "max": 50},
        "email": {"type": "email", "required": True},
        "age": {"type": "number", "min": 0, "max": 150},
        "role": {"type": "string", "enum": ["user", "admin"]},
    })


# ============================================================================
# SANITIZER BENCHMARKS
# ============================================================================

class TestSanitizerBenchmarks:

    def test_sanitize_string_clean_input(self, benchmark, sanitizer):
        """Benchmark sanitizing a clean string (no threats)."""
        input_str = "Hello, my name is John Doe and I live in Portland."
        benchmark(sanitizer.sanitize_string, input_str)

    def test_sanitize_string_xss(self, benchmark, sanitizer):
        """Benchmark sanitizing a string with XSS payload."""
        input_str = "<script>alert('xss')</script>Hello World"
        benchmark(sanitizer.sanitize_string, input_str)

    def test_sanitize_string_xss_event_handler(self, benchmark, sanitizer):
        """Benchmark sanitizing an event handler XSS payload."""
        input_str = '<img src="x" onerror="alert(1)">'
        benchmark(sanitizer.sanitize_string, input_str)

    def test_sanitize_string_sql_injection(self, benchmark, sanitizer):
        """Benchmark sanitizing a SQL injection payload."""
        input_str = "'; DROP TABLE users; --"
        benchmark(sanitizer.sanitize_string, input_str)

    def test_sanitize_string_path_traversal(self, benchmark, sanitizer):
        """Benchmark sanitizing a path traversal payload."""
        input_str = "../../etc/passwd"
        benchmark(sanitizer.sanitize_string, input_str)

    def test_sanitize_string_long_clean(self, benchmark, sanitizer):
        """Benchmark sanitizing a long clean string (1000 chars)."""
        input_str = "Hello World! " * 77  # ~1000 chars
        benchmark(sanitizer.sanitize_string, input_str)

    def test_sanitize_string_long_xss(self, benchmark, sanitizer):
        """Benchmark sanitizing a long string with embedded XSS (1000 chars)."""
        payload = "<script>alert('xss')</script>"
        input_str = ("Safe content " * 30) + payload + ("More safe content " * 20)
        benchmark(sanitizer.sanitize_string, input_str)

    def test_sanitize_dict_flat(self, benchmark, sanitizer):
        """Benchmark sanitizing a flat dictionary."""
        data = {
            "name": "John Doe",
            "email": "john@example.com",
            "bio": "Hello, I am a developer.",
            "city": "Portland",
        }
        benchmark(sanitizer.sanitize_dict, data)

    def test_sanitize_dict_with_xss(self, benchmark, sanitizer):
        """Benchmark sanitizing a dict containing XSS payloads."""
        data = {
            "name": "<script>alert('xss')</script>",
            "comment": "<img onerror='alert(1)' src='x'>",
            "url": "javascript:alert(1)",
        }
        benchmark(sanitizer.sanitize_dict, data)

    def test_sanitize_dict_nested(self, benchmark, sanitizer):
        """Benchmark sanitizing a nested dictionary (3 levels deep)."""
        data = {
            "user": {
                "profile": {
                    "name": "John Doe",
                    "bio": "Developer",
                },
                "settings": {
                    "theme": "dark",
                    "notifications": "enabled",
                },
            },
            "metadata": {
                "source": "web",
                "ip": "127.0.0.1",
            },
        }
        benchmark(sanitizer.sanitize_dict, data)

    def test_sanitize_dict_with_nosql(self, benchmark, sanitizer):
        """Benchmark sanitizing a dict with NoSQL injection keys."""
        data = {
            "$gt": "",
            "$where": "function() { return true; }",
            "name": "John",
            "$or": [{"admin": True}],
        }
        benchmark(sanitizer.sanitize_dict, data)

    def test_sanitize_dict_large(self, benchmark, sanitizer):
        """Benchmark sanitizing a large flat dictionary (50 fields)."""
        data = {f"field_{i}": f"value_{i} with some content" for i in range(50)}
        benchmark(sanitizer.sanitize_dict, data)

    def test_sanitize_xss_only(self, benchmark, sanitizer_xss_only):
        """Benchmark XSS-only sanitizer vs full sanitizer."""
        input_str = "<script>alert('xss')</script>Hello World"
        benchmark(sanitizer_xss_only.sanitize_string, input_str)


# ============================================================================
# RATE LIMITER BENCHMARKS
# ============================================================================

class TestRateLimiterBenchmarks:

    def test_rate_limiter_check_new_ip(self, benchmark, rate_limiter):
        """Benchmark rate limit check for a new unique IP each time."""
        counter = {"i": 0}

        def check_new_ip():
            counter["i"] += 1

            class MockRequest:
                remote_addr = f"10.0.{counter['i'] // 256 % 256}.{counter['i'] % 256}"

            rate_limiter.check(MockRequest())

        benchmark(check_new_ip)

    def test_rate_limiter_check_existing_ip(self, benchmark):
        """Benchmark rate limit check for the same IP (hot path)."""
        # Use a dedicated limiter so no cross-test contamination
        limiter = RateLimiter(max_requests=10_000_000, window_ms=60000)

        class MockRequest:
            remote_addr = "192.168.100.1"

        # Pre-warm: ensure entry exists
        limiter.check(MockRequest())

        benchmark(limiter.check, MockRequest())
        limiter.close()

    def test_rate_limiter_store_get(self, benchmark):
        """Benchmark InMemoryStore get operation."""
        store = InMemoryStore()
        store.increment("bench_key", 60_000)
        benchmark(store.get, "bench_key")
        store.close()

    def test_rate_limiter_store_increment_new_keys(self, benchmark):
        """Benchmark InMemoryStore increment creating fresh keys at the cap."""
        store = InMemoryStore(max_size=1_000)
        counter = iter(range(10**9))

        def do_increment():
            store.increment(f"bench_key_{next(counter)}", 60_000)

        benchmark(do_increment)
        store.close()

    def test_rate_limiter_store_increment(self, benchmark):
        """Benchmark InMemoryStore increment operation."""
        store = InMemoryStore()
        benchmark(store.increment, "bench_key", 60_000)
        store.close()


# ============================================================================
# SECURITY HEADERS BENCHMARKS
# ============================================================================

class TestSecurityHeadersBenchmarks:

    def test_security_headers_get(self, benchmark, security_headers):
        """Benchmark getting all security headers as a dict."""
        benchmark(security_headers.get_headers)

    def test_security_headers_apply(self, benchmark, security_headers):
        """Benchmark applying security headers to a mock response."""
        class MockResponse:
            def __init__(self):
                self.headers = {}

        benchmark(security_headers.apply, MockResponse())

    def test_security_headers_init(self, benchmark):
        """Benchmark SecurityHeaders instantiation."""
        benchmark(SecurityHeaders)

    def test_security_headers_init_custom_csp(self, benchmark):
        """Benchmark SecurityHeaders instantiation with custom CSP."""
        def make_headers():
            SecurityHeaders(content_security_policy="default-src 'none'; script-src 'self'")

        benchmark(make_headers)


# ============================================================================
# SCHEMA VALIDATOR BENCHMARKS
# ============================================================================

class TestSchemaValidatorBenchmarks:

    def test_validate_valid_data(self, benchmark, schema_validator):
        """Benchmark validating a fully valid payload."""
        data = {
            "name": "John Doe",
            "email": "john@example.com",
            "age": 30,
            "role": "user",
        }
        benchmark(schema_validator.validate, data)

    def test_validate_missing_required(self, benchmark, schema_validator):
        """Benchmark validation failure (missing required field)."""
        data = {"age": 30, "role": "user"}  # missing name and email
        benchmark(schema_validator.validate, data)

    def test_validate_invalid_email(self, benchmark, schema_validator):
        """Benchmark validation with an invalid email."""
        data = {
            "name": "John Doe",
            "email": "not-an-email",
            "age": 30,
            "role": "user",
        }
        benchmark(schema_validator.validate, data)

    def test_validate_mass_assignment_prevention(self, benchmark, schema_validator):
        """Benchmark mass assignment prevention (extra fields stripped)."""
        data = {
            "name": "John Doe",
            "email": "john@example.com",
            "age": 30,
            "role": "user",
            "isAdmin": True,
            "password": "secret",
            "internalId": 9999,
            "createdAt": "2024-01-01",
        }
        benchmark(schema_validator.validate, data)

    def test_schema_validator_init(self, benchmark):
        """Benchmark SchemaValidator instantiation."""
        schema = {
            "name": {"type": "string", "required": True},
            "email": {"type": "email", "required": True},
            "age": {"type": "number", "min": 0, "max": 150},
        }
        benchmark(SchemaValidator, schema)


# ============================================================================
# SAFE LOGGER BENCHMARKS
# ============================================================================

class TestSafeLoggerBenchmarks:

    def test_redact_clean_data(self, benchmark, safe_logger):
        """Benchmark redacting a clean dict (no sensitive keys)."""
        data = {"name": "John", "city": "Portland", "role": "user"}
        benchmark(safe_logger._redact, data)

    def test_redact_sensitive_data(self, benchmark, safe_logger):
        """Benchmark redacting a dict with sensitive keys."""
        data = {
            "username": "john",
            "password": "supersecret",
            "token": "eyJhbGciOiJIUzI1NiJ9...",
            "email": "john@example.com",
            "api_key": "sk-1234567890",
        }
        benchmark(safe_logger._redact, data)

    def test_redact_nested_data(self, benchmark, safe_logger):
        """Benchmark redacting a nested dict with sensitive keys."""
        data = {
            "user": {
                "profile": {"name": "John", "email": "john@example.com"},
                "auth": {"password": "secret", "token": "abc123"},
            },
            "request": {"headers": {"authorization": "Bearer token123"}},
        }
        benchmark(safe_logger._redact, data)

    def test_redact_log_injection_string(self, benchmark, safe_logger):
        """Benchmark redacting a string with log injection characters."""
        data = "Normal message\nINJECTED LOG LINE\r\nAnother injection\tTabbed"
        benchmark(safe_logger._redact, data)
