"""
RateLimiter and RateLimitExceeded tests — extracted from tests/test_core.py.
"""

import pytest
from arcis.core import RateLimiter, RateLimitExceeded


class MockRequest:
    """Mock request object for testing."""
    def __init__(self, ip: str = "127.0.0.1"):
        self.remote_addr = ip


class TestRateLimiter:
    """Test rate limiting functionality."""

    def test_allows_under_limit(self):
        """Requests under limit should pass."""
        limiter = RateLimiter(max_requests=5, window_ms=60000)

        for _ in range(3):
            result = limiter.check(MockRequest())
            assert result["allowed"] is True

    def test_returns_rate_limit_headers(self):
        """Should return X-RateLimit-* header info."""
        limiter = RateLimiter(max_requests=100, window_ms=60000)
        result = limiter.check(MockRequest())

        assert "limit" in result
        assert "remaining" in result
        assert "reset" in result
        assert result["limit"] == 100

    def test_blocks_over_limit(self):
        """Requests over limit should be blocked."""
        limiter = RateLimiter(max_requests=3, window_ms=60000)

        for _ in range(3):
            limiter.check(MockRequest(ip="192.168.1.1"))

        with pytest.raises(RateLimitExceeded):
            limiter.check(MockRequest(ip="192.168.1.1"))

    def test_different_ips_separate_limits(self):
        """Different IPs should have separate rate limits."""
        limiter = RateLimiter(max_requests=2, window_ms=60000)

        for ip_suffix in range(3):
            ip = f"192.168.1.{ip_suffix}"
            for _ in range(2):
                result = limiter.check(MockRequest(ip=ip))
                assert result["allowed"] is True

    def test_skip_function(self):
        """Skip function should bypass rate limiting."""
        limiter = RateLimiter(
            max_requests=1,
            window_ms=60000,
            skip_func=lambda req: True
        )

        for _ in range(5):
            result = limiter.check(MockRequest())
            assert result["allowed"] is True


class TestRateLimitExceeded:
    """Test RateLimitExceeded exception."""

    def test_has_message(self):
        exc = RateLimitExceeded("Custom message", retry_after=30)
        assert exc.message == "Custom message"
        assert exc.retry_after == 30
        assert str(exc) == "Custom message"
