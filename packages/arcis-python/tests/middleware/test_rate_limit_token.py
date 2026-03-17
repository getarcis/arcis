"""
Token bucket rate limiter tests.
Tests for arcis/middleware/rate_limit_token.py
"""

import time
import threading
import pytest
from arcis.middleware.rate_limit_token import TokenBucketLimiter
from arcis.middleware.rate_limit import RateLimitExceeded


class MockRequest:
    """Mock request object for testing."""
    def __init__(self, ip='127.0.0.1'):
        self.remote_addr = ip


class TestTokenBucketAllow:
    """Test requests within capacity."""

    def test_allows_burst_up_to_capacity(self):
        limiter = TokenBucketLimiter(capacity=5, refill_rate=1.0)
        try:
            for _ in range(5):
                result = limiter.check(MockRequest())
                assert result['allowed'] is True
        finally:
            limiter.close()

    def test_returns_capacity_info(self):
        limiter = TokenBucketLimiter(capacity=50, refill_rate=10.0)
        try:
            result = limiter.check(MockRequest())
            assert 'capacity' in result
            assert 'remaining' in result
            assert 'retry_after' in result
            assert result['capacity'] == 50
            assert result['retry_after'] == 0
        finally:
            limiter.close()

    def test_remaining_decreases(self):
        limiter = TokenBucketLimiter(capacity=10, refill_rate=1.0)
        try:
            r1 = limiter.check(MockRequest())
            r2 = limiter.check(MockRequest())
            assert r2['remaining'] < r1['remaining']
        finally:
            limiter.close()


class TestTokenBucketDeny:
    """Test requests exceeding capacity."""

    def test_blocks_when_tokens_exhausted(self):
        limiter = TokenBucketLimiter(capacity=3, refill_rate=0.01)
        try:
            for _ in range(3):
                limiter.check(MockRequest(ip='192.168.1.1'))

            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest(ip='192.168.1.1'))
        finally:
            limiter.close()

    def test_exception_has_retry_after(self):
        limiter = TokenBucketLimiter(capacity=1, refill_rate=1.0)
        try:
            limiter.check(MockRequest())
            with pytest.raises(RateLimitExceeded) as exc_info:
                limiter.check(MockRequest())
            assert exc_info.value.retry_after >= 0
        finally:
            limiter.close()

    def test_custom_message(self):
        limiter = TokenBucketLimiter(capacity=1, refill_rate=0.01, message='Slow down')
        try:
            limiter.check(MockRequest())
            with pytest.raises(RateLimitExceeded, match='Slow down'):
                limiter.check(MockRequest())
        finally:
            limiter.close()


class TestTokenBucketRefill:
    """Test token refill behavior."""

    def test_tokens_refill_over_time(self):
        limiter = TokenBucketLimiter(capacity=2, refill_rate=100.0)
        try:
            # Use both tokens
            limiter.check(MockRequest())
            limiter.check(MockRequest())

            # Wait for refill (100 tokens/sec = ~20ms per token)
            time.sleep(0.05)

            # Should have refilled
            result = limiter.check(MockRequest())
            assert result['allowed'] is True
        finally:
            limiter.close()


class TestTokenBucketCost:
    """Test custom cost per request."""

    def test_higher_cost_consumes_more_tokens(self):
        limiter = TokenBucketLimiter(capacity=10, refill_rate=0.01, cost=5)
        try:
            # 10 tokens, cost 5 per request = 2 requests
            limiter.check(MockRequest())
            limiter.check(MockRequest())

            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest())
        finally:
            limiter.close()


class TestTokenBucketSeparateKeys:
    """Test per-key isolation."""

    def test_different_ips_separate_buckets(self):
        limiter = TokenBucketLimiter(capacity=2, refill_rate=0.01)
        try:
            for i in range(3):
                ip = f'192.168.1.{i}'
                for _ in range(2):
                    result = limiter.check(MockRequest(ip=ip))
                    assert result['allowed'] is True
        finally:
            limiter.close()

    def test_custom_key_func(self):
        limiter = TokenBucketLimiter(
            capacity=2,
            refill_rate=0.01,
            key_func=lambda req: 'global',
        )
        try:
            limiter.check(MockRequest(ip='1.1.1.1'))
            limiter.check(MockRequest(ip='2.2.2.2'))

            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest(ip='3.3.3.3'))
        finally:
            limiter.close()


class TestTokenBucketSkip:
    """Test skip function."""

    def test_skip_bypasses_limit(self):
        limiter = TokenBucketLimiter(
            capacity=1,
            refill_rate=0.01,
            skip_func=lambda req: True,
        )
        try:
            for _ in range(10):
                result = limiter.check(MockRequest())
                assert result['allowed'] is True
                assert result['remaining'] == limiter.capacity
        finally:
            limiter.close()

    def test_skip_false_does_not_bypass(self):
        limiter = TokenBucketLimiter(
            capacity=1,
            refill_rate=0.01,
            skip_func=lambda req: False,
        )
        try:
            limiter.check(MockRequest())
            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest())
        finally:
            limiter.close()


class TestTokenBucketClose:
    """Test close and cleanup."""

    def test_close_allows_all_requests(self):
        limiter = TokenBucketLimiter(capacity=1, refill_rate=0.01)
        limiter.close()
        result = limiter.check(MockRequest())
        assert result['allowed'] is True

    def test_close_idempotent(self):
        limiter = TokenBucketLimiter(capacity=10, refill_rate=1.0)
        limiter.close()
        limiter.close()  # Should not raise

    def test_cleanup_thread_stops(self):
        limiter = TokenBucketLimiter(capacity=10, refill_rate=1.0)
        thread = limiter._cleanup_thread
        limiter.close()
        assert not thread.is_alive()


class TestTokenBucketValidation:
    """Test constructor validation."""

    def test_capacity_zero_raises(self):
        with pytest.raises(ValueError, match="capacity must be >= 1"):
            TokenBucketLimiter(capacity=0, refill_rate=1.0)

    def test_capacity_negative_raises(self):
        with pytest.raises(ValueError, match="capacity must be >= 1"):
            TokenBucketLimiter(capacity=-1, refill_rate=1.0)

    def test_refill_rate_zero_raises(self):
        with pytest.raises(ValueError, match="refill_rate must be > 0"):
            TokenBucketLimiter(capacity=10, refill_rate=0)

    def test_refill_rate_negative_raises(self):
        with pytest.raises(ValueError, match="refill_rate must be > 0"):
            TokenBucketLimiter(capacity=10, refill_rate=-1.0)

    def test_cost_zero_raises(self):
        with pytest.raises(ValueError, match="cost must be >= 1"):
            TokenBucketLimiter(capacity=10, refill_rate=1.0, cost=0)

    def test_cost_negative_raises(self):
        with pytest.raises(ValueError, match="cost must be >= 1"):
            TokenBucketLimiter(capacity=10, refill_rate=1.0, cost=-1)


class TestTokenBucketThreadSafety:
    """Test concurrent access from multiple threads."""

    def test_concurrent_requests(self):
        limiter = TokenBucketLimiter(capacity=100, refill_rate=100.0)
        errors = []
        results = []

        def make_requests():
            try:
                for _ in range(10):
                    result = limiter.check(MockRequest())
                    results.append(result)
            except RateLimitExceeded:
                pass
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=make_requests) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        limiter.close()
        assert errors == [], f"Thread errors: {errors}"
        assert len(results) > 0
