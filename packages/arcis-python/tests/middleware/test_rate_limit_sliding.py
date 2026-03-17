"""
Sliding window rate limiter tests.
Tests for arcis/middleware/rate_limit_sliding.py
"""

import time
import threading
import pytest
from arcis.middleware.rate_limit_sliding import SlidingWindowLimiter
from arcis.middleware.rate_limit import RateLimitExceeded


class MockRequest:
    """Mock request object for testing."""
    def __init__(self, ip='127.0.0.1'):
        self.remote_addr = ip


class TestSlidingWindowAllow:
    """Test requests within rate limit."""

    def test_allows_under_limit(self):
        limiter = SlidingWindowLimiter(max_requests=10, window='1m')
        try:
            for _ in range(5):
                result = limiter.check(MockRequest())
                assert result['allowed'] is True
        finally:
            limiter.close()

    def test_returns_limit_info(self):
        limiter = SlidingWindowLimiter(max_requests=100, window='1m')
        try:
            result = limiter.check(MockRequest())
            assert 'limit' in result
            assert 'remaining' in result
            assert 'reset' in result
            assert result['limit'] == 100
        finally:
            limiter.close()

    def test_remaining_decreases(self):
        limiter = SlidingWindowLimiter(max_requests=10, window='1m')
        try:
            r1 = limiter.check(MockRequest())
            r2 = limiter.check(MockRequest())
            assert r2['remaining'] <= r1['remaining']
        finally:
            limiter.close()


class TestSlidingWindowDeny:
    """Test requests exceeding rate limit."""

    def test_blocks_over_limit(self):
        limiter = SlidingWindowLimiter(max_requests=3, window='1m')
        try:
            for _ in range(3):
                limiter.check(MockRequest(ip='192.168.1.1'))

            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest(ip='192.168.1.1'))
        finally:
            limiter.close()

    def test_exception_has_retry_after(self):
        limiter = SlidingWindowLimiter(max_requests=1, window='1m')
        try:
            limiter.check(MockRequest())
            with pytest.raises(RateLimitExceeded) as exc_info:
                limiter.check(MockRequest())
            assert exc_info.value.retry_after >= 0
        finally:
            limiter.close()

    def test_custom_message(self):
        limiter = SlidingWindowLimiter(max_requests=1, window='1m', message='Slow down')
        try:
            limiter.check(MockRequest())
            with pytest.raises(RateLimitExceeded, match='Slow down'):
                limiter.check(MockRequest())
        finally:
            limiter.close()


class TestSlidingWindowSeparateKeys:
    """Test per-key isolation."""

    def test_different_ips_separate_limits(self):
        limiter = SlidingWindowLimiter(max_requests=2, window='1m')
        try:
            for i in range(3):
                ip = f'192.168.1.{i}'
                for _ in range(2):
                    result = limiter.check(MockRequest(ip=ip))
                    assert result['allowed'] is True
        finally:
            limiter.close()

    def test_custom_key_func(self):
        limiter = SlidingWindowLimiter(
            max_requests=2,
            window='1m',
            key_func=lambda req: 'global',
        )
        try:
            limiter.check(MockRequest(ip='1.1.1.1'))
            limiter.check(MockRequest(ip='2.2.2.2'))

            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest(ip='3.3.3.3'))
        finally:
            limiter.close()


class TestSlidingWindowSkip:
    """Test skip function."""

    def test_skip_bypasses_limit(self):
        limiter = SlidingWindowLimiter(
            max_requests=1,
            window='1m',
            skip_func=lambda req: True,
        )
        try:
            for _ in range(10):
                result = limiter.check(MockRequest())
                assert result['allowed'] is True
                assert result['remaining'] == limiter.max_requests
        finally:
            limiter.close()

    def test_skip_false_does_not_bypass(self):
        limiter = SlidingWindowLimiter(
            max_requests=1,
            window='1m',
            skip_func=lambda req: False,
        )
        try:
            limiter.check(MockRequest())
            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest())
        finally:
            limiter.close()


class TestSlidingWindowClose:
    """Test close and cleanup."""

    def test_close_allows_all_requests(self):
        limiter = SlidingWindowLimiter(max_requests=1, window='1m')
        limiter.close()
        # After close, all requests should be allowed
        result = limiter.check(MockRequest())
        assert result['allowed'] is True

    def test_close_idempotent(self):
        limiter = SlidingWindowLimiter(max_requests=10, window='1m')
        limiter.close()
        limiter.close()  # Should not raise

    def test_cleanup_thread_stops(self):
        limiter = SlidingWindowLimiter(max_requests=10, window='1m')
        thread = limiter._cleanup_thread
        limiter.close()
        assert not thread.is_alive()


class TestSlidingWindowValidation:
    """Test constructor validation."""

    def test_max_requests_zero_raises(self):
        with pytest.raises(ValueError, match="max_requests must be >= 1"):
            SlidingWindowLimiter(max_requests=0, window='1m')

    def test_max_requests_negative_raises(self):
        with pytest.raises(ValueError, match="max_requests must be >= 1"):
            SlidingWindowLimiter(max_requests=-1, window='1m')

    def test_invalid_window_raises(self):
        with pytest.raises(ValueError):
            SlidingWindowLimiter(max_requests=10, window='invalid')

    def test_accepts_int_window(self):
        limiter = SlidingWindowLimiter(max_requests=10, window=60000)
        try:
            assert limiter.window_ms == 60000
        finally:
            limiter.close()


class TestSlidingWindowThreadSafety:
    """Test concurrent access from multiple threads."""

    def test_concurrent_requests(self):
        limiter = SlidingWindowLimiter(max_requests=100, window='1m')
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
