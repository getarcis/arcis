"""
Sliding window rate limiter tests.
Tests for arcis/middleware/rate_limit_sliding.py
"""

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

    def test_max_requests_zero_blocks_everything(self):
        limiter = SlidingWindowLimiter(max_requests=0, window='1m')
        try:
            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest())
        finally:
            limiter.close()

    @pytest.mark.parametrize("bad", [-1, 1.5, True, "5"])
    def test_invalid_max_requests_raises(self, bad):
        with pytest.raises(ValueError, match="max_requests must be a non-negative integer"):
            SlidingWindowLimiter(max_requests=bad, window='1m')

    @pytest.mark.parametrize("bad", [0, 1.5, 2**31, '0ms', '30d'])
    def test_out_of_range_window_raises(self, bad):
        with pytest.raises(ValueError):
            SlidingWindowLimiter(max_requests=10, window=bad)

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


class _FakeClock:
    """Stands in for the ``time`` module inside rate_limit_sliding."""

    def __init__(self, now: float) -> None:
        self.now = now

    def time(self) -> float:
        return self.now


class TestSlidingWindowPreviousWindow:
    """The previous window counts only when it immediately precedes the current one."""

    @pytest.fixture
    def clock(self, monkeypatch):
        from arcis.middleware import rate_limit_sliding

        fake = _FakeClock(1_000_000.0)  # aligned to a 10 s window boundary
        monkeypatch.setattr(rate_limit_sliding, "time", fake)
        return fake

    def test_adjacent_previous_window_is_weighted(self, clock):
        limiter = SlidingWindowLimiter(max_requests=3, window=10_000)
        try:
            for _ in range(3):
                limiter.check(MockRequest())
            clock.now += 10.5  # 5% into the next window: previous weight 0.95
            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest())
        finally:
            limiter.close()

    def test_key_idle_for_a_full_window_starts_from_zero(self, clock):
        limiter = SlidingWindowLimiter(max_requests=3, window=10_000)
        try:
            for _ in range(3):
                limiter.check(MockRequest())
            clock.now += 20.5  # skipped one whole window
            for _ in range(3):
                assert limiter.check(MockRequest())["allowed"] is True
        finally:
            limiter.close()

    def test_stale_previous_is_not_reused_after_rotation(self, clock):
        limiter = SlidingWindowLimiter(max_requests=3, window=10_000)
        try:
            for _ in range(3):
                limiter.check(MockRequest())
            clock.now += 10.5
            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest())
            clock.now += 10  # window after next: the full one is no longer adjacent
            for _ in range(3):
                assert limiter.check(MockRequest())["allowed"] is True
        finally:
            limiter.close()


class TestSlidingWindowClientKey:
    def test_public_peer_cannot_rotate_forwarded_for(self):
        class Req:
            def __init__(self, xff):
                self.remote_addr = "203.0.113.5"
                self.headers = {"x-forwarded-for": xff}

        limiter = SlidingWindowLimiter(max_requests=1, window='1m')
        try:
            limiter.check(Req("1.1.1.1"))
            with pytest.raises(RateLimitExceeded):
                limiter.check(Req("2.2.2.2"))
        finally:
            limiter.close()
