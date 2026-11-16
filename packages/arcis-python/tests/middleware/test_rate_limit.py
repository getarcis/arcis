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


class TestRateLimiterFailOpen:
    """The limiter must fail open (in-memory fallback) when the store errors."""

    class _BoomStore:
        """A store whose every operation raises, simulating Redis being down."""
        def increment_or_set(self, key, window):
            raise RuntimeError("redis down")

        def get(self, key):
            raise RuntimeError("redis down")

        def set(self, *args):
            raise RuntimeError("redis down")

        def increment(self, key):
            raise RuntimeError("redis down")

        def close(self):
            pass

    def test_allows_request_when_store_errors(self):
        """Availability over denial: a store outage must not 500 the request."""
        limiter = RateLimiter(max_requests=5, window_ms=60000, store=self._BoomStore())
        try:
            result = limiter.check(MockRequest("9.9.9.9"))
            assert result["allowed"] is True
        finally:
            limiter.close()

    def test_fallback_still_enforces_limit(self):
        """The fallback maintains protection; it is not a pure bypass."""
        limiter = RateLimiter(max_requests=1, window_ms=60000, store=self._BoomStore())
        try:
            limiter.check(MockRequest("8.8.8.8"))  # allowed via fallback
            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest("8.8.8.8"))  # fallback rate-limits it
        finally:
            limiter.close()


class TestRateLimitExceeded:
    """Test RateLimitExceeded exception."""

    def test_has_message(self):
        exc = RateLimitExceeded("Custom message", retry_after=30)
        assert exc.message == "Custom message"
        assert exc.retry_after == 30
        assert str(exc) == "Custom message"


# ============================================================================
# Store contract, error reporting and validation (spec: Store contract)
# ============================================================================

import asyncio  # noqa: E402
import logging  # noqa: E402
import time  # noqa: E402

from arcis.middleware import rate_limit as rate_limit_module  # noqa: E402
from arcis.stores import base as store_base  # noqa: E402


class _CountingStore:
    """Atomic-contract store that records every call."""

    def __init__(self):
        self.calls = []
        self.hits = {}

    def increment(self, key, window_ms):
        self.calls.append(("increment", key, window_ms))
        self.hits[key] = self.hits.get(key, 0) + 1
        return self.hits[key], time.time() + window_ms / 1000

    def decrement(self, key):
        self.calls.append(("decrement", key))

    def reset_key(self, key):
        self.calls.append(("reset_key", key))


class _FailingStore:
    def __init__(self):
        self.attempts = 0

    def increment(self, key, window_ms):
        self.attempts += 1
        raise ConnectionError("redis down")

    def decrement(self, key):
        raise ConnectionError("redis down")

    def reset_key(self, key):
        raise ConnectionError("redis down")


class _LegacyStore:
    """The pre-contract get / set / increment(key) interface."""

    def __init__(self):
        self.entries = {}

    def get(self, key):
        return self.entries.get(key)

    def set(self, key, count, reset_time):
        from arcis.core.types import RateLimitEntry

        self.entries[key] = RateLimitEntry(count=count, reset_time=reset_time)

    def increment(self, key):
        self.entries[key].count += 1
        return self.entries[key].count


def _store_error_records(caplog):
    return [r for r in caplog.records if "store error" in r.getMessage()]


class TestRateLimiterStoreContract:
    def test_exactly_one_increment_per_counted_request(self):
        store = _CountingStore()
        limiter = RateLimiter(max_requests=2, window_ms=60000, store=store)
        try:
            limiter.check(MockRequest("192.0.2.1"))
            limiter.check(MockRequest("192.0.2.1"))
            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest("192.0.2.1"))
            assert store.calls == [("increment", "192.0.2.1", 60000)] * 3
        finally:
            limiter.close()

    def test_skipped_request_is_not_counted(self):
        store = _CountingStore()
        limiter = RateLimiter(max_requests=1, store=store, skip_func=lambda r: True)
        try:
            limiter.check(MockRequest())
            assert store.calls == []
        finally:
            limiter.close()

    def test_store_error_runs_fallback_and_reports_once_per_window(self, caplog):
        store = _FailingStore()
        limiter = RateLimiter(max_requests=1, window_ms=60000, store=store)
        try:
            with caplog.at_level(logging.ERROR, logger=rate_limit_module.__name__):
                limiter.check(MockRequest("192.0.2.9"))
                # The in-memory fallback counted the first request.
                with pytest.raises(RateLimitExceeded):
                    limiter.check(MockRequest("192.0.2.9"))
                limiter.check(MockRequest("192.0.2.10"))
            assert store.attempts == 3
            records = _store_error_records(caplog)
            assert len(records) == 1
            assert "ConnectionError" in records[0].getMessage()
        finally:
            limiter.close()

    def test_store_error_reported_again_after_window(self, caplog):
        limiter = RateLimiter(max_requests=10, window_ms=50, store=_FailingStore())
        try:
            with caplog.at_level(logging.ERROR, logger=rate_limit_module.__name__):
                limiter.check(MockRequest())
                limiter.check(MockRequest())
                time.sleep(0.08)
                limiter.check(MockRequest())
            assert len(_store_error_records(caplog)) == 2
        finally:
            limiter.close()

    def test_legacy_store_is_wrapped_and_warns_once(self, caplog):
        store_base._warned_store_types.clear()
        with caplog.at_level(logging.WARNING, logger=store_base.__name__):
            first = RateLimiter(max_requests=2, window_ms=60000, store=_LegacyStore())
            second = RateLimiter(max_requests=2, window_ms=60000, store=_LegacyStore())
        try:
            warnings = [r for r in caplog.records if "not atomic" in r.getMessage()]
            assert len(warnings) == 1
            first.check(MockRequest("192.0.2.3"))
            first.check(MockRequest("192.0.2.3"))
            with pytest.raises(RateLimitExceeded):
                first.check(MockRequest("192.0.2.3"))
        finally:
            first.close()
            second.close()

    def test_store_without_required_methods_is_rejected(self):
        class Empty:
            pass

        with pytest.raises(TypeError):
            RateLimiter(store=Empty())


class TestRateLimiterValidation:
    @pytest.mark.parametrize(
        "window_ms", [0, -1, 1.5, 2**31, float("nan"), "60000", True, None]
    )
    def test_invalid_window_rejected(self, window_ms):
        with pytest.raises(ValueError, match="window_ms"):
            RateLimiter(window_ms=window_ms)

    @pytest.mark.parametrize("window_ms", [1, 60000.0, 2**31 - 1])
    def test_valid_window_accepted(self, window_ms):
        limiter = RateLimiter(window_ms=window_ms)
        try:
            assert limiter.window_ms == int(window_ms)
        finally:
            limiter.close()

    @pytest.mark.parametrize("max_requests", [-1, 1.5, "5", True, None])
    def test_invalid_max_rejected(self, max_requests):
        with pytest.raises(ValueError, match="max_requests"):
            RateLimiter(max_requests=max_requests)

    def test_max_zero_blocks_everything(self):
        limiter = RateLimiter(max_requests=0)
        try:
            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest())
        finally:
            limiter.close()

    def test_invalid_trusted_proxies_rejected(self):
        with pytest.raises(ValueError, match="trusted_proxies"):
            RateLimiter(trusted_proxies=["10.0.0.0/99"])

    def test_invalid_ipv6_subnet_rejected(self):
        with pytest.raises(ValueError, match="ipv6_subnet"):
            RateLimiter(ipv6_subnet=0)


class TestRateLimiterDefaultKey:
    def test_public_peer_cannot_rotate_forwarded_for(self):
        class Req:
            def __init__(self, xff):
                self.remote_addr = "203.0.113.5"
                self.headers = {"x-forwarded-for": xff}

        limiter = RateLimiter(max_requests=1)
        try:
            limiter.check(Req("1.1.1.1"))
            with pytest.raises(RateLimitExceeded):
                limiter.check(Req("2.2.2.2"))
        finally:
            limiter.close()

    def test_ipv6_allocation_shares_one_key(self):
        limiter = RateLimiter(max_requests=1)
        try:
            limiter.check(MockRequest("2001:db8:1234:5601::1"))
            with pytest.raises(RateLimitExceeded):
                limiter.check(MockRequest("2001:db8:1234:56ff::2"))
        finally:
            limiter.close()


class TestAsyncRateLimiterStoreContract:
    def _limiter(self, **kwargs):
        from arcis.async_rate_limit import AsyncRateLimiter

        return AsyncRateLimiter(**kwargs)

    def test_store_error_fails_open_and_reports_once(self, caplog):
        class AsyncFailingStore:
            attempts = 0

            async def increment(self, key, window_ms):
                AsyncFailingStore.attempts += 1
                raise ConnectionError("redis down")

            async def close(self):
                pass

        async def run():
            limiter = self._limiter(max_requests=1, window_ms=60000, store=AsyncFailingStore())
            results = [await limiter.check(MockRequest("192.0.2.1")) for _ in range(3)]
            await limiter.close()
            return results

        with caplog.at_level(logging.ERROR, logger=rate_limit_module.__name__):
            results = asyncio.run(run())
        assert [r["allowed"] for r in results] == [True, True, True]
        assert AsyncFailingStore.attempts == 3
        assert len(_store_error_records(caplog)) == 1

    def test_legacy_async_store_is_wrapped(self):
        from arcis.async_rate_limit import AsyncRateLimitExceeded

        class AsyncLegacyStore:
            def __init__(self):
                self.inner = _LegacyStore()

            async def get(self, key):
                return self.inner.get(key)

            async def set(self, key, count, reset_time):
                self.inner.set(key, count, reset_time)

            async def increment(self, key):
                return self.inner.increment(key)

        async def run():
            limiter = self._limiter(max_requests=2, window_ms=60000, store=AsyncLegacyStore())
            await asyncio.gather(*[limiter.check(MockRequest("192.0.2.2")) for _ in range(2)])
            with pytest.raises(AsyncRateLimitExceeded):
                await limiter.check(MockRequest("192.0.2.2"))

        asyncio.run(run())

    def test_concurrent_requests_admit_exactly_max(self):
        from arcis.async_rate_limit import AsyncRateLimitExceeded

        async def run():
            limiter = self._limiter(max_requests=5, window_ms=60000)

            async def one():
                try:
                    await limiter.check(MockRequest("192.0.2.3"))
                    return True
                except AsyncRateLimitExceeded:
                    return False

            results = await asyncio.gather(*[one() for _ in range(50)])
            await limiter.close()
            return results

        assert sum(asyncio.run(run())) == 5
