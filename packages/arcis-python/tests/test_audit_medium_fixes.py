"""Regression tests for AUDIT_PLAN medium findings (M1, M3, M7) — Python SDK."""

import asyncio
import pytest

from arcis.sanitizers.ssti import sanitize_ssti
from arcis.sanitizers.jsonp import sanitize_jsonp_callback, detect_jsonp_injection


class TestM1_SSTIDunderPatterns:
    def test_strips_self_dunder_dict(self):
        out = sanitize_ssti("hello ${self.__dict__} world")
        assert "__dict__" not in out

    def test_strips_pug_dunder_class(self):
        out = sanitize_ssti("#{obj.__class__}")
        assert "__class__" not in out

    def test_leaves_plain_template_literal(self):
        assert sanitize_ssti("Hello ${name}") == "Hello ${name}"


class TestM3_JSONPBrackets:
    def test_rejects_unbalanced_bracket(self):
        assert sanitize_jsonp_callback("cb[x") is None

    def test_rejects_any_brackets(self):
        assert sanitize_jsonp_callback("cb[0]") is None
        assert sanitize_jsonp_callback("arr[1].fn") is None

    def test_detect_flags_brackets(self):
        assert detect_jsonp_injection("cb[x") is True

    def test_accepts_plain_identifiers(self):
        assert sanitize_jsonp_callback("myCallback") == "myCallback"
        assert sanitize_jsonp_callback("ns.cb") == "ns.cb"


class TestM7_AsyncCleanupRace:
    def test_concurrent_start_cleanup_yields_single_task(self):
        pytest.importorskip("starlette")
        from arcis.fastapi import AsyncRateLimiter

        async def run():
            limiter = AsyncRateLimiter(max_requests=10, window_ms=60_000)
            try:
                # Fire many concurrent _start_cleanup() calls — the lock must ensure
                # only one cleanup task is actually spawned.
                await asyncio.gather(*(limiter._start_cleanup() for _ in range(20)))
                assert limiter._cleanup_task is not None
                # Second wave must not replace the task
                original = limiter._cleanup_task
                await asyncio.gather(*(limiter._start_cleanup() for _ in range(10)))
                assert limiter._cleanup_task is original
            finally:
                limiter._closed = True
                if limiter._cleanup_task:
                    limiter._cleanup_task.cancel()
                    try:
                        await limiter._cleanup_task
                    except (asyncio.CancelledError, Exception):
                        pass

        asyncio.run(run())
