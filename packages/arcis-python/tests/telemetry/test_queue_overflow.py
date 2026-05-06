"""
Regression tests for the v1.4.4 fix: telemetry queue must be bounded
to prevent OOM during sustained dashboard outages.

Pre-fix the in-memory queue was unbounded, so 24h of unreachable
dashboard at moderate traffic would crash the worker. Now drops oldest
when the queue is full and notifies via on_queue_overflow.
"""

import asyncio
import time
from unittest.mock import MagicMock


from arcis.telemetry.client import TelemetryClient, AsyncTelemetryClient
from arcis.telemetry.types import TelemetryEvent, TelemetryOptions


def _ev(i: int = 0) -> TelemetryEvent:
    return TelemetryEvent(
        ip="127.0.0.1",
        method="GET",
        path=f"/p{i}",
        decision="deny",
        status=403,
    )


class TestSyncClientQueueCap:
    def test_caps_queue_at_max_queue_size(self, monkeypatch):
        """When max_queue_size is exceeded, drop-oldest keeps the queue
        at exactly max_queue_size and pending_count never grows past it."""
        # Stub _send so events stay in the queue (no flush).
        from arcis.telemetry import client as client_module
        monkeypatch.setattr(client_module, "httpx", None)
        monkeypatch.setattr(client_module, "_post_sync_urllib", lambda *a, **kw: None)

        c = TelemetryClient(
            TelemetryOptions(
                endpoint="http://example/v1/events",
                batch_size=5,
                max_queue_size=10,
                # Long flush interval so worker doesn't drain in test window.
                flush_interval_ms=60_000,
            )
        )
        try:
            for i in range(50):
                c.record(_ev(i))
            # Give the worker a moment to flush a single batch (it will
            # because qsize >= batch_size triggered _wakeup) but the queue
            # should NEVER exceed max_queue_size during recording.
            assert c.pending_count <= 10
        finally:
            c.close()

    def test_overflow_callback_invoked(self, monkeypatch):
        from arcis.telemetry import client as client_module
        monkeypatch.setattr(client_module, "httpx", None)
        # Block all sends so the queue actually fills.
        def _hang(*a, **kw):
            time.sleep(60)  # never returns within the test
        monkeypatch.setattr(client_module, "_post_sync_urllib", _hang)

        on_overflow = MagicMock()
        c = TelemetryClient(
            TelemetryOptions(
                endpoint="http://example/v1/events",
                # batch_size must be <= max_queue_size, else the client
                # raises max_queue_size up to batch_size (flush needs to
                # dequeue a full batch). Use a small batch + blocked send
                # so the queue actually fills and overflows.
                batch_size=3,
                max_queue_size=5,
                flush_interval_ms=60_000,
                on_queue_overflow=on_overflow,
            )
        )
        try:
            # Record more than max_queue_size; the surplus drops oldest.
            for i in range(20):
                c.record(_ev(i))
            # Queue must be capped at max_queue_size regardless of how
            # many events were recorded.
            assert c.pending_count <= 5
            # Callback fires at least once per drop. With 20 records
            # against a maxsize of 5, we expect ~10+ drops.
            assert on_overflow.call_count >= 10
            # Last call argument is the cumulative drop count for the
            # current outage window (resets to 0 on next successful flush).
            last_call_arg = on_overflow.call_args[0][0]
            assert last_call_arg >= 10
        finally:
            c.close()


class TestAsyncClientQueueCap:
    def test_async_caps_queue_at_max_queue_size(self):
        async def run():
            c = AsyncTelemetryClient(
                TelemetryOptions(
                    endpoint="http://example/v1/events",
                    batch_size=5,
                    max_queue_size=10,
                    flush_interval_ms=60_000,
                )
            )
            try:
                for i in range(50):
                    c.record(_ev(i))
                # No await before close → no flush has happened yet.
                assert c.pending_count <= 10
            finally:
                await c.close()

        asyncio.run(run())

    def test_async_overflow_callback_invoked(self):
        """Stub _send to a hanging coroutine so the worker can't drain
        the queue, then verify the cap holds and overflow callback fires."""
        async def run():
            async def _hang(self, batch):
                await asyncio.sleep(60)  # never returns within test window

            on_overflow = MagicMock()
            c = AsyncTelemetryClient(
                TelemetryOptions(
                    endpoint="http://example/v1/events",
                    batch_size=3,
                    max_queue_size=5,
                    flush_interval_ms=60_000,
                    on_queue_overflow=on_overflow,
                )
            )
            c._send = _hang.__get__(c, type(c))  # type: ignore[method-assign]
            try:
                for i in range(20):
                    c.record(_ev(i))
                assert c.pending_count <= 5
                assert on_overflow.call_count >= 1
            finally:
                c._closed = True
                if c._task is not None:
                    c._task.cancel()
                    try:
                        await c._task
                    except BaseException:
                        pass

        asyncio.run(run())
