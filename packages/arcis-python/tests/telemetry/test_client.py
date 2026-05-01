"""
Unit tests for TelemetryClient + AsyncTelemetryClient.

Strategy: tests monkeypatch the low-level HTTP poster functions so the client
queue/flush/fail-open logic is exercised in isolation. No real network calls.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from arcis.telemetry import client as client_module
from arcis.telemetry.client import (
    AsyncTelemetryClient,
    TelemetryClient,
    TelemetryHttpError,
)
from arcis.telemetry.types import TelemetryEvent, TelemetryOptions


def _make_event(decision: str = "allow", status: int = 200) -> TelemetryEvent:
    return TelemetryEvent(
        ip="127.0.0.1",
        method="POST",
        path="/api",
        decision=decision,  # type: ignore[arg-type]
        status=status,
    )


# ─── Sync TelemetryClient ──────────────────────────────────────────────────


class TestSyncClient:
    def test_endpoint_required(self) -> None:
        with pytest.raises(TypeError):
            TelemetryClient(TelemetryOptions(endpoint=""))

    def test_record_enqueues(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[bytes] = []
        monkeypatch.setattr(client_module, "httpx", None)
        monkeypatch.setattr(
            client_module,
            "_post_sync_urllib",
            lambda endpoint, headers, body, timeout: captured.append(body),
        )

        c = TelemetryClient(TelemetryOptions(endpoint="http://x/v1/events", batch_size=2))
        try:
            c.record(_make_event())
            assert c.pending_count == 1
        finally:
            c.close()

    def test_flush_on_batch_size(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[bytes] = []
        monkeypatch.setattr(client_module, "httpx", None)
        monkeypatch.setattr(
            client_module,
            "_post_sync_urllib",
            lambda endpoint, headers, body, timeout: captured.append(body),
        )

        c = TelemetryClient(TelemetryOptions(endpoint="http://x", batch_size=2))
        try:
            c.record(_make_event())
            c.record(_make_event())
            # batch trigger sets _wakeup; the worker should flush within ~1s
            for _ in range(50):
                if captured:
                    break
                time.sleep(0.02)
            assert len(captured) == 1
            payload = captured[0].decode()
            assert '"events"' in payload
            assert '"decision": "allow"' in payload
        finally:
            c.close()

    def test_fail_open_calls_on_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        errors: list[Exception] = []

        def boom(endpoint: str, headers: dict, body: bytes, timeout: float) -> None:
            raise TelemetryHttpError(503, "down")

        monkeypatch.setattr(client_module, "httpx", None)
        monkeypatch.setattr(client_module, "_post_sync_urllib", boom)

        c = TelemetryClient(
            TelemetryOptions(
                endpoint="http://x",
                batch_size=1,
                on_error=lambda e: errors.append(e),
            )
        )
        try:
            c.record(_make_event())
            for _ in range(50):
                if errors:
                    break
                time.sleep(0.02)
            assert len(errors) == 1
            assert isinstance(errors[0], TelemetryHttpError)
            # batch was dropped, queue is now empty
            assert c.pending_count == 0
        finally:
            c.close()

    def test_close_is_idempotent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(client_module, "httpx", None)
        monkeypatch.setattr(
            client_module,
            "_post_sync_urllib",
            lambda *_a, **_kw: None,
        )
        c = TelemetryClient(TelemetryOptions(endpoint="http://x"))
        c.close()
        c.close()  # must not raise

    def test_record_after_close_is_noop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(client_module, "httpx", None)
        monkeypatch.setattr(
            client_module,
            "_post_sync_urllib",
            lambda *_a, **_kw: None,
        )
        c = TelemetryClient(TelemetryOptions(endpoint="http://x"))
        c.close()
        c.record(_make_event())
        assert c.pending_count == 0

    def test_batch_size_clamped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(client_module, "httpx", None)
        monkeypatch.setattr(
            client_module,
            "_post_sync_urllib",
            lambda *_a, **_kw: None,
        )
        # Out-of-range batch sizes get clamped to [1, 500].
        c = TelemetryClient(TelemetryOptions(endpoint="http://x", batch_size=99999))
        try:
            assert c._batch_size == 500
        finally:
            c.close()
        c2 = TelemetryClient(TelemetryOptions(endpoint="http://x", batch_size=0))
        try:
            assert c2._batch_size == 1
        finally:
            c2.close()

    def test_flush_interval_clamped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(client_module, "httpx", None)
        monkeypatch.setattr(
            client_module,
            "_post_sync_urllib",
            lambda *_a, **_kw: None,
        )
        c = TelemetryClient(TelemetryOptions(endpoint="http://x", flush_interval_ms=10))
        try:
            assert c._flush_interval_s == 0.5  # min 500ms
        finally:
            c.close()

    def test_payload_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def fake_post(endpoint: str, headers: dict, body: bytes, timeout: float) -> None:
            captured["endpoint"] = endpoint
            captured["headers"] = headers
            captured["body"] = body

        monkeypatch.setattr(client_module, "httpx", None)
        monkeypatch.setattr(client_module, "_post_sync_urllib", fake_post)

        c = TelemetryClient(
            TelemetryOptions(
                endpoint="http://example/v1/events",
                api_key="secret",
                workspace_id="ws_abc",
                batch_size=1,
            )
        )
        try:
            c.record(_make_event(decision="deny", status=403))
            for _ in range(50):
                if captured:
                    break
                time.sleep(0.02)
            assert captured["endpoint"] == "http://example/v1/events"
            assert captured["headers"]["authorization"] == "Bearer secret"
            assert captured["headers"]["x-workspace-id"] == "ws_abc"
            payload = captured["body"].decode()
            assert '"events"' in payload
            assert '"decision": "deny"' in payload
            assert '"status": 403' in payload
        finally:
            c.close()


# ─── Async AsyncTelemetryClient ────────────────────────────────────────────
#
# Async tests run via ``asyncio.run`` to avoid taking a test-time dependency on
# pytest-asyncio. Each test sets up its own event loop and the client tasks
# are torn down inside that loop so we don't leak.


class TestAsyncClient:
    def test_endpoint_required(self) -> None:
        async def go() -> None:
            with pytest.raises(TypeError):
                AsyncTelemetryClient(TelemetryOptions(endpoint=""))

        asyncio.run(go())

    def test_record_enqueues(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_async(endpoint: str, headers: dict, body: bytes, timeout: float) -> None:
            return None

        monkeypatch.setattr(client_module, "_post_async_httpx", fake_async)
        monkeypatch.setattr(
            client_module, "_post_sync_urllib", lambda *_a, **_kw: None
        )

        async def go() -> None:
            c = AsyncTelemetryClient(TelemetryOptions(endpoint="http://x", batch_size=10))
            try:
                c.record(_make_event())
                assert c.pending_count == 1
            finally:
                await c.close()

        asyncio.run(go())

    def test_flush_on_batch_size(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[bytes] = []

        async def fake_async(endpoint: str, headers: dict, body: bytes, timeout: float) -> None:
            captured.append(body)

        def fake_urllib(endpoint: str, headers: dict, body: bytes, timeout: float) -> None:
            # urllib path runs in an executor when httpx isn't installed
            captured.append(body)

        monkeypatch.setattr(client_module, "_post_async_httpx", fake_async)
        monkeypatch.setattr(client_module, "_post_sync_urllib", fake_urllib)

        async def go() -> None:
            c = AsyncTelemetryClient(TelemetryOptions(endpoint="http://x", batch_size=2))
            try:
                c.record(_make_event())
                c.record(_make_event())
                for _ in range(50):
                    if captured:
                        break
                    await asyncio.sleep(0.02)
                assert len(captured) == 1
            finally:
                await c.close()

        asyncio.run(go())

    def test_fail_open_calls_on_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        errors: list[Exception] = []

        async def boom_async(endpoint: str, headers: dict, body: bytes, timeout: float) -> None:
            raise TelemetryHttpError(500, "boom")

        def boom_sync(endpoint: str, headers: dict, body: bytes, timeout: float) -> None:
            raise TelemetryHttpError(500, "boom")

        monkeypatch.setattr(client_module, "_post_async_httpx", boom_async)
        monkeypatch.setattr(client_module, "_post_sync_urllib", boom_sync)

        async def go() -> None:
            c = AsyncTelemetryClient(
                TelemetryOptions(
                    endpoint="http://x",
                    batch_size=1,
                    on_error=lambda e: errors.append(e),
                )
            )
            try:
                c.record(_make_event())
                for _ in range(50):
                    if errors:
                        break
                    await asyncio.sleep(0.02)
                assert len(errors) == 1
                assert c.pending_count == 0
            finally:
                await c.close()

        asyncio.run(go())

    def test_close_idempotent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_async(*_a: Any, **_kw: Any) -> None:
            return None

        monkeypatch.setattr(client_module, "_post_async_httpx", fake_async)

        async def go() -> None:
            c = AsyncTelemetryClient(TelemetryOptions(endpoint="http://x"))
            await c.close()
            await c.close()  # must not raise

        asyncio.run(go())

    def test_record_after_close_is_noop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_async(*_a: Any, **_kw: Any) -> None:
            return None

        monkeypatch.setattr(client_module, "_post_async_httpx", fake_async)

        async def go() -> None:
            c = AsyncTelemetryClient(TelemetryOptions(endpoint="http://x"))
            await c.close()
            c.record(_make_event())
            assert c.pending_count == 0

        asyncio.run(go())
