"""
Tests for the telemetry middleware bridge (build_event, infer_decision,
extract_starlette_ip) and ArcisMiddleware integration with telemetry.
"""

from __future__ import annotations

from typing import Any

import pytest

from arcis.middleware.telemetry import (
    ArcisTelemetryMarker,
    build_event,
    extract_starlette_ip,
    infer_decision,
    threat_to_vector,
)


class TestInferDecision:
    @pytest.mark.parametrize(
        "status,expected",
        [
            (200, "allow"),
            (302, "allow"),
            (400, "deny"),
            (403, "deny"),
            (429, "deny"),
            (500, "allow"),  # 5xx is server error, not a security decision
        ],
    )
    def test_status_to_decision(self, status: int, expected: str) -> None:
        assert infer_decision(status) == expected


class TestThreatToVector:
    def test_known_threats_mapped(self) -> None:
        assert threat_to_vector("sql_injection") == "sql"
        assert threat_to_vector("nosql_injection") == "nosql"
        assert threat_to_vector("path_traversal") == "path"

    def test_unknown_passes_through(self) -> None:
        assert threat_to_vector("brand-new-vector") == "brand-new-vector"


class TestBuildEvent:
    def test_no_marker_uses_inferred_decision(self) -> None:
        event = build_event(
            ip="1.2.3.4",
            method="GET",
            path="/api",
            status=200,
            user_agent="ua",
            latency_ms=12.5,
            marker=None,
        )
        assert event.decision == "allow"
        assert event.vector is None
        assert event.latency_ms == 12.5
        assert event.user_agent == "ua"

    def test_marker_overrides_decision(self) -> None:
        marker = ArcisTelemetryMarker(
            vector="xss",
            rule="xss/match",
            severity="high",
            decision="deny",
            reason="caught script tag",
            matched_pattern="<script>",
        )
        event = build_event(
            ip="1.2.3.4",
            method="POST",
            path="/api",
            status=400,
            user_agent="",
            latency_ms=0.1,
            marker=marker,
        )
        assert event.decision == "deny"
        assert event.vector == "xss"
        assert event.severity == "high"
        assert event.matched_pattern == "<script>"
        assert event.reason == "caught script tag"

    def test_429_without_marker_attributes_to_rate_limit(self) -> None:
        event = build_event(
            ip="1.2.3.4",
            method="GET",
            path="/api",
            status=429,
            user_agent="",
            latency_ms=0.0,
            marker=None,
        )
        assert event.decision == "deny"
        assert event.vector == "rate-limit"
        assert event.rule == "rate-limit/exceeded"
        assert event.severity == "medium"

    def test_negative_latency_clamped(self) -> None:
        event = build_event(
            ip="1.2.3.4",
            method="GET",
            path="/",
            status=200,
            user_agent="",
            latency_ms=-5.0,
            marker=None,
        )
        assert event.latency_ms == 0.0

    def test_method_uppercased(self) -> None:
        event = build_event(
            ip="1.2.3.4",
            method="post",
            path="/api",
            status=200,
            user_agent="",
            latency_ms=0.0,
            marker=None,
        )
        assert event.method == "POST"

    def test_path_defaults_to_root(self) -> None:
        event = build_event(
            ip="1.2.3.4",
            method="GET",
            path="",
            status=200,
            user_agent="",
            latency_ms=0.0,
            marker=None,
        )
        assert event.path == "/"


class _StubClient:
    host: str

    def __init__(self, host: str) -> None:
        self.host = host


class _StubRequest:
    def __init__(self, headers: dict[str, str], client_host: str | None = None) -> None:
        self.headers = headers
        self.client = _StubClient(client_host) if client_host else None


class TestExtractIp:
    def test_x_forwarded_for_first_hop(self) -> None:
        req = _StubRequest({"x-forwarded-for": "203.0.113.5, 10.0.0.1, 10.0.0.2"})
        assert extract_starlette_ip(req) == "203.0.113.5"

    def test_x_real_ip(self) -> None:
        req = _StubRequest({"x-real-ip": "203.0.113.5"})
        assert extract_starlette_ip(req) == "203.0.113.5"

    def test_request_client_host(self) -> None:
        req = _StubRequest({}, client_host="198.51.100.10")
        assert extract_starlette_ip(req) == "198.51.100.10"

    def test_fallback_zero_ip(self) -> None:
        req = _StubRequest({})
        assert extract_starlette_ip(req) == "0.0.0.0"


# ─── ArcisMiddleware integration ────────────────────────────────────────────


class TestMiddlewareTelemetry:
    """Integration tests using Starlette TestClient.

    Skipped automatically when ``starlette`` isn't installed (e.g., on a bare
    install without the FastAPI deps).
    """

    def setup_method(self) -> None:
        starlette = pytest.importorskip("starlette")  # noqa: F841

    def test_telemetry_disabled_no_overhead(self) -> None:
        pytest.importorskip("starlette")
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient

        from arcis.fastapi import ArcisMiddleware

        def _ok(_request: Any) -> JSONResponse:
            return JSONResponse({"ok": True})

        app = Starlette(routes=[Route("/api", _ok, methods=["GET", "POST"])])
        app.add_middleware(
            ArcisMiddleware,
            sanitize=False,
            rate_limit=False,
            headers=False,
            error_handling=False,
            telemetry=None,
        )
        with TestClient(app) as client:
            resp = client.get("/api")
            assert resp.status_code == 200

    def test_telemetry_records_event(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pytest.importorskip("starlette")
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient

        from arcis.fastapi import ArcisMiddleware
        from arcis.telemetry import client as client_module

        captured: list[bytes] = []

        async def fake_async(endpoint: str, headers: dict, body: bytes, timeout: float) -> None:
            captured.append(body)

        def fake_urllib(endpoint: str, headers: dict, body: bytes, timeout: float) -> None:
            captured.append(body)

        monkeypatch.setattr(client_module, "_post_async_httpx", fake_async)
        monkeypatch.setattr(client_module, "_post_sync_urllib", fake_urllib)

        def _ok(_request: Any) -> JSONResponse:
            return JSONResponse({"ok": True})

        app = Starlette(routes=[Route("/api", _ok, methods=["GET", "POST"])])
        app.add_middleware(
            ArcisMiddleware,
            sanitize=False,
            rate_limit=False,
            headers=False,
            error_handling=False,
            telemetry={"endpoint": "http://x/v1/events", "batch_size": 1},
        )
        with TestClient(app) as client:
            resp = client.get("/api")
            assert resp.status_code == 200

        import time as _time

        for _ in range(50):
            if captured:
                break
            _time.sleep(0.02)

        assert len(captured) >= 1
        payload = captured[0].decode()
        assert '"events"' in payload
        assert '"path": "/api"' in payload
        assert '"method": "GET"' in payload
        assert '"decision": "allow"' in payload
