"""
FastAPI block-mode integration tests.

When ArcisMiddleware is constructed with ``block=True``, requests carrying
attack patterns must receive a 403 response without reaching the handler.
"""

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from arcis.fastapi import ArcisMiddleware


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(ArcisMiddleware, block=True, rate_limit=False)

    @app.get("/")
    async def root():
        return {"ok": True}

    @app.post("/echo")
    async def echo(payload: dict):
        return {"received": payload}

    @app.get("/items")
    async def items():
        return {"ok": True}

    return app


@pytest.fixture
def client():
    return TestClient(_make_app())


def test_clean_request_passes(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_clean_post_body_passes(client):
    r = client.post("/echo", json={"name": "alice", "age": 30})
    assert r.status_code == 200
    assert r.json()["received"]["name"] == "alice"


@pytest.mark.parametrize(
    "payload,expected_vector",
    [
        ({"q": "<script>alert(1)</script>"}, "xss"),
        ({"q": "1' OR '1'='1'"}, "sql"),
        ({"q": "../../etc/passwd"}, "path"),
        ({"q": "$(whoami)"}, "command"),
        ({"$where": "function() { return true }"}, "nosql"),
        ({"__proto__": {"polluted": True}}, "prototype"),
    ],
)
def test_attack_payload_blocked(client, payload, expected_vector):
    r = client.post("/echo", json=payload)
    assert r.status_code == 403, r.text
    body = r.json()
    assert body["code"] == "SECURITY_THREAT"
    assert body["vector"] == expected_vector


def test_xss_in_query_string_blocked(client):
    r = client.get("/items", params={"q": "<script>alert(1)</script>"})
    assert r.status_code == 403
    assert r.json()["vector"] == "xss"


def test_path_traversal_in_url_path_blocked(client):
    # Starlette resolves ../ on the URL, but the raw path on the request
    # object still carries the bypass form; this asserts our path scan.
    r = client.get("/items", params={"file": "....//etc/passwd"})
    assert r.status_code == 403
    assert r.json()["vector"] == "path"


def test_block_disabled_by_default():
    """Default middleware (block=False) must still allow attack payloads
    through to the handler — we only sanitize silently. This is the v1.4.3
    behavior we are preserving for opt-in safety."""
    app = FastAPI()
    app.add_middleware(ArcisMiddleware, rate_limit=False)

    @app.post("/echo")
    async def echo(payload: dict):
        return {"received": payload}

    c = TestClient(app)
    r = c.post("/echo", json={"q": "<script>alert(1)</script>"})
    assert r.status_code == 200


@pytest.mark.parametrize(
    "payload,expected_vector",
    [
        ({"q": "<script>alert(1)</script>"}, "xss"),
        ({"q": "{{ 7 * 7 }}"}, "ssti"),
        ({"q": "<!DOCTYPE foo [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>"}, "xxe"),
    ],
)
def test_extended_vectors_blocked(payload, expected_vector):
    """SSTI and XXE landed in `vector=null` before — verify scan_threats
    now classifies them under the extended block-mode taxonomy."""
    app = FastAPI()
    app.add_middleware(ArcisMiddleware, block=True, rate_limit=False)

    @app.post("/echo")
    async def echo(p: dict):
        return p

    r = TestClient(app).post("/echo", json=payload)
    assert r.status_code == 403, r.text
    assert r.json()["vector"] == expected_vector


def test_telemetry_marker_records_block_decision():
    """Regression: prior to this fix Python's name-mangling rewrote
    ``request.state.__arcis`` to ``_ArcisMiddleware__arcis`` on assignment
    while the reader looked up the literal ``__arcis``, so block-mode
    decisions never reached the dashboard. Captures the recorded event
    and asserts ``vector=xss``, ``decision=deny``."""
    from arcis.telemetry.client import AsyncTelemetryClient
    from arcis.telemetry.types import TelemetryOptions

    captured = []

    class _Capture(AsyncTelemetryClient):
        def record(self, event):  # type: ignore[override]
            captured.append(event)

    client = _Capture(TelemetryOptions(endpoint="http://localhost:9999/v1/events"))

    app = FastAPI()
    app.add_middleware(
        ArcisMiddleware, block=True, rate_limit=False, telemetry=client
    )

    @app.post("/echo")
    async def echo(p: dict):
        return p

    r = TestClient(app).post("/echo", json={"q": "<script>alert(1)</script>"})
    assert r.status_code == 403
    assert len(captured) == 1, f"expected 1 event, got {captured}"
    ev = captured[0]
    assert ev.decision == "deny"
    assert ev.vector == "xss"
    assert ev.status == 403
