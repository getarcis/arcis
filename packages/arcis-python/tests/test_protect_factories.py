"""Tests for the per-framework protect factories (improvements.md §1.4).

The factories are thin wrappers that compose the existing composite
login / signup / api checks with a shared CorrelationWindow, auto-extract
the client IP and route from the framework request, and map a denial to
the framework's standard error response.

Framework-agnostic glue is tested unconditionally. FastAPI tests run when
FastAPI + httpx are installed (they are in CI). Litestar and Django tests
are guarded with ``pytest.importorskip`` so they no-op when the framework
is absent from the dev environment.
"""

import pytest

from arcis.middleware.correlation import CorrelationWindow
from arcis.middleware.protect_factories import (
    DEFAULT_API_RATE_LIMIT,
    DEFAULT_LOGIN_RATE_LIMIT,
    DEFAULT_SIGNUP_RATE_LIMIT,
    block_status_code,
    client_ip_from_xff_then,
    signup_check_with_correlation,
)


# ============================================================================
# FRAMEWORK-AGNOSTIC GLUE
# ============================================================================


class _DictRequest:
    """Minimal request shim exposing a dict body + headers mapping."""

    def __init__(self, body=None, headers=None):
        self.body = body or {}
        self.headers = headers or {}


def test_block_status_code_maps_correlation_to_429():
    assert block_status_code("correlation") == 429
    assert block_status_code("rate_limited") == 429


def test_block_status_code_maps_bot_to_403():
    assert block_status_code("bot") == 403
    assert block_status_code("bad_origin") == 403
    assert block_status_code("threat") == 403


def test_block_status_code_maps_input_errors_to_400():
    assert block_status_code("missing_credentials") == 400
    assert block_status_code("missing_email") == 400
    assert block_status_code("invalid_email") == 400
    assert block_status_code("disposable_email") == 400


def test_client_ip_honors_xff_first_hop():
    assert client_ip_from_xff_then("1.2.3.4, 10.0.0.1", "127.0.0.1") == "1.2.3.4"


def test_client_ip_falls_back_to_socket_peer():
    assert client_ip_from_xff_then(None, "203.0.113.7") == "203.0.113.7"
    assert client_ip_from_xff_then("", "203.0.113.7") == "203.0.113.7"


def test_client_ip_none_when_no_source():
    assert client_ip_from_xff_then(None, None) is None
    assert client_ip_from_xff_then("  ", None) is None


def test_default_rate_limit_tuples_match_node_table():
    # Node protect helper defaults: login 5/min, signup 3/min, api 100/min.
    assert DEFAULT_LOGIN_RATE_LIMIT == (5, 60_000)
    assert DEFAULT_SIGNUP_RATE_LIMIT == (3, 60_000)
    assert DEFAULT_API_RATE_LIMIT == (100, 60_000)


def test_signup_check_records_into_window():
    window = CorrelationWindow()
    req = _DictRequest(body={"email": "alice@example.com"})
    result = signup_check_with_correlation(
        req,
        correlation_window=window,
        client_ip="1.2.3.4",
        route="/signup",
        check_bot=False,
    )
    assert result.allowed is True
    assert window.stats()["events_in_window"] == 1


def test_signup_check_blocks_on_credential_stuffing_shape():
    # Many distinct emails from one IP at one signup route trip the
    # credential-stuffing detector.
    window = CorrelationWindow(credential_stuffing_distinct_values=3)
    for i in range(2):
        req = _DictRequest(body={"email": f"user{i}@example.com"})
        result = signup_check_with_correlation(
            req,
            correlation_window=window,
            client_ip="9.9.9.9",
            route="/signup",
            check_bot=False,
        )
        assert result.allowed is True

    req = _DictRequest(body={"email": "user2@example.com"})
    result = signup_check_with_correlation(
        req,
        correlation_window=window,
        client_ip="9.9.9.9",
        route="/signup",
        check_bot=False,
    )
    assert result.allowed is False
    assert result.reason == "correlation"
    assert result.details["credential_stuffing"] is True


def test_signup_check_base_denial_is_not_overridden_by_correlation():
    # A missing email fails the base check; the correlation window must
    # not be consulted (and so must not record) on a base denial.
    window = CorrelationWindow()
    req = _DictRequest(body={})
    result = signup_check_with_correlation(
        req,
        correlation_window=window,
        client_ip="1.2.3.4",
        route="/signup",
        check_bot=False,
    )
    assert result.allowed is False
    assert result.reason == "missing_email"
    assert window.stats()["events_in_window"] == 0


# ============================================================================
# FASTAPI / STARLETTE
# ============================================================================

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from arcis.fastapi import (  # noqa: E402
    protect_api as fastapi_protect_api,
    protect_login as fastapi_protect_login,
    protect_signup as fastapi_protect_signup,
)


def _fastapi_login_app(window=None):
    app = FastAPI()
    guard = fastapi_protect_login(
        check_bot=False,
        correlation_window=window,
        route="/login",
    )

    @app.post("/login")
    async def login(_result=Depends(guard)):
        return {"status": "ok"}

    return app


def test_fastapi_login_legit_request_passes():
    client = TestClient(_fastapi_login_app())
    resp = client.post("/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_fastapi_login_credential_stuffing_returns_429():
    window = CorrelationWindow(credential_stuffing_distinct_values=3)
    client = TestClient(_fastapi_login_app(window))
    # First two distinct usernames pass.
    for i in range(2):
        resp = client.post(
            "/login",
            json={"username": f"user{i}", "password": "pw"},
            headers={"X-Forwarded-For": "9.9.9.9"},
        )
        assert resp.status_code == 200
    # Third distinct username from the same forwarded IP trips the window.
    resp = client.post(
        "/login",
        json={"username": "user2", "password": "pw"},
        headers={"X-Forwarded-For": "9.9.9.9"},
    )
    assert resp.status_code == 429
    assert resp.json()["detail"]["error"] == "correlation"


def test_fastapi_login_ip_extraction_honors_xff():
    # Two requests with DIFFERENT forwarded IPs must NOT share a
    # credential-stuffing bucket; the XFF first hop is the bucket key.
    window = CorrelationWindow(credential_stuffing_distinct_values=2)
    client = TestClient(_fastapi_login_app(window))
    resp_a = client.post(
        "/login",
        json={"username": "a", "password": "pw"},
        headers={"X-Forwarded-For": "1.1.1.1"},
    )
    resp_b = client.post(
        "/login",
        json={"username": "b", "password": "pw"},
        headers={"X-Forwarded-For": "2.2.2.2"},
    )
    assert resp_a.status_code == 200
    assert resp_b.status_code == 200
    # The window saw two distinct IPs, each with one event.
    assert window.stats()["tracked_ips"] == 2


def test_fastapi_shared_window_across_two_factory_instances():
    # A login factory and a separate api factory sharing one window must
    # accumulate cross-route scanner pressure on the same IP.
    window = CorrelationWindow(
        scanner_distinct_vectors=2,
        scanner_min_requests=3,
    )
    app = FastAPI()
    login_guard = fastapi_protect_login(
        check_bot=False, correlation_window=window, route="/login"
    )
    api_guard = fastapi_protect_api(
        check_bot=False, correlation_window=window, route="/api"
    )

    @app.post("/login")
    async def login(_r=Depends(login_guard)):
        return {"ok": "login"}

    @app.post("/api")
    async def api(_r=Depends(api_guard)):
        return {"ok": "api"}

    client = TestClient(app)
    # Seed two cross-vector events on the shared IP via the window directly
    # (simulating prior XSS + SQL hits), then a clean login crosses the
    # scanner threshold because the window state is shared.
    window.record("7.7.7.7", "xss", "/api", "POST")
    window.record("7.7.7.7", "sql", "/api", "POST")
    resp = client.post(
        "/login",
        json={"username": "alice", "password": "pw"},
        headers={"X-Forwarded-For": "7.7.7.7"},
    )
    assert resp.status_code == 429
    assert resp.json()["detail"]["error"] == "correlation"


def test_fastapi_signup_legit_request_passes():
    app = FastAPI()
    guard = fastapi_protect_signup(check_bot=False, route="/signup")

    @app.post("/signup")
    async def signup(_r=Depends(guard)):
        return {"status": "ok"}

    client = TestClient(app)
    resp = client.post("/signup", json={"email": "alice@example.com"})
    assert resp.status_code == 200


def test_fastapi_signup_credential_stuffing_returns_429():
    window = CorrelationWindow(credential_stuffing_distinct_values=2)
    app = FastAPI()
    guard = fastapi_protect_signup(
        check_bot=False, correlation_window=window, route="/signup"
    )

    @app.post("/signup")
    async def signup(_r=Depends(guard)):
        return {"status": "ok"}

    client = TestClient(app)
    resp1 = client.post(
        "/signup",
        json={"email": "one@example.com"},
        headers={"X-Forwarded-For": "5.5.5.5"},
    )
    assert resp1.status_code == 200
    resp2 = client.post(
        "/signup",
        json={"email": "two@example.com"},
        headers={"X-Forwarded-For": "5.5.5.5"},
    )
    assert resp2.status_code == 429
    assert resp2.json()["detail"]["error"] == "correlation"


def test_fastapi_api_threat_body_returns_403():
    app = FastAPI()
    guard = fastapi_protect_api(check_bot=False, route="/api")

    @app.post("/api")
    async def api(_r=Depends(guard)):
        return {"status": "ok"}

    client = TestClient(app)
    resp = client.post("/api", json={"comment": "<script>alert(1)</script>"})
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "threat"


def test_fastapi_api_legit_request_passes():
    app = FastAPI()
    guard = fastapi_protect_api(check_bot=False, route="/api")

    @app.post("/api")
    async def api(_r=Depends(guard)):
        return {"status": "ok"}

    client = TestClient(app)
    resp = client.post("/api", json={"hello": "world"})
    assert resp.status_code == 200


# ============================================================================
# LITESTAR
# ============================================================================


def test_litestar_protect_factories():
    litestar = pytest.importorskip("litestar")
    from typing import Any as _Any

    from litestar import Litestar, post
    from litestar.testing import TestClient as LitestarTestClient

    from arcis.litestar import (
        protect_login as litestar_protect_login,
    )

    window = CorrelationWindow(credential_stuffing_distinct_values=3)
    guard = litestar_protect_login(
        check_bot=False, correlation_window=window, route="/login"
    )

    # Litestar injects dependencies by name; the param needs a type
    # annotation (Any is fine) and the dependency must be wrapped with
    # Provide so the factory's coroutine is awaited per request.
    from litestar.di import Provide

    @post("/login", dependencies={"_guard": Provide(guard)})
    async def login(_guard: _Any, data: dict) -> dict:
        return {"status": "ok"}

    app = Litestar(route_handlers=[login])
    with LitestarTestClient(app=app) as client:
        # Legit request passes.
        resp = client.post("/login", json={"username": "alice", "password": "pw"})
        assert resp.status_code == 201  # Litestar POST default is 201

        # Credential stuffing trips 429.
        for i in range(2):
            r = client.post(
                "/login",
                json={"username": f"user{i}", "password": "pw"},
                headers={"X-Forwarded-For": "9.9.9.9"},
            )
            assert r.status_code == 201
        blocked = client.post(
            "/login",
            json={"username": "user2", "password": "pw"},
            headers={"X-Forwarded-For": "9.9.9.9"},
        )
        assert blocked.status_code == 429


# ============================================================================
# DJANGO
# ============================================================================


def test_django_protect_factories():
    pytest.importorskip("django")
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            DEBUG=True,
            ALLOWED_HOSTS=["testserver", "localhost"],
            ROOT_URLCONF=__name__,
            SECRET_KEY="test-only-not-a-secret",
        )
        import django

        django.setup()

    import json as _json

    from django.http import JsonResponse
    from django.test import RequestFactory

    from arcis.django import (
        protect_login as django_protect_login,
        protect_api as django_protect_api,
    )

    window = CorrelationWindow(credential_stuffing_distinct_values=3)

    @django_protect_login(
        check_bot=False, correlation_window=window, route="/login"
    )
    def login_view(request):
        return JsonResponse({"status": "ok"})

    rf = RequestFactory()

    def _post(username, ip):
        req = rf.post(
            "/login",
            data=_json.dumps({"username": username, "password": "pw"}),
            content_type="application/json",
            HTTP_X_FORWARDED_FOR=ip,
        )
        return login_view(req)

    # Legit request passes.
    resp = _post("alice", "1.2.3.4")
    assert resp.status_code == 200

    # Credential stuffing from one IP trips 429.
    assert _post("u0", "9.9.9.9").status_code == 200
    assert _post("u1", "9.9.9.9").status_code == 200
    blocked = _post("u2", "9.9.9.9")
    assert blocked.status_code == 429
    assert _json.loads(blocked.content)["error"] == "correlation"

    # Shared window: an api decorator on the same window sees the same IP
    # state. A threat body returns 403 regardless of correlation.
    @django_protect_api(check_bot=False, correlation_window=window, route="/api")
    def api_view(request):
        return JsonResponse({"status": "ok"})

    threat_req = rf.post(
        "/api",
        data=_json.dumps({"comment": "<script>alert(1)</script>"}),
        content_type="application/json",
        HTTP_X_FORWARDED_FOR="3.3.3.3",
    )
    threat_resp = api_view(threat_req)
    assert threat_resp.status_code == 403
    assert _json.loads(threat_resp.content)["error"] == "threat"
