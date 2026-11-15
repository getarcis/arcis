"""
Baseline security-header profile through each Python adapter.

Every adapter runs a real app through the framework's own test client (or a
RequestFactory for Django) and must put the baseline headers on the wire,
keep headers the route set, strip X-Powered-By unless configured to keep it,
expose the CSP nonce before the handler runs and pass the framework request
object to callable CSP directive values.
"""

import json
import re
from typing import Any, Callable, Dict, NamedTuple

import pytest

from arcis.middleware.headers import SecurityHeaders
from tests.conformance.test_security_headers_baseline import BASELINE, DEFAULT_HEADERS


ROUTE_SETS: Dict[str, str] = BASELINE["route_header_wins"]["route_sets"]
DEFAULTS_CASE = next(case for case in BASELINE["cases"] if case["name"] == "defaults")
NONCE_IN_CSP = re.compile(r"'nonce-([A-Za-z0-9+/]{22}==)'")
API_SOURCE = "https://api.example.com"


class Wire(NamedTuple):
    status: int
    headers: Dict[str, str]  # lower-case names
    body: Any


Client = Callable[[str], Wire]


def _baseline(options: Dict[str, Any]) -> Dict[str, Any]:
    return {"profile": "baseline", **options}


# ─── One small app per adapter: /, /route-set, /nonce ───────────────────

def _fastapi_client(options: Dict[str, Any], raise_server_exceptions: bool = True) -> Client:
    pytest.importorskip("fastapi")
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    from arcis.fastapi import ArcisMiddleware

    app = FastAPI()
    app.add_middleware(ArcisMiddleware, headers=_baseline(options), rate_limit=False)

    @app.get("/")
    async def index() -> Dict[str, Any]:
        return {"ok": True}

    @app.get("/route-set")
    async def route_set() -> JSONResponse:
        return JSONResponse({"ok": True}, headers={**ROUTE_SETS, "X-Powered-By": "app"})

    @app.get("/nonce")
    async def nonce(request: Request) -> Dict[str, Any]:
        return {"nonce": request.state.csp_nonce}

    client = TestClient(app, raise_server_exceptions=raise_server_exceptions)

    def get(path: str) -> Wire:
        response = client.get(path)
        body = response.json() if response.status_code == 200 else None
        return Wire(response.status_code, {k.lower(): v for k, v in response.headers.items()}, body)

    return get


def _flask_client(options: Dict[str, Any]) -> Client:
    pytest.importorskip("flask")
    from flask import Flask, g, jsonify

    from arcis import Arcis

    app = Flask(__name__)
    app.config["TESTING"] = True
    Arcis(app, headers=_baseline(options), rate_limit=False)

    @app.route("/")
    def index():
        return jsonify(ok=True)

    @app.route("/route-set")
    def route_set():
        response = jsonify(ok=True)
        response.headers.update({**ROUTE_SETS, "X-Powered-By": "app"})
        return response

    @app.route("/nonce")
    def nonce():
        return jsonify(nonce=g.csp_nonce)

    client = app.test_client()

    def get(path: str) -> Wire:
        response = client.get(path)
        headers = {k.lower(): v for k, v in response.headers.items()}
        return Wire(response.status_code, headers, response.get_json())

    return get


def _django_ready() -> None:
    pytest.importorskip("django")
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            DEBUG=True,
            DATABASES={},
            INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth"],
            MIDDLEWARE=[],
            ROOT_URLCONF="",
            SECRET_KEY="test-secret-key-for-arcis-tests",
        )
        django.setup()


def _django_view(request):
    from django.http import JsonResponse

    if request.path == "/route-set":
        response = JsonResponse({"ok": True})
        for name, value in {**ROUTE_SETS, "X-Powered-By": "app"}.items():
            response[name] = value
        return response
    if request.path == "/nonce":
        return JsonResponse({"nonce": request.csp_nonce})
    return JsonResponse({"ok": True})


def _django_client(options: Dict[str, Any], middleware_name: str = "ArcisMiddleware") -> Client:
    _django_ready()
    from django.test import RequestFactory, override_settings

    from arcis import django as arcis_django

    middleware_class = getattr(arcis_django, middleware_name)
    with override_settings(ARCIS_CONFIG={"headers": _baseline(options), "rate_limit": False}):
        middleware = middleware_class(_django_view)
    factory = RequestFactory()

    def get(path: str) -> Wire:
        response = middleware(factory.get(path))
        headers = {k.lower(): v for k, v in response.headers.items()}
        return Wire(response.status_code, headers, json.loads(response.content))

    return get


def _litestar_client(options: Dict[str, Any]) -> Client:
    pytest.importorskip("litestar")
    from litestar import Litestar, Request, Response, get as route
    from litestar.middleware.base import DefineMiddleware
    from litestar.testing import TestClient

    from arcis.litestar import ArcisMiddleware

    @route("/")
    async def index() -> Dict[str, Any]:
        return {"ok": True}

    @route("/route-set")
    async def route_set() -> Response:
        return Response({"ok": True}, headers={**ROUTE_SETS, "X-Powered-By": "app"})

    @route("/nonce")
    async def nonce(request: Request) -> Dict[str, Any]:
        return {"nonce": request.state.csp_nonce}

    app = Litestar(
        route_handlers=[index, route_set, nonce],
        middleware=[DefineMiddleware(ArcisMiddleware, headers=_baseline(options), rate_limit=False)],
    )
    client = TestClient(app)

    def get(path: str) -> Wire:
        response = client.get(path)
        headers = {k.lower(): v for k, v in response.headers.items()}
        return Wire(response.status_code, headers, response.json())

    return get


def _request_class(adapter: str) -> type:
    if adapter == "fastapi":
        from starlette.requests import Request
    elif adapter == "flask":
        from flask import Request
    elif adapter == "django":
        from django.http import HttpRequest as Request
    else:
        from litestar import Request
    return Request


ADAPTERS: Dict[str, Callable[[Dict[str, Any]], Client]] = {
    "fastapi": _fastapi_client,
    "flask": _flask_client,
    "django": _django_client,
    "django-headers-only": lambda options: _django_client(options, "ArcisHeadersMiddleware"),
    "litestar": _litestar_client,
}


@pytest.fixture(params=sorted(ADAPTERS))
def adapter(request) -> str:
    return request.param


def _client(adapter: str, options: Dict[str, Any]) -> Client:
    return ADAPTERS[adapter](options)


# ─── Wire behavior, every adapter ───────────────────────────────────────

def test_baseline_defaults_on_the_wire(adapter):
    wire = _client(adapter, {})("/")

    assert wire.status == 200
    for name, value in DEFAULT_HEADERS.items():
        assert wire.headers.get(name) == value, name
    for name in DEFAULTS_CASE["expected_absent"]:
        assert name.lower() not in wire.headers


def test_route_set_headers_are_kept(adapter):
    wire = _client(adapter, {})("/route-set")

    for name, value in BASELINE["route_header_wins"]["expected_headers"].items():
        assert wire.headers[name.lower()] == value
    assert wire.headers["referrer-policy"] == DEFAULT_HEADERS["referrer-policy"]


def test_x_powered_by_removed_by_default(adapter):
    assert "x-powered-by" not in _client(adapter, {})("/route-set").headers


def test_x_powered_by_kept_when_disabled(adapter):
    wire = _client(adapter, {"x_powered_by": False})("/route-set")
    assert wire.headers["x-powered-by"] == "app"


def test_configured_options_reach_the_wire(adapter):
    get = _client(adapter, {
        "x_frame_options": {"action": "deny"},
        "strict_transport_security": {"max_age": 63072000, "preload": True},
        "cross_origin_embedder_policy": True,
    })
    wire = get("/")

    assert wire.headers["x-frame-options"] == "DENY"
    assert wire.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains; preload"
    assert wire.headers["cross-origin-embedder-policy"] == "require-corp"


def test_nonce_exposed_to_handler_equals_header(adapter):
    get = _client(adapter, {"content_security_policy": {"nonce": True}})
    first = get("/nonce")
    second = get("/nonce")

    for wire in (first, second):
        match = NONCE_IN_CSP.search(wire.headers["content-security-policy"])
        assert match is not None
        assert wire.body["nonce"] == match.group(1)
    assert first.body["nonce"] != second.body["nonce"]


def test_callable_directive_receives_the_framework_request(adapter):
    seen = []

    def api_source(request: Any) -> str:
        # __class__ (not type()) so Flask's request proxy reports the real class.
        seen.append(request.__class__)
        return API_SOURCE

    get = _client(adapter, {"content_security_policy": {"directives": {"connectSrc": ["'self'", api_source]}}})
    wire = get("/")

    assert wire.headers["content-security-policy"].endswith(f";connect-src 'self' {API_SOURCE}")
    assert len(seen) == 1
    assert issubclass(seen[0], _request_class(adapter.split("-")[0]))


# ─── Adapter-specific behavior ──────────────────────────────────────────

def test_fastapi_invalid_callable_result_is_a_server_error():
    get = _fastapi_client(
        {"content_security_policy": {"directives": {"script-src": [lambda request: "self"]}}},
        raise_server_exceptions=False,
    )
    assert get("/").status == 500


def test_fastapi_accepts_a_security_headers_instance():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from arcis.fastapi import ArcisMiddleware

    app = FastAPI()
    app.add_middleware(
        ArcisMiddleware,
        security_headers=SecurityHeaders(profile="baseline", referrer_policy={"policy": "origin"}),
        rate_limit=False,
    )

    @app.get("/")
    async def index() -> Dict[str, Any]:
        return {"ok": True}

    response = TestClient(app).get("/")
    assert response.headers["referrer-policy"] == "origin"
    assert response.headers["x-frame-options"] == "SAMEORIGIN"


def test_invalid_options_fail_when_the_adapter_is_constructed():
    pytest.importorskip("flask")
    from flask import Flask

    from arcis import Arcis

    with pytest.raises(ValueError, match="does not support"):
        Arcis(Flask(__name__), headers=_baseline({"cross_origin_opener_policy": {"policy": "isolate"}}))


def test_legacy_adapters_still_overwrite_route_headers():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    from arcis.fastapi import ArcisMiddleware

    app = FastAPI()
    app.add_middleware(ArcisMiddleware, rate_limit=False)

    @app.get("/")
    async def index() -> JSONResponse:
        return JSONResponse({"ok": True}, headers={"X-Frame-Options": "SAMEORIGIN"})

    response = TestClient(app).get("/")
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"].startswith("no-store")


def test_generic_arcis_wrapper_on_fastapi_honours_headers_false():
    """Arcis(app, headers=False) on FastAPI must send no Arcis security headers."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from arcis import Arcis

    app = FastAPI()

    @app.get("/")
    def index():
        return {"ok": True}

    Arcis(app, headers=False, rate_limit=False)
    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert "content-security-policy" not in response.headers
    assert "x-frame-options" not in response.headers


def test_generic_arcis_wrapper_on_fastapi_passes_baseline_profile():
    """Arcis(app, headers={"profile": "baseline"}) on FastAPI sends the baseline defaults."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from arcis import Arcis

    app = FastAPI()

    @app.get("/")
    def index():
        return {"ok": True}

    Arcis(app, headers={"profile": "baseline"}, rate_limit=False)
    response = TestClient(app).get("/")
    for name, value in DEFAULT_HEADERS.items():
        assert response.headers.get(name) == value, name
