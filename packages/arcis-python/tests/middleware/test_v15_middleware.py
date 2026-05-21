"""
End-to-end tests for the four Phase B middleware modules:
mass_assignment, method_allowlist, response_splitting, graphql.

Uses Starlette TestClient which works against any ASGI app. The same
middleware mounts unchanged on FastAPI / Litestar / Quart — the
contract is ASGI, not framework-specific.
"""

import json

import pytest

from starlette.applications import Starlette
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

from arcis.middleware.graphql import GraphqlGuardMiddleware
from arcis.middleware.mass_assignment import (
    MassAssignMiddleware,
    apply_mass_assign_filter,
)
from arcis.middleware.method_allowlist import (
    METHOD_OVERRIDE_HEADERS,
    MethodAllowlistMiddleware,
    check_method,
)
from arcis.middleware.response_splitting import (
    ResponseSplittingError,
    ResponseSplittingMiddleware,
    sanitize_response_headers,
)
from arcis.sanitizers.graphql import GraphqlGuardOptions


# ── mass-assign ────────────────────────────────────────────────────────


class TestMassAssignPureFunction:
    def test_strips_disallowed_keys(self):
        result = apply_mass_assign_filter(
            {"email": "x@y.z", "is_admin": True, "role": "admin"},
            allow=["email", "name"],
        )
        assert result.filtered == {"email": "x@y.z"}
        assert sorted(result.disallowed) == ["is_admin", "role"]
        assert result.body_type == "dict"

    def test_empty_allowlist_raises(self):
        with pytest.raises(ValueError):
            apply_mass_assign_filter({"a": 1}, allow=[])

    def test_non_dict_body_returns_none_filtered(self):
        for body in [["a", "b"], "raw-string", b"bytes", None]:
            result = apply_mass_assign_filter(body, allow=["k"])
            assert result.filtered is None
            assert result.disallowed == []


class TestMassAssignMiddlewareStripMode:
    def _build(self, allow, mode="strip"):
        async def echo(request):
            body = await request.body()
            # Try JSON; if not JSON (form-encoded etc.) echo as text.
            try:
                parsed = json.loads(body) if body else None
            except (json.JSONDecodeError, UnicodeDecodeError):
                return Response(body, media_type="text/plain")
            return JSONResponse({"received": parsed})

        app = Starlette(routes=[Route("/echo", echo, methods=["POST"])])
        app.add_middleware(MassAssignMiddleware, allow=allow, mode=mode)
        return TestClient(app)

    def test_disallowed_keys_stripped_in_strip_mode(self):
        client = self._build(allow=["email"])
        r = client.post("/echo", json={"email": "x@y.z", "is_admin": True})
        assert r.status_code == 200
        assert r.json() == {"received": {"email": "x@y.z"}}

    def test_allowed_keys_pass_through(self):
        client = self._build(allow=["email", "name"])
        r = client.post("/echo", json={"email": "x@y.z", "name": "Jane"})
        assert r.status_code == 200
        assert r.json()["received"] == {"email": "x@y.z", "name": "Jane"}

    def test_reject_mode_returns_400(self):
        client = self._build(allow=["email"], mode="reject")
        r = client.post("/echo", json={"email": "x@y.z", "is_admin": True})
        assert r.status_code == 400
        body = r.json()
        assert body["error"] == "Disallowed fields"
        assert body["fields"] == ["is_admin"]

    def test_non_json_content_type_passes_through(self):
        client = self._build(allow=["email"])
        r = client.post(
            "/echo",
            data="raw=string",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        # Body is form-encoded, not JSON — middleware does NOT touch it.
        # The route handler receives the raw bytes.
        assert r.status_code == 200

    def test_non_dict_json_passes_through(self):
        # A JSON array body is mass-assignment-irrelevant (no top-level
        # keys to filter), so it flows through unchanged.
        client = self._build(allow=["email"])
        r = client.post("/echo", json=["array", "body"])
        assert r.status_code == 200


# ── method-allowlist ──────────────────────────────────────────────────


class TestMethodCheckPureFunction:
    def test_default_methods(self):
        for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
            r = check_method(m, [])
            assert r.allowed is True
            assert r.method == m

    def test_trace_and_connect_rejected_by_default(self):
        assert check_method("TRACE", []).allowed is False
        assert check_method("CONNECT", []).allowed is False

    def test_custom_allowlist(self):
        assert check_method("DELETE", [], allow=["GET", "POST"]).allowed is False
        assert check_method("get", [], allow=["GET"]).allowed is True

    def test_override_headers_detected(self):
        r = check_method(
            "GET",
            [(b"x-http-method-override", b"DELETE")],
        )
        assert r.stripped_headers == ["x-http-method-override"]

    def test_no_override_headers(self):
        r = check_method("GET", [(b"x-real-ip", b"1.2.3.4")])
        assert r.stripped_headers == []


class TestMethodAllowlistMiddleware:
    def _build(self, allow=None):
        async def echo(request):
            return JSONResponse({"method": request.method})

        # Accept all methods on the route so middleware controls denial.
        all_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "TRACE", "OPTIONS"]
        app = Starlette(
            routes=[Route("/echo", echo, methods=all_methods)],
        )
        kwargs = {"allow": allow} if allow is not None else {}
        app.add_middleware(MethodAllowlistMiddleware, **kwargs)
        return TestClient(app)

    def test_get_allowed_by_default(self):
        client = self._build()
        r = client.get("/echo")
        assert r.status_code == 200
        assert r.json() == {"method": "GET"}

    def test_trace_blocked_by_default(self):
        client = self._build()
        # TestClient supports request() for arbitrary methods.
        r = client.request("TRACE", "/echo")
        assert r.status_code == 405
        body = r.json()
        assert body["error"] == "Method not allowed"
        assert body["method"] == "TRACE"
        # RFC 9110 §15.5.6: Allow header lists permitted methods.
        assert "GET" in r.headers["allow"]

    def test_custom_allowlist_rejects_outside_set(self):
        client = self._build(allow=["GET"])
        r = client.post("/echo")
        assert r.status_code == 405
        assert "GET" in r.headers["allow"]
        assert "POST" not in r.headers["allow"]

    def test_method_override_header_does_not_change_method(self):
        client = self._build(allow=["GET"])
        # Sending X-HTTP-Method-Override: DELETE should NOT let the
        # request through as DELETE — the middleware strips that header
        # before the route handler sees it.
        r = client.get("/echo", headers={"x-http-method-override": "DELETE"})
        assert r.status_code == 200
        # Echo route reports the actual method (GET), not the override.
        assert r.json() == {"method": "GET"}


# ── response-splitting ─────────────────────────────────────────────────


class TestSanitizeResponseHeadersPure:
    def test_clean_headers_pass_through(self):
        headers = [(b"content-type", b"text/html"), (b"x-custom", b"safe-value")]
        out = sanitize_response_headers(headers)
        assert out == headers

    def test_crlf_in_value_stripped(self):
        bad = b"/home\r\nSet-Cookie: admin=true"
        out = sanitize_response_headers([(b"location", bad)])
        assert b"\r\n" not in out[0][1]
        assert b"\r" not in out[0][1]
        assert b"\n" not in out[0][1]

    def test_reject_mode_raises(self):
        bad = b"/home\r\nSet-Cookie: admin=true"
        with pytest.raises(ResponseSplittingError) as exc:
            sanitize_response_headers([(b"location", bad)], mode="reject")
        assert exc.value.header == "location"

    def test_on_detect_callback_fires(self):
        seen = []
        bad = b"x\r\nX-Injected: pwned"
        sanitize_response_headers(
            [(b"location", bad)],
            on_detect=lambda name, value: seen.append((name, value)),
        )
        assert seen and seen[0][0] == "location"


class TestResponseSplittingMiddleware:
    def _build(self, mode="strip", target="legit"):
        async def redirect_handler(request):
            to = request.query_params.get("to", target)
            return RedirectResponse(to)

        app = Starlette(routes=[Route("/r", redirect_handler)])
        app.add_middleware(ResponseSplittingMiddleware, mode=mode)
        return TestClient(app)

    def test_clean_redirect_passes(self):
        client = self._build(target="/home")
        r = client.get("/r", follow_redirects=False)
        assert r.status_code in (302, 307)
        assert r.headers["location"] == "/home"

    def test_crlf_in_location_stripped(self):
        client = self._build()
        # ?to= contains a CRLF + a Set-Cookie injection attempt
        bad = "/home\r\nSet-Cookie: admin=true"
        r = client.get("/r", params={"to": bad}, follow_redirects=False)
        assert r.status_code in (302, 307)
        loc = r.headers["location"]
        assert "\r" not in loc and "\n" not in loc


# ── graphql ────────────────────────────────────────────────────────────


class TestGraphqlGuardMiddleware:
    def _build(self, options=None, only_paths=None):
        async def graphql_endpoint(request):
            body = await request.body()
            payload = json.loads(body) if body else {}
            return JSONResponse({"received_query": payload.get("query")})

        app = Starlette(
            routes=[Route("/graphql", graphql_endpoint, methods=["POST"])],
        )
        kwargs = {}
        if options is not None:
            kwargs["options"] = options
        if only_paths is not None:
            kwargs["only_paths"] = only_paths
        app.add_middleware(GraphqlGuardMiddleware, **kwargs)
        return TestClient(app)

    def test_clean_query_passes(self):
        client = self._build()
        r = client.post("/graphql", json={"query": "{ user { name } }"})
        assert r.status_code == 200
        assert r.json() == {"received_query": "{ user { name } }"}

    def test_depth_bomb_blocked(self):
        client = self._build(options=GraphqlGuardOptions(max_depth=5))
        deep = "query { " + "x { " * 8 + "x" + " }" * 9
        r = client.post("/graphql", json={"query": deep})
        assert r.status_code == 400
        body = r.json()
        assert body["error"] == "graphql_query_blocked"
        assert body["reason"] == "depth"

    def test_introspection_blocked(self):
        client = self._build()
        r = client.post(
            "/graphql", json={"query": "{ __schema { types { name } } }"}
        )
        assert r.status_code == 400
        assert r.json()["reason"] == "introspection"

    def test_introspection_can_be_disabled(self):
        client = self._build(
            options=GraphqlGuardOptions(block_introspection=False)
        )
        r = client.post(
            "/graphql", json={"query": "{ __schema { types { name } } }"}
        )
        assert r.status_code == 200

    def test_batched_query_with_one_bad_blocks_all(self):
        client = self._build()
        r = client.post(
            "/graphql",
            json=[
                {"query": "{ user { name } }"},
                {"query": "{ __schema { types { name } } }"},
                {"query": "{ posts { title } }"},
            ],
        )
        assert r.status_code == 400
        assert r.json()["reason"] == "introspection"

    def test_non_graphql_path_unaffected(self):
        client = self._build()
        # Hit a non-/graphql endpoint — middleware should pass through.
        # Add a /other endpoint to the same app to test this.

        async def other(request):
            return JSONResponse({"ok": True})

        app = Starlette(
            routes=[
                Route("/other", other, methods=["POST"]),
                Route(
                    "/graphql",
                    lambda r: JSONResponse({"q": True}),
                    methods=["POST"],
                ),
            ],
        )
        app.add_middleware(GraphqlGuardMiddleware)
        client = TestClient(app)
        # __schema in body is fine — this is /other, not /graphql.
        r = client.post(
            "/other", json={"query": "{ __schema { types { name } } }"}
        )
        assert r.status_code == 200

    def test_get_method_unaffected(self):
        # GraphQL over GET is uncommon but valid (Apollo allows it). The
        # middleware only inspects POST requests in v1 — GET requests
        # flow through unfiltered. Documented v1 tradeoff.
        async def get_handler(request):
            return JSONResponse({"method": "GET"})

        app = Starlette(routes=[Route("/graphql", get_handler, methods=["GET"])])
        app.add_middleware(GraphqlGuardMiddleware)
        client = TestClient(app)
        r = client.get("/graphql")
        assert r.status_code == 200
