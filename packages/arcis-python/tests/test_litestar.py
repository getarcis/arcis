"""
Litestar adapter tests (sdk-vectors P1 Litestar / P2 #24).

The adapter is a pure-ASGI middleware so the tests don't need
``litestar`` installed — we just drive the ``(scope, receive, send)``
contract directly. That keeps CI lean and proves the adapter works
with any ASGI host, not just Litestar.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Dict, List, Tuple

import pytest

from arcis.litestar import ArcisMiddleware


def _build_scope(
    *,
    method: str = "POST",
    path: str = "/api/echo",
    query: bytes = b"",
    headers: List[Tuple[bytes, bytes]] | None = None,
    client_ip: str = "1.2.3.4",
) -> Dict[str, Any]:
    return {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": query,
        "headers": headers or [(b"content-type", b"application/json")],
        "client": (client_ip, 12345),
        "server": ("testserver", 80),
        "scheme": "http",
    }


async def _drive(
    middleware: ArcisMiddleware,
    scope: Dict[str, Any],
    body: bytes = b"",
    inner: Callable[..., Awaitable[None]] | None = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Drive one request through the middleware and capture sent messages.

    Returns ``(sent_messages, received_messages_seen_by_inner)`` so
    tests can assert on both surfaces.
    """
    received_by_inner: List[Dict[str, Any]] = []
    sent: List[Dict[str, Any]] = []
    delivered = False

    async def receive() -> Dict[str, Any]:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    if inner is None:

        async def default_inner(scope_in, receive_in, send_in):
            # Read whatever the wrapped receive yields so we know what
            # the middleware passed downstream.
            while True:
                msg = await receive_in()
                received_by_inner.append(msg)
                if msg.get("type") in ("http.disconnect",):
                    break
                if msg.get("type") == "http.request" and not msg.get("more_body"):
                    break
            await send_in(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/plain")],
                }
            )
            await send_in({"type": "http.response.body", "body": b"ok"})

        middleware.app = default_inner  # type: ignore[assignment]
    else:
        middleware.app = inner  # type: ignore[assignment]

    await middleware(scope, receive, send)
    return sent, received_by_inner


# ─── Lifespan + websocket pass-through ─────────────────────────────────────


@pytest.mark.asyncio
async def test_non_http_scope_passes_through_untouched():
    seen: List[Dict[str, Any]] = []

    async def inner(scope, receive, send):
        seen.append(scope)
        await send({"type": "lifespan.startup.complete"})

    middleware = ArcisMiddleware(inner)
    sent: List[Dict[str, Any]] = []

    async def receive():
        return {"type": "lifespan.startup"}

    async def send(message):
        sent.append(message)

    await middleware({"type": "lifespan"}, receive, send)
    assert seen and seen[0]["type"] == "lifespan"
    assert any(m.get("type") == "lifespan.startup.complete" for m in sent)


# ─── Security headers ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_security_headers_attached_to_response_start():
    middleware = ArcisMiddleware(lambda *a, **k: None, rate_limit=False)
    sent, _ = await _drive(middleware, _build_scope())
    start = next(m for m in sent if m["type"] == "http.response.start")
    keys = {k.lower() for k, _ in start["headers"]}
    assert b"content-security-policy" in keys
    assert b"x-frame-options" in keys
    assert b"strict-transport-security" in keys
    assert b"referrer-policy" in keys


@pytest.mark.asyncio
async def test_security_headers_disabled_when_headers_false():
    middleware = ArcisMiddleware(
        lambda *a, **k: None, rate_limit=False, headers=False
    )
    sent, _ = await _drive(middleware, _build_scope())
    start = next(m for m in sent if m["type"] == "http.response.start")
    keys = {k.lower() for k, _ in start["headers"]}
    assert b"content-security-policy" not in keys


@pytest.mark.asyncio
async def test_x_powered_by_is_stripped():
    async def inner(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"x-powered-by", b"Litestar")],
            }
        )
        await send({"type": "http.response.body", "body": b""})

    middleware = ArcisMiddleware(inner, rate_limit=False)
    sent, _ = await _drive(middleware, _build_scope(), inner=inner)
    start = next(m for m in sent if m["type"] == "http.response.start")
    keys = {k.lower() for k, _ in start["headers"]}
    assert b"x-powered-by" not in keys


# ─── Rate limit ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rate_limit_blocks_after_cap():
    middleware = ArcisMiddleware(
        lambda *a, **k: None,
        rate_limit=True,
        rate_limit_max=2,
        rate_limit_window_ms=60_000,
        headers=False,
    )

    # First two go through.
    sent1, _ = await _drive(middleware, _build_scope(client_ip="9.9.9.9"))
    assert any(m["type"] == "http.response.start" and m["status"] == 200 for m in sent1)
    sent2, _ = await _drive(middleware, _build_scope(client_ip="9.9.9.9"))
    assert any(m["type"] == "http.response.start" and m["status"] == 200 for m in sent2)

    # Third: 429 + Retry-After.
    sent3, _ = await _drive(middleware, _build_scope(client_ip="9.9.9.9"))
    start = next(m for m in sent3 if m["type"] == "http.response.start")
    assert start["status"] == 429
    keys = {k.lower() for k, _ in start["headers"]}
    assert b"retry-after" in keys


@pytest.mark.asyncio
async def test_rate_limit_isolates_per_ip():
    middleware = ArcisMiddleware(
        lambda *a, **k: None,
        rate_limit=True,
        rate_limit_max=1,
        rate_limit_window_ms=60_000,
        headers=False,
    )
    sent_a, _ = await _drive(middleware, _build_scope(client_ip="1.1.1.1"))
    sent_b, _ = await _drive(middleware, _build_scope(client_ip="2.2.2.2"))
    assert any(m.get("status") == 200 for m in sent_a)
    assert any(m.get("status") == 200 for m in sent_b)


@pytest.mark.asyncio
async def test_dry_run_does_not_enforce_rate_limit():
    middleware = ArcisMiddleware(
        lambda *a, **k: None,
        dry_run=True,
        rate_limit=True,
        rate_limit_max=1,
        rate_limit_window_ms=60_000,
        headers=False,
    )

    sent1, _ = await _drive(middleware, _build_scope(client_ip="192.0.2.60"))
    sent2, _ = await _drive(middleware, _build_scope(client_ip="192.0.2.60"))
    assert any(m.get("status") == 200 for m in sent1)
    assert any(m.get("status") == 200 for m in sent2)


@pytest.mark.asyncio
async def test_xff_from_trusted_peer_drives_rate_limit_key():
    """
    Behind trusted (private) proxies the X-Forwarded-For walk, read from
    the right, picks the client: same client means same bucket regardless
    of which proxy forwarded it.
    """
    middleware = ArcisMiddleware(
        lambda *a, **k: None,
        rate_limit=True,
        rate_limit_max=1,
        rate_limit_window_ms=60_000,
        headers=False,
    )
    base = lambda peer: _build_scope(
        client_ip=peer,
        headers=[
            (b"content-type", b"application/json"),
            (b"x-forwarded-for", b"203.0.113.7, 10.0.0.1"),
        ],
    )
    sent1, _ = await _drive(middleware, base("10.0.0.5"))
    sent2, _ = await _drive(middleware, base("10.0.0.6"))
    # Different trusted socket peers, same client: same bucket, 429 on the second.
    assert any(m.get("status") == 200 for m in sent1)
    assert any(m.get("status") == 429 for m in sent2)


# ─── Block mode ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_block_mode_rejects_xss_payload_in_json_body():
    middleware = ArcisMiddleware(
        lambda *a, **k: None, block=True, rate_limit=False, headers=False
    )
    body = json.dumps({"q": "<script>alert(1)</script>"}).encode()
    sent, _ = await _drive(middleware, _build_scope(), body=body)
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 403
    body_msg = next(m for m in sent if m["type"] == "http.response.body")
    payload = json.loads(body_msg["body"].decode())
    assert payload["code"] == "SECURITY_THREAT"
    assert payload["vector"] == "xss"


@pytest.mark.asyncio
async def test_block_mode_allows_clean_body():
    captured: List[Dict[str, Any]] = []

    async def inner(scope, receive, send):
        msg = await receive()
        captured.append(msg)
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = ArcisMiddleware(inner, block=True, rate_limit=False)
    body = json.dumps({"name": "Gagan"}).encode()
    sent, _ = await _drive(middleware, _build_scope(), body=body, inner=inner)
    assert any(m.get("status") == 200 for m in sent)
    # The inner app saw the original (unmodified) body since it's
    # already clean. Sanitiser is on by default but rewrites only
    # when threats fire.
    inner_body = next(m["body"] for m in captured if m["type"] == "http.request")
    assert json.loads(inner_body.decode()) == {"name": "Gagan"}


@pytest.mark.asyncio
async def test_block_mode_rejects_query_string_path_traversal():
    middleware = ArcisMiddleware(
        lambda *a, **k: None,
        block=True,
        rate_limit=False,
        headers=False,
    )
    sent, _ = await _drive(
        middleware,
        _build_scope(
            method="GET",
            path="/files",
            query=b"f=..%2f..%2fetc%2fpasswd",
            headers=[(b"content-type", b"text/plain")],
        ),
    )
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 403
    body_msg = next(m for m in sent if m["type"] == "http.response.body")
    payload = json.loads(body_msg["body"].decode())
    assert payload["code"] == "SECURITY_THREAT"


@pytest.mark.asyncio
async def test_block_mode_rejects_invalid_json_body_with_400():
    middleware = ArcisMiddleware(
        lambda *a, **k: None, block=True, rate_limit=False, headers=False
    )
    sent, _ = await _drive(middleware, _build_scope(), body=b"{not json")
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 400


@pytest.mark.asyncio
async def test_dry_run_passes_invalid_json_to_inner_app():
    middleware = ArcisMiddleware(
        lambda *a, **k: None,
        block=True,
        dry_run=True,
        rate_limit=False,
        headers=False,
    )
    sent, received = await _drive(
        middleware,
        _build_scope(),
        body=b"{not json",
    )
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 200
    assert received[0]["body"] == b"{not json"


# ─── Sanitisation rewrite ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sanitiser_rewrites_dirty_body_for_inner_app():
    captured: List[bytes] = []

    async def inner(scope, receive, send):
        msg = await receive()
        if msg.get("type") == "http.request":
            captured.append(msg.get("body") or b"")
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = ArcisMiddleware(
        inner, sanitize=True, block=False, rate_limit=False, headers=False
    )
    # Use a payload the Arcis XSS detector actively rewrites — bare
    # formatting tags like <b> are not XSS vectors and are passed
    # through unchanged. <script>alert(1)</script> is the canonical
    # case the detector targets.
    dirty = json.dumps({"comment": "<script>alert(1)</script>"}).encode()
    await _drive(middleware, _build_scope(), body=dirty, inner=inner)
    assert captured, "inner app should have received a request body"
    after = json.loads(captured[0].decode())
    assert "<script>" not in after["comment"]


@pytest.mark.asyncio
async def test_sanitiser_updates_content_length_for_inner_app():
    captured_scopes: List[Dict[str, Any]] = []

    async def inner(scope, receive, send):
        captured_scopes.append(scope)
        await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = ArcisMiddleware(
        inner, sanitize=True, rate_limit=False, headers=False
    )
    dirty = json.dumps({"q": "<script>alert(1)</script>"}).encode()
    await _drive(middleware, _build_scope(), body=dirty, inner=inner)
    cl = dict(captured_scopes[0]["headers"]).get(b"content-length")
    assert cl is not None
    # The XSS sanitiser strips <script> tags, so the rewritten body
    # length differs from the input. The inner app's content-length
    # header must reflect the new size or downstream parsers will
    # over- / under-read.
    assert int(cl) != len(dirty)


@pytest.mark.asyncio
async def test_dry_run_preserves_request_body_bytes():
    captured: List[bytes] = []

    async def inner(scope, receive, send):
        msg = await receive()
        captured.append(msg.get("body") or b"")
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = ArcisMiddleware(
        inner,
        sanitize=True,
        block=True,
        dry_run=True,
        rate_limit=False,
        headers=False,
    )
    original = json.dumps(
        {
            "note": "Use the -- flag; it works",
            "path": "docs/../README.md",
        }
    ).encode()

    await _drive(middleware, _build_scope(), body=original, inner=inner)

    assert captured == [original]


@pytest.mark.asyncio
async def test_dry_run_reports_would_deny_without_rewriting_body():
    captured: List[bytes] = []
    events: List[Dict[str, Any]] = []

    async def inner(scope, receive, send):
        msg = await receive()
        captured.append(msg.get("body") or b"")
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = ArcisMiddleware(
        inner,
        sanitize=True,
        block=True,
        dry_run=True,
        on_sanitize=events.append,
        rate_limit=False,
        headers=False,
    )
    original = json.dumps({"comment": "<script>alert(1)</script>"}).encode()

    sent, _ = await _drive(middleware, _build_scope(), body=original, inner=inner)

    assert any(message.get("status") == 200 for message in sent)
    assert captured == [original]
    assert len(events) == 1
    assert events[0]["decision"] == "would_deny"
    assert events[0]["vector"] == "xss"


# ─── Bot detection ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bot_detection_blocks_automated_when_enabled():
    middleware = ArcisMiddleware(
        lambda *a, **k: None,
        bot=True,
        rate_limit=False,
        headers=False,
    )
    sent, _ = await _drive(
        middleware,
        _build_scope(
            headers=[
                (b"content-type", b"application/json"),
                (b"user-agent", b"HeadlessChrome/120.0.0.0 Safari/537.36"),
            ]
        ),
    )
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 403


@pytest.mark.asyncio
async def test_bot_detection_passes_googlebot_when_enabled():
    middleware = ArcisMiddleware(
        lambda *a, **k: None,
        bot=True,
        rate_limit=False,
        headers=False,
    )
    sent, _ = await _drive(
        middleware,
        _build_scope(
            headers=[
                (b"content-type", b"application/json"),
                (
                    b"user-agent",
                    b"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                ),
            ]
        ),
    )
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 200
