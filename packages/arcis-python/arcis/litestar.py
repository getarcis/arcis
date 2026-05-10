"""
Arcis Litestar adapter (sdk-vectors.md P1 Litestar / P2 #24).

Litestar is ASGI-native, so this adapter is a pure ASGI middleware
class. The ``litestar`` package is a *type-only* import — the adapter
ships in every Arcis install regardless of whether the consumer uses
Litestar.

Quick start::

    from litestar import Litestar
    from litestar.middleware.base import DefineMiddleware
    from arcis.litestar import ArcisMiddleware

    app = Litestar(
        middleware=[DefineMiddleware(ArcisMiddleware, block=True)],
    )

The pipeline mirrors the Node and FastAPI adapters:

    1. Rate limit (returns 429 with ``Retry-After`` if exceeded)
    2. Bot detection (returns 403 if the bot category matches the deny list)
    3. Block-mode threat scan over body / query / path
    4. Hand off to the inner ASGI app
    5. Mutate the outgoing response with the security-header set

The class accepts the inner ``app`` as its first arg so it composes
with any ASGI router that supports the standard ``(scope, receive,
send)`` triple — Starlette, FastAPI, Litestar, Quart, Hypercorn.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs

from .middleware.headers import SecurityHeaders
from .middleware.rate_limit import RateLimiter, RateLimitExceeded
from .sanitizers.sanitize import Sanitizer, scan_threats

# ASGI typing surface — kept narrow enough that we don't need ``litestar``
# imports for runtime correctness. ``Receive`` and ``Send`` are awaitable
# callables; ``Scope`` is a dict with the well-known keys.
Scope = Dict[str, Any]
Message = Dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


_DEFAULT_BOT_ALLOW: Tuple[str, ...] = ("SEARCH_ENGINE", "SOCIAL", "MONITORING")
_DEFAULT_BOT_DENY: Tuple[str, ...] = ("AUTOMATED",)


def _client_ip_from_scope(scope: Scope) -> str:
    """
    Pull the client IP off an ASGI scope, honouring proxy headers.
    Order: ``X-Forwarded-For`` (leftmost) > ``X-Real-IP`` >
    ``CF-Connecting-IP`` > scope ``client`` tuple > "unknown".

    The "unknown" fallback is shared per design: a header-stripping
    edge proxy must not be able to escape rate limiting by erasing
    every IP signal.
    """
    headers = dict(scope.get("headers") or [])
    xff = headers.get(b"x-forwarded-for")
    if xff:
        first = xff.decode("latin-1", errors="ignore").split(",")[0].strip()
        if first:
            return first
    xri = headers.get(b"x-real-ip")
    if xri:
        return xri.decode("latin-1", errors="ignore").strip()
    cfip = headers.get(b"cf-connecting-ip")
    if cfip:
        return cfip.decode("latin-1", errors="ignore").strip()
    client = scope.get("client")
    if isinstance(client, (list, tuple)) and len(client) >= 1:
        return str(client[0])
    return "unknown"


def _bot_input_from_scope(scope: Scope) -> Any:
    """
    detect_bot reads a few string headers. Build a duck-typed object
    with a ``.headers`` mapping rather than importing the helper's
    expected request type.
    """
    raw = dict(scope.get("headers") or [])
    h = {
        "user-agent": (raw.get(b"user-agent") or b"").decode("latin-1", errors="ignore"),
        "accept": (raw.get(b"accept") or b"").decode("latin-1", errors="ignore"),
        "accept-language": (raw.get(b"accept-language") or b"").decode("latin-1", errors="ignore"),
        "accept-encoding": (raw.get(b"accept-encoding") or b"").decode("latin-1", errors="ignore"),
        "connection": (raw.get(b"connection") or b"").decode("latin-1", errors="ignore"),
    }

    class _ScopeReq:
        headers = h

    return _ScopeReq()


def _query_dict(scope: Scope) -> Dict[str, Any]:
    """Parse the raw scope query string into a flat dict for scan_threats."""
    raw = scope.get("query_string", b"") or b""
    if not raw:
        return {}
    try:
        parsed = parse_qs(raw.decode("latin-1", errors="ignore"), keep_blank_values=True)
    except Exception:
        return {}
    out: Dict[str, Any] = {}
    for k, vals in parsed.items():
        out[k] = vals[0] if len(vals) == 1 else vals
    return out


async def _read_body(receive: Receive) -> Tuple[bytes, List[Message]]:
    """
    Drain the http.request stream into a single bytes blob and capture
    the messages so the inner app can replay them through a wrapped
    ``receive``. Returns ``(body, messages)``.

    Bounded by the caller's ``max_input_size`` Sanitizer config; this
    helper itself does not cap because some apps want to read very
    large multipart bodies — we only buffer when block-mode or
    sanitisation is enabled.
    """
    body = bytearray()
    messages: List[Message] = []
    while True:
        msg = await receive()
        messages.append(msg)
        if msg.get("type") == "http.request":
            body.extend(msg.get("body") or b"")
            if not msg.get("more_body"):
                return bytes(body), messages
        elif msg.get("type") == "http.disconnect":
            return bytes(body), messages


def _replay_receive(messages: List[Message]) -> Receive:
    """Build a Receive callable that yields buffered messages then blocks."""
    queue = list(messages)

    async def replay() -> Message:
        if queue:
            return queue.pop(0)
        # Once we've replayed everything, behave like the original
        # receive after EOF — yield a synthetic disconnect so
        # downstream code doesn't hang.
        return {"type": "http.disconnect"}

    return replay


def _json_response(status: int, payload: Dict[str, Any], extra_headers: Optional[List[Tuple[bytes, bytes]]] = None) -> Tuple[Message, Message]:
    """Build the (start, body) ASGI message pair for a JSON response."""
    body = json.dumps(payload).encode("utf-8")
    headers: List[Tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    return (
        {"type": "http.response.start", "status": status, "headers": headers},
        {"type": "http.response.body", "body": body},
    )


class ArcisMiddleware:
    """
    Pure ASGI middleware that runs the Arcis pipeline before every HTTP
    request. Composes with Litestar via ``DefineMiddleware`` and with
    any other ASGI host via direct instantiation.

    Parameters
    ----------
    app : ASGIApp
        The inner ASGI app. Litestar passes this automatically.
    block : bool
        When True, scan body/query/path for attack patterns and respond
        403 instead of running the handler.
    sanitize : bool
        When True, sanitise JSON bodies in place before the handler runs.
    rate_limit : bool
        When True, enforce per-IP rate limiting using the bundled
        in-memory ``RateLimiter``.
    rate_limit_max : int
    rate_limit_window_ms : int
        Rate-limit configuration. Defaults match the FastAPI adapter.
    headers : bool
        When True, attach the standard security-header set to every
        outgoing response.
    bot : bool
        When True, run the lightweight bot classifier.
    bot_allow : tuple[str, ...]
    bot_deny : tuple[str, ...]
        Bot categories. Defaults: allow SEARCH_ENGINE / SOCIAL /
        MONITORING; deny AUTOMATED.
    csp : str | None
        Override the default Content-Security-Policy.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        block: bool = False,
        sanitize: bool = True,
        rate_limit: bool = True,
        rate_limit_max: int = 100,
        rate_limit_window_ms: int = 60_000,
        headers: bool = True,
        bot: bool = False,
        bot_allow: Tuple[str, ...] = _DEFAULT_BOT_ALLOW,
        bot_deny: Tuple[str, ...] = _DEFAULT_BOT_DENY,
        csp: Optional[str] = None,
    ) -> None:
        self.app = app
        self.block = block
        self._sanitizer: Optional[Sanitizer] = Sanitizer() if sanitize else None
        # The bundled RateLimiter expects a request object and delegates
        # key extraction to ``key_func``. Pass a passthrough so we can
        # call ``check(ip_string)`` with the IP we already pulled from
        # the ASGI scope without building a request shim.
        self._rate_limiter: Optional[RateLimiter] = (
            RateLimiter(
                max_requests=rate_limit_max,
                window_ms=rate_limit_window_ms,
                key_func=lambda key: key,
            )
            if rate_limit
            else None
        )
        self._headers: Optional[SecurityHeaders] = (
            SecurityHeaders(content_security_policy=csp) if headers else None
        )
        self._bot_enabled = bot
        self._bot_allow = set(bot_allow)
        self._bot_deny = set(bot_deny)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Lifespan + websocket scopes pass straight through. We only
        # protect HTTP requests; WS handshake protection is a separate
        # vector tracked outside this adapter.
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # 1. Rate limit. The sync RateLimiter is in-memory + threading
        #    Lock; the critical section is microsecond-scale so it's
        #    acceptable inside an async handler.
        if self._rate_limiter is not None:
            ip = _client_ip_from_scope(scope)
            try:
                self._rate_limiter.check(ip)
            except RateLimitExceeded as exc:
                start, body = _json_response(
                    429,
                    {"error": exc.message, "retry_after": exc.retry_after},
                    extra_headers=[(b"retry-after", str(exc.retry_after).encode())],
                )
                await send(start)
                await send(body)
                return

        # 2. Bot detection. Defer the import so consumers without the
        #    bot corpus loaded at startup don't pay it.
        if self._bot_enabled:
            from .middleware.bot_detection import detect_bot  # local import

            result = detect_bot(_bot_input_from_scope(scope))
            if getattr(result, "is_bot", False):
                category = getattr(result, "category", "UNKNOWN")
                if category in self._bot_deny or category not in self._bot_allow:
                    start, body = _json_response(403, {"error": "Access denied."})
                    await send(start)
                    await send(body)
                    return

        # 3. Body/query/path scan + (optionally) sanitise. Read the
        #    body once; the inner app gets a wrapped receive that
        #    replays the captured messages.
        wrapped_receive = receive
        if self.block or self._sanitizer is not None:
            content_type = (
                dict(scope.get("headers") or []).get(b"content-type", b"").decode(
                    "latin-1", errors="ignore"
                )
            )
            if "application/json" in content_type:
                raw_body, messages = await _read_body(receive)
                body_obj: Any = None
                if raw_body:
                    try:
                        body_obj = json.loads(raw_body.decode("utf-8"))
                    except json.JSONDecodeError:
                        start, body = _json_response(
                            400, {"error": "Invalid JSON in request body"}
                        )
                        await send(start)
                        await send(body)
                        return

                if self.block:
                    threat = None
                    if body_obj is not None:
                        threat = scan_threats(body_obj)
                    if threat is None:
                        q = _query_dict(scope)
                        if q:
                            threat = scan_threats(q)
                    if threat is None:
                        threat = scan_threats(scope.get("path", "") or "")
                    if threat is not None:
                        vector, rule, _matched = threat
                        start, body = _json_response(
                            403,
                            {
                                "error": "Request blocked for security reasons",
                                "code": "SECURITY_THREAT",
                                "vector": vector,
                                "rule": rule,
                            },
                        )
                        await send(start)
                        await send(body)
                        return

                if self._sanitizer is not None and isinstance(body_obj, dict):
                    sanitised = self._sanitizer.sanitize_dict(body_obj)
                    new_body = json.dumps(sanitised).encode("utf-8")
                    # Rewrite the buffered request so the inner app
                    # parses the sanitised body. We replace each
                    # http.request fragment with the new bytes
                    # delivered as one final non-streaming message.
                    messages = [
                        m
                        for m in messages
                        if m.get("type") != "http.request"
                    ]
                    messages.insert(
                        0,
                        {"type": "http.request", "body": new_body, "more_body": False},
                    )
                    # Rewrite content-length on the scope so the inner
                    # app's body parser doesn't read past the new body.
                    new_headers: List[Tuple[bytes, bytes]] = []
                    cl = str(len(new_body)).encode()
                    saw_cl = False
                    for k, v in scope.get("headers") or []:
                        if k.lower() == b"content-length":
                            new_headers.append((k, cl))
                            saw_cl = True
                        else:
                            new_headers.append((k, v))
                    if not saw_cl:
                        new_headers.append((b"content-length", cl))
                    scope["headers"] = new_headers
                wrapped_receive = _replay_receive(messages)

            elif self.block:
                # Non-JSON body still gets the query + path scan.
                threat = None
                q = _query_dict(scope)
                if q:
                    threat = scan_threats(q)
                if threat is None:
                    threat = scan_threats(scope.get("path", "") or "")
                if threat is not None:
                    vector, rule, _ = threat
                    start, body = _json_response(
                        403,
                        {
                            "error": "Request blocked for security reasons",
                            "code": "SECURITY_THREAT",
                            "vector": vector,
                            "rule": rule,
                        },
                    )
                    await send(start)
                    await send(body)
                    return

        # 4. Wrap send so we can splice security headers into the
        #    response start message before the inner app's bytes flush
        #    to the wire.
        if self._headers is not None:
            extra = self._headers.get_headers()
            extra_pairs: List[Tuple[bytes, bytes]] = [
                (k.lower().encode("latin-1"), v.encode("latin-1"))
                for k, v in extra.items()
            ]

            async def wrapped_send(message: Message) -> None:
                if message.get("type") == "http.response.start":
                    existing_keys = {k.lower() for k, _ in message.get("headers") or []}
                    merged = list(message.get("headers") or [])
                    for k, v in extra_pairs:
                        if k not in existing_keys:
                            merged.append((k, v))
                    # Strip X-Powered-By if the inner app set it.
                    merged = [(k, v) for k, v in merged if k.lower() != b"x-powered-by"]
                    message = {**message, "headers": merged}
                await send(message)

            await self.app(scope, wrapped_receive, wrapped_send)
        else:
            await self.app(scope, wrapped_receive, send)


__all__ = ["ArcisMiddleware"]
