"""
HTTP response splitting prevention (sdk-vectors.md tier 1 #27).

Response splitting is the *output* counterpart to header injection: app
code passes user input into a response header without stripping CR/LF,
and an attacker uses the embedded newline to break out of the header
block and forge a second response. Most often weaponised against
``Location:`` after a redirect that reflects user input
(``/redirect?to=...``).

``sanitize_header_value`` (in ``sanitizers/headers.py``) covers the
byte-level fix on the way in; this middleware wraps the response on the
way out so every header that leaves the app gets sanitised even when
the app forgets.

Two modes:

- ``"strip"`` (default) silently sanitise the value before it reaches
  the wire. Preserves availability; existing routes don't break.
- ``"reject"`` raise the exception captured below. Use in apps that
  would rather fail-closed than emit a partial response.

Mirrors ``arcis-node/src/middleware/response-splitting.ts``.
"""

from typing import Callable, Iterable, List, Optional, Tuple

from ..sanitizers.headers import detect_header_injection, sanitize_header_value


# Sentinel exception name kept in line with Node's ResponseSplittingError.
class ResponseSplittingError(Exception):
    """Raised in ``reject`` mode when an outgoing header value contains
    CR / LF / NUL.

    Attributes:
        header: Name of the offending header.
        value: The originally attempted value (for logs).
    """

    def __init__(self, header: str, value: str):
        super().__init__(f"Response splitting payload in header {header!r}")
        self.header = header
        self.value = value


def sanitize_response_headers(
    headers: Iterable[Tuple[bytes, bytes]],
    *,
    mode: str = "strip",
    on_detect: Optional[Callable[[str, str], None]] = None,
) -> List[Tuple[bytes, bytes]]:
    """Return a copy of ``headers`` with every CR/LF/NUL stripped from
    values.

    Args:
        headers: ASGI-style header list ``[(name_bytes, value_bytes), ...]``.
        mode: ``"strip"`` (default) sanitises silently. ``"reject"``
            raises ``ResponseSplittingError`` on the first offending
            header without producing partial output.
        on_detect: Optional callback fired before strip/reject when a
            CRLF/NUL payload is detected. Receives
            ``(header_name, original_value)``.

    Returns:
        New header list. Values that were clean pass through byte-for-byte;
        offending values are sanitised (in strip mode) or the function
        raises (in reject mode).

    Raises:
        ResponseSplittingError: in reject mode when CR/LF/NUL is found.
    """
    if mode not in ("strip", "reject"):
        raise ValueError(
            "sanitize_response_headers: mode must be 'strip' or 'reject'"
        )

    out: List[Tuple[bytes, bytes]] = []
    for name, value in headers:
        try:
            value_str = value.decode("latin-1")
        except (UnicodeDecodeError, AttributeError):
            value_str = ""
        name_str = name.decode("latin-1") if isinstance(name, bytes) else str(name)
        if detect_header_injection(value_str):
            if on_detect is not None:
                on_detect(name_str, value_str)
            if mode == "reject":
                raise ResponseSplittingError(name_str, value_str)
            cleaned = sanitize_header_value(value_str)
            out.append((name, cleaned.encode("latin-1")))
        else:
            out.append((name, value))
    return out


# ── ASGI middleware adapter ────────────────────────────────────────────


class ResponseSplittingMiddleware:
    """ASGI middleware that sanitises every outgoing response header
    against CR/LF/NUL response-splitting payloads.

    Example (FastAPI / Starlette)::

        from arcis.middleware.response_splitting import ResponseSplittingMiddleware
        app.add_middleware(ResponseSplittingMiddleware)

        @app.get("/r")
        def redirect(to: str):
            # Even a forgotten sanitization here is caught on the way out.
            return RedirectResponse(to)

    Pair with ``validate_redirect()`` for full coverage: this middleware
    blocks the response-splitting payload, ``validate_redirect`` blocks
    the open-redirect payload.
    """

    def __init__(
        self,
        app: Callable,
        *,
        mode: str = "strip",
        on_detect: Optional[Callable[[str, str], None]] = None,
    ):
        if mode not in ("strip", "reject"):
            raise ValueError(
                "ResponseSplittingMiddleware: mode must be 'strip' or 'reject'"
            )
        self.app = app
        self.mode = mode
        self.on_detect = on_detect

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def guarded_send(message):
            if message.get("type") == "http.response.start":
                headers = message.get("headers", []) or []
                try:
                    sanitized = sanitize_response_headers(
                        headers, mode=self.mode, on_detect=self.on_detect
                    )
                except ResponseSplittingError:
                    # Reject mode: emit a 500 and stop. Doing this from
                    # inside guarded_send means the route handler has
                    # already started its response — we cannot rewind,
                    # so the safest action is to close the connection.
                    # The Node sibling throws synchronously and lets the
                    # framework error handler render 500; we mirror that
                    # by emitting a minimal 500 ourselves.
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 500,
                            "headers": [
                                (b"content-type", b"application/json"),
                            ],
                        }
                    )
                    await send(
                        {
                            "type": "http.response.body",
                            "body": b'{"error":"response_splitting_blocked"}',
                            "more_body": False,
                        }
                    )
                    return
                message = {**message, "headers": sanitized}
            await send(message)

        await self.app(scope, receive, guarded_send)
