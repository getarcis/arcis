"""
HTTP method tampering protection (sdk-vectors.md tier 1 #26).

Two related threats:

1. **Disallowed methods.** ``TRACE`` leaks Authorization headers (XST);
   ``CONNECT`` is for proxies and shouldn't reach an application server;
   custom verbs slip past route-handlers that only check
   ``request.method == "POST"``. This middleware rejects anything
   outside an allowlist with 405.

2. **Method-override bypass.** Frameworks that respect
   ``X-HTTP-Method-Override`` let an attacker turn a GET into a POST
   or DELETE, bypassing route-level method checks. The middleware
   strips these headers BEFORE the route handler sees them.

Two layers per Pattern 3:

- ``check_method()`` is the framework-agnostic pure function.
- ``MethodAllowlistMiddleware`` is the ASGI adapter.

Mirrors ``arcis-node/src/middleware/method-allowlist.ts``.
"""

from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Tuple


METHOD_OVERRIDE_HEADERS: Tuple[bytes, ...] = (
    b"x-http-method-override",
    b"x-method-override",
    b"x-http-method",
)

# TRACE + CONNECT intentionally excluded:
# - TRACE enables Cross-Site Tracing (leaks Cookie / Authorization headers
#   to attacker JS via reflected response)
# - CONNECT is for HTTP proxies. An app server should never see it.
DEFAULT_ALLOWED_METHODS: Tuple[str, ...] = (
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "PATCH",
)


@dataclass(frozen=True)
class MethodCheckResult:
    """Outcome of checking a request method.

    Attributes:
        allowed: Whether the method is in the allowlist.
        method: The uppercased method that was checked.
        stripped_headers: Names of override headers that were detected
            (and would be stripped by the middleware adapter). Empty
            list when no override headers were present.
    """

    allowed: bool
    method: str
    stripped_headers: List[str]


def check_method(
    method: str,
    headers: Iterable[Tuple[bytes, bytes]],
    *,
    allow: Optional[Iterable[str]] = None,
) -> MethodCheckResult:
    """Pure method check.

    Args:
        method: HTTP method from the request (any case).
        headers: ASGI-style header list ``[(name_bytes, value_bytes), ...]``.
        allow: Iterable of permitted methods. Each is uppercased before
            comparison. Defaults to GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH.

    Returns:
        ``MethodCheckResult`` with the allow decision and any override
        headers that were detected.

    Example:
        result = check_method("GET", [(b"x-http-method-override", b"DELETE")])
        # result.allowed == True
        # result.stripped_headers == ["x-http-method-override"]
    """
    allow_set = {m.upper() for m in allow} if allow else set(DEFAULT_ALLOWED_METHODS)
    method_upper = (method or "").upper()
    stripped: List[str] = []
    for name, _value in headers:
        if name.lower() in METHOD_OVERRIDE_HEADERS:
            stripped.append(name.decode("latin-1"))
    return MethodCheckResult(
        allowed=method_upper in allow_set,
        method=method_upper,
        stripped_headers=stripped,
    )


# ── ASGI middleware adapter ────────────────────────────────────────────


class MethodAllowlistMiddleware:
    """ASGI middleware that rejects disallowed HTTP methods + strips
    method-override headers.

    Example (FastAPI / Starlette)::

        from arcis.middleware.method_allowlist import MethodAllowlistMiddleware
        app.add_middleware(
            MethodAllowlistMiddleware,
            allow=["GET", "POST"],
        )

    A blocked request gets a 405 with body
    ``{"error": "Method not allowed", "method": "TRACE"}`` and an
    ``Allow:`` header listing the permitted methods (per RFC 9110 §15.5.6).
    """

    def __init__(
        self,
        app: Callable,
        *,
        allow: Optional[Iterable[str]] = None,
        strip_override_headers: bool = True,
        status_code: int = 405,
        message: str = "Method not allowed",
    ):
        self.app = app
        self.allow = (
            tuple(m.upper() for m in allow) if allow else DEFAULT_ALLOWED_METHODS
        )
        self.strip_override_headers = strip_override_headers
        self.status_code = status_code
        self.message = message

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        headers = scope.get("headers", []) or []
        result = check_method(method, headers, allow=self.allow)

        if not result.allowed:
            await self._send_method_not_allowed(send, method)
            return

        # Strip override headers in place by rebuilding the headers list.
        if self.strip_override_headers and result.stripped_headers:
            sanitized = [
                (name, value)
                for name, value in headers
                if name.lower() not in METHOD_OVERRIDE_HEADERS
            ]
            # Mutate the scope dict — ASGI scopes are mutable per spec
            # and this is the canonical way for middleware to change them.
            scope = {**scope, "headers": sanitized}

        await self.app(scope, receive, send)

    async def _send_method_not_allowed(self, send, method: str) -> None:
        import json
        payload = json.dumps({"error": self.message, "method": method}).encode("utf-8")
        allow_header = ", ".join(self.allow).encode("ascii")
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode("ascii")),
                    (b"allow", allow_header),
                ],
            }
        )
        await send(
            {"type": "http.response.body", "body": payload, "more_body": False}
        )
