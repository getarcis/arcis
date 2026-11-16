"""Test helper: run an ASGI app as if the server saw a given socket peer.

Litestar's TestClient always reports the peer as ``("testclient", 50000)``.
Real servers put the connecting address in ``scope["client"]``; this wrapper
does the same so tests can exercise trusted and untrusted peers.
"""

from typing import Any, Awaitable, Callable, Dict

ASGIApp = Callable[[Dict[str, Any], Any, Any], Awaitable[None]]


def with_peer(app: ASGIApp, host: str, port: int = 50000) -> ASGIApp:
    """Return an ASGI app that sets ``scope["client"]`` to ``(host, port)``."""

    async def wrapped(scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") in ("http", "websocket"):
            scope = {**scope, "client": (host, port)}
        await app(scope, receive, send)

    return wrapped
