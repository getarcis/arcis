"""
Per-process request-budget middleware (sdk-vectors.md tier 1 #30 analogue).

Node's ``eventLoopProtection`` measures event-loop lag and 503s when
the loop is saturated. Python's asyncio doesn't expose a directly
comparable lag signal (the loop is single-threaded but uses a different
scheduling model; ``asyncio.get_event_loop().time()`` measurements drift
under heavy GIL contention and aren't a clean analogue).

This middleware ships the SAME INTENT in a Python-shaped way: cap the
number of concurrent in-flight requests per process. When the
configured ceiling is reached, new requests get 503 + Retry-After
immediately so the existing in-flight set can finish.

It's not a perfect overload guard — a single CPU-bound handler can
still wedge the loop without consuming the in-flight budget. The
Python-side answer to that is uvicorn workers + a real HTTP
load-balancer, not middleware. What this DOES catch:

- Burst floods that would otherwise queue resolvers / DB connections
- Slowloris-style holds (concurrent requests stuck waiting on slow IO)
- Cascading retries from buggy clients
- Memory-pressure cascades where every additional request makes the
  whole app slower

Defaults are conservative: 1000 concurrent requests per process. A
typical FastAPI/Litestar app on a 4-core box handles this comfortably;
the middleware engages only under genuine pressure.

Example::

    from arcis.middleware.request_budget import RequestBudgetMiddleware
    app.add_middleware(RequestBudgetMiddleware, max_concurrent=500)
"""

import asyncio
import json
from typing import Callable


class RequestBudgetMiddleware:
    """ASGI middleware that caps in-flight request concurrency.

    When ``max_concurrent`` requests are already being served, new
    requests immediately receive ``status_code`` (default 503) with a
    ``Retry-After`` header set to ``retry_after_seconds``.

    The counter is an in-memory integer, per-process. In a multi-worker
    deployment (uvicorn --workers, gunicorn, etc.) each worker has its
    own ceiling; multiply by worker count for the effective cap.

    Attributes:
        in_flight: Number of requests currently being served. Read-only
            for callers; useful for tests and monitoring exporters.
    """

    def __init__(
        self,
        app: Callable,
        *,
        max_concurrent: int = 1000,
        status_code: int = 503,
        message: str = "Server overloaded, please retry",
        retry_after_seconds: int = 5,
        expose_inflight_header: bool = False,
    ):
        if max_concurrent < 1:
            raise ValueError(
                "RequestBudgetMiddleware: max_concurrent must be >= 1"
            )
        self.app = app
        self.max_concurrent = max_concurrent
        self.status_code = status_code
        self.message = message
        self.retry_after_seconds = retry_after_seconds
        self.expose_inflight_header = expose_inflight_header
        self._in_flight = 0
        self._lock = asyncio.Lock()

    @property
    def in_flight(self) -> int:
        """Current concurrent request count. Useful for tests / monitoring."""
        return self._in_flight

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # Atomic check-and-increment so a burst of N concurrent
        # arrivals doesn't all see "still under the cap" at once.
        admitted = False
        async with self._lock:
            if self._in_flight < self.max_concurrent:
                self._in_flight += 1
                admitted = True

        if not admitted:
            await self._send_overload(send)
            return

        try:
            if self.expose_inflight_header:
                # Wrap send to add X-Arcis-In-Flight to the response.
                inflight = self._in_flight
                async def wrapped_send(message):
                    if message.get("type") == "http.response.start":
                        headers = list(message.get("headers", []) or [])
                        headers.append(
                            (b"x-arcis-in-flight", str(inflight).encode("ascii"))
                        )
                        message = {**message, "headers": headers}
                    await send(message)
                await self.app(scope, receive, wrapped_send)
            else:
                await self.app(scope, receive, send)
        finally:
            async with self._lock:
                if self._in_flight > 0:
                    self._in_flight -= 1

    async def _send_overload(self, send) -> None:
        payload = json.dumps({"error": self.message}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode("ascii")),
                    (b"retry-after", str(self.retry_after_seconds).encode("ascii")),
                ],
            }
        )
        await send(
            {"type": "http.response.body", "body": payload, "more_body": False}
        )
