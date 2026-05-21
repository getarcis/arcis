"""
Tests for the request-budget middleware — Python analogue of Node's
event-loop overload protection.

Verifies the in-flight ceiling + 503 + Retry-After behavior end-to-end
against a Starlette app.
"""

import asyncio

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from arcis.middleware.request_budget import RequestBudgetMiddleware


class TestConstructionValidation:
    def test_zero_concurrent_rejected(self):
        async def app(scope, receive, send):
            pass

        with pytest.raises(ValueError):
            RequestBudgetMiddleware(app, max_concurrent=0)


class TestUnderCapacity:
    """When in_flight < max_concurrent, requests flow through normally."""

    def _build(self):
        async def echo(request):
            return JSONResponse({"ok": True})

        app = Starlette(routes=[Route("/", echo)])
        app.add_middleware(RequestBudgetMiddleware, max_concurrent=10)
        return TestClient(app)

    def test_single_request_passes(self):
        client = self._build()
        r = client.get("/")
        assert r.status_code == 200

    def test_sequential_requests_all_pass(self):
        client = self._build()
        for _ in range(5):
            assert client.get("/").status_code == 200


class TestCeilingEnforcement:
    """Burst load past max_concurrent receives 503."""

    @pytest.mark.asyncio
    async def test_burst_past_ceiling_returns_503(self):
        # 5 concurrent slow handlers vs max_concurrent=2: 3 must 503.
        gate = asyncio.Event()
        admitted = []

        async def slow(request):
            admitted.append(1)
            await gate.wait()
            return JSONResponse({"ok": True})

        app = Starlette(routes=[Route("/", slow)])
        mw = RequestBudgetMiddleware(app, max_concurrent=2)

        # Drive ASGI directly to avoid TestClient's thread-pool quirks.
        async def call(headers=None):
            scope = {
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": headers or [],
                "query_string": b"",
            }
            sent = {"status": None}

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message):
                if message["type"] == "http.response.start":
                    sent["status"] = message["status"]

            await mw(scope, receive, send)
            return sent["status"]

        # Launch 5 concurrent. The first 2 will block at gate.wait();
        # the remaining 3 must be rejected with 503 immediately.
        tasks = [asyncio.create_task(call()) for _ in range(5)]
        # Let the admitted handlers reach the gate.
        await asyncio.sleep(0.02)
        # Open the gate so the 2 admitted finish.
        gate.set()

        results = await asyncio.gather(*tasks)
        # Exactly 2 should have made it through to the handler.
        assert sum(1 for s in results if s == 200) == 2
        # The remaining 3 should have been 503'd.
        assert sum(1 for s in results if s == 503) == 3
        # mw counter restored after handlers finished.
        assert mw.in_flight == 0

    def test_overload_response_carries_retry_after(self):
        # Synchronous client check: drive in_flight high via a wedged
        # background handler, fire one extra synchronously and inspect
        # headers. Easier to do via direct mw call.

        async def runner():
            gate = asyncio.Event()

            async def slow(scope, receive, send):
                await gate.wait()
                await send(
                    {"type": "http.response.start", "status": 200, "headers": []}
                )
                await send(
                    {"type": "http.response.body", "body": b"", "more_body": False}
                )

            mw = RequestBudgetMiddleware(
                slow, max_concurrent=1, retry_after_seconds=42, status_code=503
            )

            async def call():
                scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}
                received = {"messages": []}

                async def receive():
                    return {"type": "http.request", "body": b"", "more_body": False}

                async def send(message):
                    received["messages"].append(message)

                await mw(scope, receive, send)
                return received["messages"]

            # First call wedges in slow handler.
            t1 = asyncio.create_task(call())
            await asyncio.sleep(0.01)
            # Second call should be 503.
            t2 = asyncio.create_task(call())
            results2 = await t2
            # Release the wedge so t1 finishes too.
            gate.set()
            await t1

            start = next(m for m in results2 if m["type"] == "http.response.start")
            assert start["status"] == 503
            retry_after = dict(start["headers"]).get(b"retry-after")
            assert retry_after == b"42"

        asyncio.run(runner())


class TestExposeInflightHeader:
    """When expose_inflight_header=True, every response carries
    X-Arcis-In-Flight. Useful for monitoring."""

    def test_header_present_when_opted_in(self):
        async def echo(request):
            return JSONResponse({"ok": True})

        app = Starlette(routes=[Route("/", echo)])
        app.add_middleware(
            RequestBudgetMiddleware,
            max_concurrent=10,
            expose_inflight_header=True,
        )
        client = TestClient(app)
        r = client.get("/")
        assert r.status_code == 200
        assert r.headers.get("x-arcis-in-flight") is not None

    def test_header_absent_by_default(self):
        async def echo(request):
            return JSONResponse({"ok": True})

        app = Starlette(routes=[Route("/", echo)])
        app.add_middleware(RequestBudgetMiddleware, max_concurrent=10)
        client = TestClient(app)
        r = client.get("/")
        assert r.headers.get("x-arcis-in-flight") is None


class TestCounterAlwaysRestored:
    """Even on handler exception, in_flight must come back down or the
    process leaks budget over time."""

    @pytest.mark.asyncio
    async def test_handler_exception_releases_slot(self):
        # Drive the middleware directly so the test isn't entangled with
        # Starlette's TestClient exception-propagation policy. The point
        # is to verify the finally-block decrements; whether Starlette
        # surfaces the inner exception as 500 is a Starlette concern.
        async def boom(scope, receive, send):
            raise RuntimeError("handler crash")

        mw = RequestBudgetMiddleware(boom, max_concurrent=1)

        async def call():
            scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(_):
                pass

            try:
                await mw(scope, receive, send)
            except RuntimeError:
                pass

        for _ in range(3):
            await call()

        # If the finally block didn't run, in_flight would stay at 1
        # after the first call, then the second call would have 503'd
        # at the lock-acquire instead of reaching the boom handler.
        # All three calls reaching the handler PROVES the slot released.
        assert mw.in_flight == 0
