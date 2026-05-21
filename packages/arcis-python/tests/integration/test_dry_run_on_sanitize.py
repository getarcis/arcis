"""
dry_run + on_sanitize tests for the FastAPI ArcisMiddleware.

Covers:
- Default block=True path still returns 403 (no regression)
- block=True + dry_run=True scans but doesn't deny
- on_sanitize callback fires with full event dict
- Callback exceptions are swallowed (don't crash the middleware)
"""

from fastapi import FastAPI
from starlette.testclient import TestClient

from arcis.fastapi import ArcisMiddleware


def _build_app(**middleware_kwargs):
    app = FastAPI()
    app.add_middleware(ArcisMiddleware, **middleware_kwargs)

    @app.post("/echo")
    async def echo(payload: dict):
        return {"ok": True, "received": payload}

    return TestClient(app)


class TestBlockModeNoRegression:
    """Default block=True path unchanged."""

    def test_xss_payload_returns_403_in_block_mode(self):
        client = _build_app(block=True, rate_limit=False, headers=False)
        r = client.post("/echo", json={"q": "<script>alert(1)</script>"})
        assert r.status_code == 403
        assert r.json()["code"] == "SECURITY_THREAT"

    def test_clean_payload_passes_in_block_mode(self):
        client = _build_app(block=True, rate_limit=False, headers=False)
        r = client.post("/echo", json={"q": "hello world"})
        assert r.status_code == 200


class TestDryRunMode:
    """block=True + dry_run=True scans + logs but doesn't deny."""

    def test_xss_payload_passes_through_with_200(self):
        client = _build_app(
            block=True, dry_run=True, rate_limit=False, headers=False
        )
        r = client.post("/echo", json={"q": "<script>alert(1)</script>"})
        # Would-have-blocked but didn't. Route handler runs.
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_clean_payload_passes_in_dry_run(self):
        # Clean traffic shouldn't be affected at all by dry_run.
        client = _build_app(
            block=True, dry_run=True, rate_limit=False, headers=False
        )
        r = client.post("/echo", json={"q": "hello world"})
        assert r.status_code == 200

    def test_dry_run_without_block_is_no_op(self):
        # block=False means no scan happens; dry_run has nothing to skip.
        client = _build_app(
            block=False, dry_run=True, rate_limit=False, headers=False
        )
        r = client.post("/echo", json={"q": "<script>alert(1)</script>"})
        # Sanitizer still runs by default — body gets cleaned and handler
        # sees the sanitized value. Status is always 200 here.
        assert r.status_code == 200


class TestOnSanitizeCallback:
    """on_sanitize fires with the full event dict when a threat is hit."""

    def test_callback_receives_vector_and_path(self):
        events = []
        client = _build_app(
            block=True,
            rate_limit=False,
            headers=False,
            on_sanitize=lambda e: events.append(e),
        )
        client.post("/echo", json={"q": "<script>alert(1)</script>"})
        assert len(events) == 1
        e = events[0]
        assert e["vector"] == "xss"
        assert e["rule"] == "xss/match"
        assert e["path"] == "/echo"
        assert e["dry_run"] is False
        assert isinstance(e["matched"], str)

    def test_callback_dry_run_field_true_in_dry_mode(self):
        events = []
        client = _build_app(
            block=True,
            dry_run=True,
            rate_limit=False,
            headers=False,
            on_sanitize=lambda e: events.append(e),
        )
        client.post("/echo", json={"q": "<script>alert(1)</script>"})
        assert events[0]["dry_run"] is True

    def test_callback_does_not_fire_on_clean_traffic(self):
        events = []
        client = _build_app(
            block=True,
            rate_limit=False,
            headers=False,
            on_sanitize=lambda e: events.append(e),
        )
        client.post("/echo", json={"q": "hello world"})
        assert events == []

    def test_callback_exception_does_not_crash_middleware(self):
        def boom(_event):
            raise RuntimeError("callback exploded")

        client = _build_app(
            block=True,
            rate_limit=False,
            headers=False,
            on_sanitize=boom,
        )
        # Middleware must not propagate the callback's exception. The
        # threat is still denied (block mode), the callback's failure is
        # logged and swallowed.
        r = client.post("/echo", json={"q": "<script>alert(1)</script>"})
        assert r.status_code == 403

    def test_callback_fires_in_dry_run_then_request_succeeds(self):
        events = []
        client = _build_app(
            block=True,
            dry_run=True,
            rate_limit=False,
            headers=False,
            on_sanitize=lambda e: events.append(e),
        )
        r = client.post(
            "/echo", json={"q": "*)(uid=*))(|(uid=*"}
        )
        # Callback fired with LDAP vector, request still succeeded.
        assert r.status_code == 200
        assert events[0]["vector"] == "ldap"
        assert events[0]["dry_run"] is True
