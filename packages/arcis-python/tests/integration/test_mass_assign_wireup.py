"""v1.7 W4 mass-assignment field detection integration tests."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from arcis.fastapi import ArcisMiddleware


_BROWSER_HEADERS = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml",
    "accept-language": "en-US,en;q=0.9",
    "accept-encoding": "gzip, deflate, br",
}


def _make_app(**middleware_kwargs):
    app = FastAPI()
    middleware_kwargs.setdefault("rate_limit", False)
    app.add_middleware(ArcisMiddleware, **middleware_kwargs)

    @app.post("/users")
    async def users():
        return {"ok": True}

    return TestClient(app)


BENCH_PAYLOADS = [
    ("isAdmin", {"name": "john", "email": "j@x.com", "isAdmin": True}),
    ("role", {"username": "j", "role": "superadmin"}),
    ("nested-permissions", {"profile": {"name": "j", "permissions": ["admin", "billing"]}}),
]


@pytest.mark.parametrize("name,body", BENCH_PAYLOADS)
def test_default_blocks_bench_payloads(name, body):
    client = _make_app()
    r = client.post("/users", json=body, headers=_BROWSER_HEADERS)
    assert r.status_code == 403, f"{name} should be blocked"


LEGIT_BODIES = [
    {"name": "Alice", "email": "alice@example.com"},
    {"profile": {"displayName": "Al", "bio": "hello world"}},
    {"user": {"name": "Bob", "address": {"city": "NYC", "zip": "10001"}}},
    {"items": [{"sku": "A1", "qty": 2}], "total": 49.99},
    {},
]


@pytest.mark.parametrize("body", LEGIT_BODIES)
def test_legit_bodies_allowed(body):
    client = _make_app()
    r = client.post("/users", json=body, headers=_BROWSER_HEADERS)
    assert r.status_code == 200


def test_opt_out():
    client = _make_app(mass_assign=False)
    r = client.post("/users", json={"name": "j", "isAdmin": True}, headers=_BROWSER_HEADERS)
    assert r.status_code == 200


@pytest.mark.parametrize("key", ["is_admin", "IS_ADMIN", "is-admin", "isAdmin"])
def test_case_separator_insensitivity(key):
    client = _make_app()
    r = client.post("/users", json={"name": "j", key: True}, headers=_BROWSER_HEADERS)
    assert r.status_code == 403


def test_custom_field_list():
    # Override the default set; isAdmin no longer flagged, only "secret_flag".
    client = _make_app(mass_assign_fields=["secret_flag"])
    assert client.post("/users", json={"isAdmin": True}, headers=_BROWSER_HEADERS).status_code == 200
    assert client.post("/users", json={"secret_flag": 1}, headers=_BROWSER_HEADERS).status_code == 403
