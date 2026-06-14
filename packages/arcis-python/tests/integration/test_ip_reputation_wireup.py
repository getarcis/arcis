"""Phase C cloud IP-reputation wire-up tests (FastAPI ArcisMiddleware).

Parity with the Node integration test. The HTTP layer is monkeypatched (no
network). Lookups are cache-first and non-blocking: the first request from an
IP misses (allowed) and schedules a background refresh; later requests read the
cached verdict and block when severity >= block_threshold. Unreachable service
fails open; omitting cloud_decisions makes it inert.
"""

from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from arcis.fastapi import ArcisMiddleware
import arcis.intelligence.client as client_mod

_BROWSER_HEADERS = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}
PUBLIC_IP = "203.0.113.50"
CLEAN_IP = "198.51.100.20"


def _make_app(**middleware_kwargs) -> TestClient:
    app = FastAPI()
    middleware_kwargs.setdefault("rate_limit", False)
    app.add_middleware(ArcisMiddleware, **middleware_kwargs)

    @app.get("/")
    async def root():
        return {"ok": True}

    return TestClient(app)


def _headers(ip: str) -> dict:
    return {**_BROWSER_HEADERS, "x-forwarded-for": ip}


def _poll_until_status(client: TestClient, ip: str, status: int, tries: int = 60) -> bool:
    for _ in range(tries):
        r = client.get("/", headers=_headers(ip))
        if r.status_code == status:
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def stub_verdicts(monkeypatch):
    """Monkeypatch the HTTP layer with a per-IP verdict map; count hits."""
    state = {"verdicts": {}, "hits": 0}

    def fake(url, headers, timeout_s):
        state["hits"] += 1
        ip = url.rsplit("/", 1)[-1]
        v = state["verdicts"].get(ip)
        if not v:
            return {"ip": ip, "found": False}
        return {
            "ip": ip,
            "found": True,
            "severity": v["severity"],
            "categories": v.get("categories", ["abuse"]),
            "sources": ["tor-exit"],
            "first_seen": "2026-06-11",
            "last_seen": "2026-06-11",
            "matched": ip,
        }

    monkeypatch.setattr(client_mod, "_request_json", fake)
    return state


def test_blocks_known_bad_after_warmup(stub_verdicts):
    stub_verdicts["verdicts"][PUBLIC_IP] = {"severity": 9, "categories": ["botnet"]}
    client = _make_app(
        intelligence={
            "endpoint": "https://intel.test",
            "cloud_decisions": ["ip-rep"],
            "block_threshold": 7,
        }
    )
    # First request is a cache miss -> allowed.
    first = client.get("/", headers=_headers(PUBLIC_IP))
    assert first.status_code == 200
    # After the background refresh warms the cache, the IP is blocked.
    assert _poll_until_status(client, PUBLIC_IP, 403)


def test_never_blocks_clean_ip(stub_verdicts):
    stub_verdicts["verdicts"][PUBLIC_IP] = {"severity": 9}
    client = _make_app(
        intelligence={
            "endpoint": "https://intel.test",
            "cloud_decisions": ["ip-rep"],
            "block_threshold": 7,
        }
    )
    for _ in range(5):
        r = client.get("/", headers=_headers(CLEAN_IP))
        assert r.status_code == 200
        time.sleep(0.02)


def test_fails_open_on_transport_error(monkeypatch):
    def boom(url, headers, timeout_s):
        raise RuntimeError("unreachable")

    monkeypatch.setattr(client_mod, "_request_json", boom)
    client = _make_app(
        intelligence={
            "endpoint": "https://intel.test",
            "cloud_decisions": ["ip-rep"],
            "block_threshold": 1,
        }
    )
    # Even with block_threshold 1, an unreachable service never warms the cache.
    assert not _poll_until_status(client, PUBLIC_IP, 403, tries=8)


def test_inert_without_cloud_decisions(stub_verdicts):
    stub_verdicts["verdicts"][PUBLIC_IP] = {"severity": 9}
    client = _make_app(
        intelligence={"endpoint": "https://intel.test", "block_threshold": 1}
    )
    for _ in range(4):
        r = client.get("/", headers=_headers(PUBLIC_IP))
        assert r.status_code == 200
        time.sleep(0.02)
    assert stub_verdicts["hits"] == 0


def test_dry_run_never_blocks(stub_verdicts):
    stub_verdicts["verdicts"][PUBLIC_IP] = {"severity": 10}
    client = _make_app(
        dry_run=True,
        intelligence={
            "endpoint": "https://intel.test",
            "cloud_decisions": ["ip-rep"],
            "block_threshold": 1,
        },
    )
    client.get("/", headers=_headers(PUBLIC_IP))  # warm
    time.sleep(0.1)
    assert not _poll_until_status(client, PUBLIC_IP, 403, tries=6)
