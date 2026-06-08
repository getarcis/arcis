"""v1.7 W5 SSRF body-URL validation integration tests."""

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

    @app.post("/fetch")
    async def fetch():
        return {"ok": True}

    return TestClient(app)


BENCH_PAYLOADS = [
    ("loopback", "http://127.0.0.1:8080/admin"),
    ("aws-metadata", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("gcp-metadata", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ("azure-metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("decimal-ip", "http://2130706433/admin"),
    ("hex-ip", "http://0x7f000001/admin"),
    ("file-scheme", "file:///etc/passwd"),
    ("gopher-smtp", "gopher://127.0.0.1:25/_EHLO%20attacker"),
]


@pytest.mark.parametrize("name,url", BENCH_PAYLOADS)
def test_default_blocks_bench_payloads(name, url):
    client = _make_app()
    r = client.post("/fetch", json={"url": url}, headers=_BROWSER_HEADERS)
    assert r.status_code == 403, f"{name} should be blocked"


PUBLIC_URLS = [
    "https://example.com/page",
    "https://api.github.com/repos/x/y",
    "http://cdn.example.org/asset.png",
    "https://sub.domain.example.com:8443/path?a=1",
]


@pytest.mark.parametrize("url", PUBLIC_URLS)
def test_public_urls_allowed(url):
    client = _make_app()
    r = client.post("/fetch", json={"url": url}, headers=_BROWSER_HEADERS)
    assert r.status_code == 200


def test_no_url_field_passes():
    client = _make_app()
    r = client.post("/fetch", json={"name": "alice", "count": 3}, headers=_BROWSER_HEADERS)
    assert r.status_code == 200


def test_nested_private_url_caught():
    client = _make_app()
    r = client.post(
        "/fetch",
        json={"config": {"webhook": {"url": "http://169.254.169.254/"}}},
        headers=_BROWSER_HEADERS,
    )
    assert r.status_code == 403


def test_opt_out():
    client = _make_app(ssrf=False)
    r = client.post("/fetch", json={"url": "http://127.0.0.1:8080/admin"}, headers=_BROWSER_HEADERS)
    assert r.status_code == 200
