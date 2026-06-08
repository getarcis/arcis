"""v1.7 W2 scanner-paths wire-up integration tests for ArcisMiddleware.

ArcisMiddleware by default blocks well-known scanner probe paths with
403. Opt-out via scanner_paths=False. Real app paths with shared
prefixes (e.g. /admin/dashboard) MUST still pass.
"""

import re
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

    @app.api_route("/{full_path:path}", methods=["GET", "POST"])
    async def echo(full_path: str):
        return {"ok": True, "path": "/" + full_path}

    return TestClient(app)


# Three bench scanner_burst payloads
BENCH_PATHS = ["/admin", "/wp-admin", "/.env"]


@pytest.mark.parametrize("path", BENCH_PATHS)
def test_default_denies_bench_paths(path):
    client = _make_app()
    r = client.get(path, headers=_BROWSER_HEADERS)
    assert r.status_code == 403


# Broader probe corpus
PROBE_PATHS = [
    "/.env.local",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.aws/credentials",
    "/wp-login.php",
    "/wp-config.php",
    "/xmlrpc.php",
    "/phpmyadmin/index.php",
    "/pma/",
    "/adminer.php",
    "/phpinfo.php",
    "/server-status",
    "/administrator",
]


@pytest.mark.parametrize("path", PROBE_PATHS)
def test_default_denies_broader_probes(path):
    client = _make_app()
    r = client.get(path, headers=_BROWSER_HEADERS)
    assert r.status_code == 403


# Real app routes with overlapping prefixes — MUST pass.
LEGIT_PATHS = [
    "/",
    "/admin/dashboard",
    "/admin/users/42",
    "/api/v1/users",
    "/healthcheck",
    "/env-vars",
    "/environment",
    "/gitlab/projects",
    "/static/image.png",
    "/login",
]


@pytest.mark.parametrize("path", LEGIT_PATHS)
def test_legit_paths_allowed(path):
    client = _make_app()
    r = client.get(path, headers=_BROWSER_HEADERS)
    assert r.status_code == 200


def test_opt_out():
    client = _make_app(scanner_paths=False)
    assert client.get("/.env", headers=_BROWSER_HEADERS).status_code == 200
    assert client.get("/wp-admin", headers=_BROWSER_HEADERS).status_code == 200


def test_custom_patterns():
    client = _make_app(scanner_path_patterns=[re.compile(r"^/secret-only$")])
    assert client.get("/secret-only", headers=_BROWSER_HEADERS).status_code == 403
    # Default patterns no longer apply when custom list is supplied.
    assert client.get("/.env", headers=_BROWSER_HEADERS).status_code == 200


def test_dry_run_does_not_block():
    client = _make_app(dry_run=True)
    assert client.get("/.env", headers=_BROWSER_HEADERS).status_code == 200
