"""v1.7 W1 bot UA wire-up integration tests for ArcisMiddleware (FastAPI).

ArcisMiddleware by default classifies the request User-Agent and denies
the AUTOMATED + SCRAPER categories with 403. Opt-out via bot=False.

The five "bench bot" UAs (curl, python-requests, sqlmap, nikto, nuclei)
MUST be denied by default. These are the same payloads the local
benchmark fires against the mealie target.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from arcis.fastapi import ArcisMiddleware


# ──────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────


def _make_app(**middleware_kwargs):
    """Build a minimal FastAPI app with ArcisMiddleware applied.

    rate_limit=False so we never hit a 429 during these UA tests.
    """
    app = FastAPI()
    middleware_kwargs.setdefault("rate_limit", False)
    app.add_middleware(ArcisMiddleware, **middleware_kwargs)

    @app.get("/echo")
    async def echo():
        return {"ok": True}

    return TestClient(app)


# Real browser baseline headers — match every behavioral signal a real
# browser would set so detection falls all the way through.
_BROWSER_HEADERS = {
    "accept": "text/html,application/xhtml+xml",
    "accept-language": "en-US,en;q=0.9",
    "accept-encoding": "gzip, deflate, br",
}


# ──────────────────────────────────────────────────────────────────────────
# Default-on blocks the 5 bench bot UAs
# ──────────────────────────────────────────────────────────────────────────

BENCH_BOTS = [
    "curl/7.68.0",
    "python-requests/2.28.0",
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)",
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
]


@pytest.mark.parametrize("ua", BENCH_BOTS)
def test_default_denies_bench_bots(ua):
    client = _make_app()
    r = client.get("/echo", headers={"user-agent": ua})
    assert r.status_code == 403


# ──────────────────────────────────────────────────────────────────────────
# Default-on allows real browsers + search engines
# ──────────────────────────────────────────────────────────────────────────

REAL_CLIENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]


@pytest.mark.parametrize("ua", REAL_CLIENTS)
def test_default_allows_real_clients(ua):
    client = _make_app()
    r = client.get("/echo", headers={"user-agent": ua, **_BROWSER_HEADERS})
    assert r.status_code == 200


# ──────────────────────────────────────────────────────────────────────────
# Opt-out via bot=False
# ──────────────────────────────────────────────────────────────────────────


def test_bot_false_lets_curl_through():
    client = _make_app(bot=False)
    r = client.get("/echo", headers={"user-agent": "curl/7.68.0"})
    assert r.status_code == 200


def test_bot_false_lets_sqlmap_through():
    client = _make_app(bot=False)
    r = client.get("/echo", headers={"user-agent": "sqlmap/1.7"})
    assert r.status_code == 200


# ──────────────────────────────────────────────────────────────────────────
# Custom deny list via bot_deny
# ──────────────────────────────────────────────────────────────────────────


def test_custom_deny_only_automated_lets_scraper_through():
    # Default lumps SCRAPER + AUTOMATED. Narrowing to AUTOMATED only must
    # let curl (SCRAPER) through.
    client = _make_app(bot_deny=["AUTOMATED"])
    r = client.get("/echo", headers={"user-agent": "curl/7.68.0"})
    assert r.status_code == 200


# ──────────────────────────────────────────────────────────────────────────
# Dry-run mode never blocks
# ──────────────────────────────────────────────────────────────────────────


def test_dry_run_does_not_block_bots():
    client = _make_app(dry_run=True)
    r = client.get("/echo", headers={"user-agent": "sqlmap/1.7"})
    assert r.status_code == 200


# ──────────────────────────────────────────────────────────────────────────
# Corpus categorization regression — catches future drift where patterns
# silently fall through enum validation. v1.7 W1 prep round remapped
# 28 GENERIC + 6 SEO entries.
# ──────────────────────────────────────────────────────────────────────────


def test_bench_bots_classify_as_scraper():
    from arcis.middleware.bot_detection import detect_bot

    class _StubReq:
        def __init__(self, ua):
            self.headers = {
                "user-agent": ua,
                "accept": "text/html",
                "accept-language": "en-US",
                "accept-encoding": "gzip",
            }

    assert detect_bot(_StubReq("curl/7.68.0")).category == "SCRAPER"
    assert detect_bot(_StubReq("python-requests/2.28")).category == "SCRAPER"
    assert detect_bot(_StubReq("sqlmap/1.7")).category == "SCRAPER"
    assert detect_bot(_StubReq("Nikto/2.5")).category == "SCRAPER"
    assert detect_bot(_StubReq("Nuclei/2.9")).category == "SCRAPER"
