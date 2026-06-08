"""v1.7 W1 bot UA wire-up integration tests for ArcisMiddleware (FastAPI).

ArcisMiddleware by default classifies the request User-Agent and denies the
AUTOMATED category (headless browser automation: Selenium, Puppeteer,
Playwright, PhantomJS, WebDriver, Headless Chrome) with 403. Opt-out via
bot=False.

SCRAPER (curl, wget, python-requests, sqlmap, nikto, nuclei) is NOT denied by
default: that category also covers legitimate non-browser clients such as
health checks, monitoring, and server-to-server calls. Blocking scrapers is
opt-in via bot_deny=["AUTOMATED", "SCRAPER"].
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


# Real browser baseline headers so behavioral detection falls all the way
# through for the browser cases.
_BROWSER_HEADERS = {
    "accept": "text/html,application/xhtml+xml",
    "accept-language": "en-US,en;q=0.9",
    "accept-encoding": "gzip, deflate, br",
}


# ──────────────────────────────────────────────────────────────────────────
# Default-on denies AUTOMATED browser-automation UAs
# ──────────────────────────────────────────────────────────────────────────

AUTOMATED_BOTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/534.34",
    "Mozilla/5.0 (compatible; Selenium/4.16.0)",
]


@pytest.mark.parametrize("ua", AUTOMATED_BOTS)
def test_default_denies_automated_bots(ua):
    client = _make_app()
    r = client.get("/echo", headers={"user-agent": ua})
    assert r.status_code == 403


# ──────────────────────────────────────────────────────────────────────────
# Default-on allows browsers, search engines, and non-browser clients
# ──────────────────────────────────────────────────────────────────────────

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]


@pytest.mark.parametrize("ua", BROWSERS)
def test_default_allows_browsers(ua):
    client = _make_app()
    r = client.get("/echo", headers={"user-agent": ua, **_BROWSER_HEADERS})
    assert r.status_code == 200


# SCRAPER-category clients are not default-denied. Bare UA, no Accept headers,
# mirrors a curl health check or an uptime monitor.
NON_BROWSER_CLIENTS = [
    "curl/7.68.0",
    "python-requests/2.28.0",
    "Wget/1.21.3",
]


@pytest.mark.parametrize("ua", NON_BROWSER_CLIENTS)
def test_default_allows_non_browser_clients(ua):
    client = _make_app()
    r = client.get("/echo", headers={"user-agent": ua})
    assert r.status_code == 200


# ──────────────────────────────────────────────────────────────────────────
# Opt-out via bot=False
# ──────────────────────────────────────────────────────────────────────────


def test_bot_false_lets_automated_through():
    client = _make_app(bot=False)
    r = client.get(
        "/echo", headers={"user-agent": "Mozilla/5.0 HeadlessChrome/120.0.0.0"}
    )
    assert r.status_code == 200


# ──────────────────────────────────────────────────────────────────────────
# Opt-in scraper blocking via bot_deny
# ──────────────────────────────────────────────────────────────────────────


def test_opt_in_scraper_deny_blocks_curl():
    client = _make_app(bot_deny=["AUTOMATED", "SCRAPER"])
    r = client.get("/echo", headers={"user-agent": "curl/7.68.0"})
    assert r.status_code == 403


def test_opt_in_scraper_deny_blocks_sqlmap():
    client = _make_app(bot_deny=["AUTOMATED", "SCRAPER"])
    r = client.get(
        "/echo", headers={"user-agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"}
    )
    assert r.status_code == 403


# ──────────────────────────────────────────────────────────────────────────
# Dry-run mode never blocks
# ──────────────────────────────────────────────────────────────────────────


def test_dry_run_does_not_block_automated():
    client = _make_app(dry_run=True)
    r = client.get(
        "/echo", headers={"user-agent": "Mozilla/5.0 HeadlessChrome/120.0.0.0"}
    )
    assert r.status_code == 200


# ──────────────────────────────────────────────────────────────────────────
# Corpus categorization regression — catches future drift where patterns
# silently fall through enum validation.
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


def test_automated_bots_classify_as_automated():
    from arcis.middleware.bot_detection import detect_bot

    class _StubReq:
        def __init__(self, ua):
            self.headers = {"user-agent": ua}

    assert (
        detect_bot(_StubReq("Mozilla/5.0 HeadlessChrome/120.0.0.0")).category
        == "AUTOMATED"
    )
    assert detect_bot(_StubReq("PhantomJS/2.1.1")).category == "AUTOMATED"
