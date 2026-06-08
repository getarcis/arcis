"""v1.7 W1 bot UA wire-up integration tests for ArcisMiddleware (FastAPI).

ArcisMiddleware by default classifies the request User-Agent and denies two
categories with 403:
  - AUTOMATED: headless browser automation (Selenium, Puppeteer, Playwright,
    PhantomJS, WebDriver, Headless Chrome).
  - SECURITY_SCANNER: offensive scanners (sqlmap, nikto, nuclei, nmap,
    masscan, wpscan, Acunetix, Nessus, dirbuster).

SCRAPER (curl, wget, python-requests, monitoring) is NOT denied by default:
that category also covers legitimate non-browser clients such as health
checks and server-to-server calls. Blocking scrapers is opt-in via
bot_deny=["AUTOMATED", "SCRAPER"].
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from arcis.fastapi import ArcisMiddleware


def _make_app(**middleware_kwargs):
    app = FastAPI()
    middleware_kwargs.setdefault("rate_limit", False)
    app.add_middleware(ArcisMiddleware, **middleware_kwargs)

    @app.get("/echo")
    async def echo():
        return {"ok": True}

    return TestClient(app)


_BROWSER_HEADERS = {
    "accept": "text/html,application/xhtml+xml",
    "accept-language": "en-US,en;q=0.9",
    "accept-encoding": "gzip, deflate, br",
}

AUTOMATED_BOTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/534.34",
    "Mozilla/5.0 (compatible; Selenium/4.16.0)",
]

SECURITY_SCANNERS = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)",
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "masscan/1.3.2",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
]

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

NON_BROWSER_CLIENTS = ["curl/7.68.0", "python-requests/2.28.0", "Wget/1.21.3"]


@pytest.mark.parametrize("ua", AUTOMATED_BOTS)
def test_default_denies_automated_bots(ua):
    r = _make_app().get("/echo", headers={"user-agent": ua})
    assert r.status_code == 403


@pytest.mark.parametrize("ua", SECURITY_SCANNERS)
def test_default_denies_security_scanners(ua):
    r = _make_app().get("/echo", headers={"user-agent": ua})
    assert r.status_code == 403


@pytest.mark.parametrize("ua", BROWSERS)
def test_default_allows_browsers(ua):
    r = _make_app().get("/echo", headers={"user-agent": ua, **_BROWSER_HEADERS})
    assert r.status_code == 200


@pytest.mark.parametrize("ua", NON_BROWSER_CLIENTS)
def test_default_allows_non_browser_clients(ua):
    # Bare UA, no Accept headers: mirrors a curl health check / uptime monitor.
    r = _make_app().get("/echo", headers={"user-agent": ua})
    assert r.status_code == 200


def test_bot_false_lets_scanner_through():
    r = _make_app(bot=False).get("/echo", headers={"user-agent": "sqlmap/1.7.2"})
    assert r.status_code == 200


def test_opt_in_scraper_deny_blocks_curl():
    r = _make_app(bot_deny=["AUTOMATED", "SCRAPER"]).get(
        "/echo", headers={"user-agent": "curl/7.68.0"}
    )
    assert r.status_code == 403


def test_dry_run_does_not_block_scanner():
    r = _make_app(dry_run=True).get("/echo", headers={"user-agent": "sqlmap/1.7.2"})
    assert r.status_code == 200


def test_categorization_regression():
    from arcis.middleware.bot_detection import detect_bot

    class _StubReq:
        def __init__(self, ua):
            self.headers = {"user-agent": ua}

    # Offensive scanners -> SECURITY_SCANNER
    assert detect_bot(_StubReq("sqlmap/1.7")).category == "SECURITY_SCANNER"
    assert detect_bot(_StubReq("Nikto/2.5")).category == "SECURITY_SCANNER"
    assert detect_bot(_StubReq("Nuclei/2.9")).category == "SECURITY_SCANNER"
    assert detect_bot(_StubReq("masscan/1.3")).category == "SECURITY_SCANNER"
    # Generic non-browser clients stay SCRAPER
    assert detect_bot(_StubReq("curl/7.68.0")).category == "SCRAPER"
    assert detect_bot(_StubReq("python-requests/2.28")).category == "SCRAPER"
    # Headless automation -> AUTOMATED
    assert detect_bot(_StubReq("Mozilla/5.0 HeadlessChrome/120.0.0.0")).category == "AUTOMATED"
    assert detect_bot(_StubReq("PhantomJS/2.1.1")).category == "AUTOMATED"
