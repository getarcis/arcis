"""
Tests for check_login — composite login-endpoint protection.

Mirrors the existing check_signup test layout for symmetry.
"""

from arcis.middleware.protect_login import check_login


class FakeRequest:
    """Minimal request object matching the shape bot_detection expects."""

    def __init__(self, headers=None, body=None, ip="1.2.3.4"):
        self.headers = {}
        if headers:
            for k, v in headers.items():
                self.headers[k.lower()] = v
        self.body = body or {}
        self.remote_addr = ip


def _browser_headers(extra=None):
    h = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0",
        "accept": "text/html",
        "accept-language": "en-US",
        "accept-encoding": "gzip",
    }
    if extra:
        h.update(extra)
    return h


class TestCheckLogin:
    def test_allows_valid_credentials(self):
        req = FakeRequest(
            headers=_browser_headers(),
            body={"username": "alice", "password": "hunter2pwd!"},
        )
        out = check_login(req)
        assert out.allowed is True
        assert out.reason == "ok"

    def test_blocks_missing_username(self):
        req = FakeRequest(
            headers=_browser_headers(), body={"password": "hunter2pwd!"}
        )
        assert check_login(req).reason == "missing_credentials"

    def test_blocks_missing_password(self):
        req = FakeRequest(headers=_browser_headers(), body={"username": "alice"})
        assert check_login(req).reason == "missing_credentials"

    def test_blocks_empty_password(self):
        req = FakeRequest(
            headers=_browser_headers(), body={"username": "alice", "password": ""}
        )
        assert check_login(req).reason == "missing_credentials"

    def test_blocks_automated_bot(self):
        # curl-shaped UA is classified AUTOMATED by detect_bot.
        req = FakeRequest(
            headers={"user-agent": "curl/7.85.0"},
            body={"username": "alice", "password": "hunter2pwd!"},
        )
        out = check_login(req)
        assert out.allowed is False
        assert out.reason == "bot"
        assert out.details["category"] in {"AUTOMATED", "SCRAPER"}

    def test_credentials_check_skippable(self):
        req = FakeRequest(headers=_browser_headers(), body={})
        out = check_login(req, require_credentials=False)
        assert out.allowed is True

    def test_bot_check_skippable(self):
        req = FakeRequest(
            headers={"user-agent": "curl/7.85.0"},
            body={"username": "alice", "password": "hunter2pwd!"},
        )
        out = check_login(req, check_bot=False)
        assert out.allowed is True

    def test_custom_field_names(self):
        req = FakeRequest(
            headers=_browser_headers(),
            body={"email": "alice@x.com", "pw": "hunter2pwd!"},
        )
        out = check_login(req, username_field="email", password_field="pw")
        assert out.allowed is True

    def test_allowed_bot_category_bypass(self):
        req = FakeRequest(
            headers={"user-agent": "curl/7.85.0"},
            body={"username": "alice", "password": "hunter2pwd!"},
        )
        out = check_login(req, allowed_bot_categories=["AUTOMATED", "SCRAPER"])
        assert out.allowed is True
