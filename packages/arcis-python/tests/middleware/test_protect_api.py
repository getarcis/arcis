"""
Tests for check_api — composite API-endpoint protection.
"""

from arcis.middleware.protect_api import check_api


class FakeRequest:
    """Minimal request object: dict-like headers + body field."""

    def __init__(self, headers=None, body=None, ip="1.2.3.4"):
        self.headers = {}
        if headers:
            for k, v in headers.items():
                self.headers[k.lower()] = v
        self.body = body
        self.remote_addr = ip


def _browser_headers(extra=None):
    h = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0",
        "accept": "application/json",
        "accept-language": "en-US",
        "accept-encoding": "gzip",
    }
    if extra:
        h.update(extra)
    return h


class TestCheckApi:
    def test_allows_clean_human_request(self):
        req = FakeRequest(
            headers=_browser_headers({"origin": "https://app.example.com"}),
            body={"action": "transfer", "amount": 100},
        )
        out = check_api(req, expected_origins=["https://app.example.com"])
        assert out.allowed is True
        assert out.reason == "ok"

    def test_blocks_bad_origin(self):
        req = FakeRequest(
            headers=_browser_headers({"origin": "https://evil.com"}),
            body={"action": "transfer"},
        )
        out = check_api(req, expected_origins=["https://app.example.com"])
        assert out.allowed is False
        assert out.reason == "bad_origin"
        assert out.details["origin"] == "https://evil.com"

    def test_blocks_missing_origin_when_required(self):
        req = FakeRequest(headers=_browser_headers(), body={"x": 1})
        out = check_api(req, expected_origins=["https://app.example.com"])
        assert out.reason == "bad_origin"

    def test_origin_check_skipped_when_unset(self):
        req = FakeRequest(headers=_browser_headers(), body={"x": 1})
        out = check_api(req)
        assert out.allowed is True

    def test_origin_match_case_insensitive(self):
        req = FakeRequest(
            headers=_browser_headers({"origin": "https://APP.example.com/"}),
            body={"x": 1},
        )
        out = check_api(req, expected_origins=["https://app.example.com"])
        assert out.allowed is True

    def test_blocks_threat_in_body(self):
        req = FakeRequest(
            headers=_browser_headers(),
            body={"comment": "<script>alert(1)</script>"},
        )
        out = check_api(req)
        assert out.allowed is False
        assert out.reason == "threat"
        assert out.details["vector"] == "xss"

    def test_blocks_curl_bot_by_default(self):
        req = FakeRequest(
            headers={"user-agent": "curl/7.85.0"},
            body={"x": 1},
        )
        out = check_api(req)
        assert out.allowed is False
        assert out.reason == "bot"

    def test_monitoring_bot_allowed_by_default(self):
        req = FakeRequest(
            headers={
                "user-agent": "UptimeRobot/2.0 (https://uptimerobot.com)",
            },
            body={"x": 1},
        )
        out = check_api(req)
        assert out.allowed is True
        assert out.reason == "ok"

    def test_bot_check_skippable(self):
        req = FakeRequest(
            headers={"user-agent": "curl/7.85.0"},
            body={"x": 1},
        )
        out = check_api(req, check_bot=False)
        assert out.allowed is True

    def test_body_scan_skippable(self):
        req = FakeRequest(
            headers=_browser_headers(),
            body={"comment": "<script>alert(1)</script>"},
        )
        out = check_api(req, scan_body=False)
        assert out.allowed is True

    def test_nil_body_skips_scan(self):
        req = FakeRequest(headers=_browser_headers(), body=None)
        out = check_api(req)
        assert out.allowed is True
