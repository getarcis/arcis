"""
Tests for SignupProtection / check_signup — composite signup-endpoint protection.
Closes the Arcjet `protectSignup` gap while staying fully local.
"""

import pytest

from arcis.middleware.signup_protection import (
    SignupProtection,
    check_signup,
)


class FakeRequest:
    """Minimal request object matching the shape bot_detection + rate_limit expect."""

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


# ─── Pure check_signup ─────────────────────────────────────────────────────────

class TestCheckSignup:
    def test_allows_valid_human_signup(self):
        req = FakeRequest(headers=_browser_headers(), body={"email": "alice@gmail.com"})
        out = check_signup(req)
        assert out.allowed is True
        assert out.reason == "ok"

    def test_blocks_missing_email(self):
        req = FakeRequest(headers=_browser_headers(), body={})
        assert check_signup(req).reason == "missing_email"

    def test_blocks_invalid_syntax(self):
        req = FakeRequest(headers=_browser_headers(), body={"email": "not-an-email"})
        assert check_signup(req).reason == "invalid_email"

    def test_blocks_disposable_domain(self):
        req = FakeRequest(
            headers=_browser_headers(), body={"email": "throwaway@mailinator.com"}
        )
        assert check_signup(req).reason == "disposable_email"

    def test_blocks_automated_bot(self):
        req = FakeRequest(
            headers={"user-agent": "curl/8.0"}, body={"email": "alice@gmail.com"}
        )
        assert check_signup(req).reason == "bot"

    def test_allows_whitelisted_bot_categories(self):
        req = FakeRequest(
            headers={"user-agent": "Googlebot/2.1"}, body={"email": "alice@gmail.com"}
        )
        assert check_signup(req, allowed_bot_categories=["SEARCH_ENGINE"]).allowed is True

    def test_custom_email_field(self):
        req = FakeRequest(headers=_browser_headers(), body={"contact": "alice@gmail.com"})
        assert check_signup(req, email_field="contact").allowed is True

    def test_allowed_email_domains_bypasses_disposable(self):
        req = FakeRequest(headers=_browser_headers(), body={"email": "ci@mailinator.com"})
        assert check_signup(
            req, allowed_email_domains=["mailinator.com"]
        ).allowed is True


# ─── SignupProtection (stateful) ───────────────────────────────────────────────

class TestSignupProtection:
    def test_happy_path(self):
        sp = SignupProtection(rate_limit_max=None)
        try:
            req = FakeRequest(headers=_browser_headers(), body={"email": "a@gmail.com"})
            assert sp.check(req).allowed is True
        finally:
            sp.close()

    def test_bot_blocked_before_rate_limit(self):
        sp = SignupProtection(rate_limit_max=5)
        try:
            req = FakeRequest(
                headers={"user-agent": "curl/8.0"}, body={"email": "a@gmail.com"}
            )
            out = sp.check(req)
            assert out.allowed is False
            assert out.reason == "bot"
        finally:
            sp.close()

    def test_rate_limits_repeated_signups(self):
        sp = SignupProtection(rate_limit_max=2, rate_limit_window_ms=60_000)
        try:
            results = []
            for _ in range(4):
                req = FakeRequest(
                    headers=_browser_headers(), body={"email": "a@gmail.com"}
                )
                results.append(sp.check(req))
            allowed = [r for r in results if r.allowed]
            blocked = [r for r in results if not r.allowed]
            assert len(allowed) == 2
            assert any(r.reason == "rate_limited" for r in blocked)
        finally:
            sp.close()

    def test_on_blocked_callback_fires(self):
        calls = []
        sp = SignupProtection(
            rate_limit_max=None, on_blocked=lambda req, res: calls.append(res.reason)
        )
        try:
            req = FakeRequest(headers=_browser_headers(), body={"email": "nope"})
            sp.check(req)
            assert calls == ["invalid_email"]
        finally:
            sp.close()

    def test_close_is_idempotent(self):
        sp = SignupProtection(rate_limit_max=2)
        sp.close()
        sp.close()  # must not raise
