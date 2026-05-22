"""§1.4 — protect helpers consult an optional correlation window.

The window primitive shipped in §1.3 was useful but only valuable once
the existing protect helpers know to consult it. These tests pin that
contract.
"""
from arcis.middleware.correlation import CorrelationWindow
from arcis.middleware.protect_login import check_login
from arcis.middleware.protect_api import check_api


class _FakeRequest:
    def __init__(self, body=None, headers=None):
        self._body = body or {}
        self.headers = headers or {}

    @property
    def body(self):
        return self._body


# ---------------------------------------------------------------- login flow


def test_login_records_attempt_in_correlation_window():
    window = CorrelationWindow()
    req = _FakeRequest(body={"username": "alice@x.com", "password": "hunter2"})
    result = check_login(
        req,
        check_bot=False,
        correlation_window=window,
        client_ip="1.2.3.4",
        route="/login",
    )
    assert result.allowed is True
    assert window.stats()["events_in_window"] == 1


def test_login_no_recording_when_window_or_ip_missing():
    window = CorrelationWindow()
    req = _FakeRequest(body={"username": "alice@x.com", "password": "hunter2"})
    # No window: no recording.
    check_login(req, check_bot=False)
    assert window.stats()["events_in_window"] == 0
    # Window but no IP: no recording (the window primitive treats empty
    # IP as a no-op, but the helper short-circuits earlier so it does
    # not invent a placeholder).
    check_login(req, check_bot=False, correlation_window=window, client_ip="")
    assert window.stats()["events_in_window"] == 0


def test_login_blocks_credential_stuffing():
    window = CorrelationWindow(
        credential_stuffing_distinct_values=3, window_seconds=60
    )
    for i in range(2):
        req = _FakeRequest(body={"username": f"user{i}@x.com", "password": "pw"})
        result = check_login(
            req,
            check_bot=False,
            correlation_window=window,
            client_ip="9.9.9.9",
            route="/login",
        )
        assert result.allowed is True

    # Third distinct username crosses the threshold.
    req = _FakeRequest(body={"username": "user2@x.com", "password": "pw"})
    result = check_login(
        req,
        check_bot=False,
        correlation_window=window,
        client_ip="9.9.9.9",
        route="/login",
    )
    assert result.allowed is False
    assert result.reason == "correlation"
    assert result.details["credential_stuffing"] is True


def test_login_blocks_scanner_pattern():
    window = CorrelationWindow(
        scanner_distinct_vectors=2,
        scanner_min_requests=3,
        window_seconds=60,
    )
    # Two prior cross-vector requests recorded with the live clock so
    # they land in the same 60s window as the upcoming helper call.
    window.record("9.9.9.9", "xss", "/anywhere", "GET")
    window.record("9.9.9.9", "sql", "/anywhere", "GET")
    # Now a /login hit on the same IP crosses the scanner threshold.
    req = _FakeRequest(body={"username": "alice@x.com", "password": "pw"})
    result = check_login(
        req,
        check_bot=False,
        correlation_window=window,
        client_ip="9.9.9.9",
        route="/login",
    )
    assert result.allowed is False
    assert result.reason == "correlation"
    assert result.details["scanner"] is True


def test_login_ok_path_unchanged_when_no_window():
    req = _FakeRequest(body={"username": "alice@x.com", "password": "hunter2"})
    result = check_login(req, check_bot=False)
    assert result.allowed is True
    assert result.reason == "ok"


# ------------------------------------------------------------------ api flow


def test_api_records_clean_request_in_correlation_window():
    window = CorrelationWindow()
    req = _FakeRequest(body={"hello": "world"})
    result = check_api(
        req,
        check_bot=False,
        scan_body=True,
        correlation_window=window,
        client_ip="1.2.3.4",
        route="/api/data",
    )
    assert result.allowed is True
    s = window.stats()
    assert s["tracked_ips"] == 1
    assert s["events_in_window"] == 1


def test_api_records_threat_with_real_vector_then_refuses():
    window = CorrelationWindow()
    # An obvious XSS payload should be caught by scan_threats.
    req = _FakeRequest(body={"comment": "<script>alert(1)</script>"})
    result = check_api(
        req,
        check_bot=False,
        scan_body=True,
        correlation_window=window,
        client_ip="9.9.9.9",
        route="/api/comments",
    )
    assert result.allowed is False
    assert result.reason == "threat"
    # The threat event was recorded.
    assert window.stats()["events_in_window"] == 1


def test_api_blocks_scanner_pattern_via_cross_vector_recording():
    window = CorrelationWindow(
        scanner_distinct_vectors=2,
        scanner_min_requests=3,
        window_seconds=60,
    )
    window.record("9.9.9.9", "xss", "/api/x", "POST")
    window.record("9.9.9.9", "sql", "/api/y", "POST")
    # Clean request from the same IP still crosses the scanner threshold
    # because the prior two cross-vector hits + this one >= 3 requests
    # AND >= 2 distinct vectors.
    req = _FakeRequest(body={"safe": "value"})
    result = check_api(
        req,
        check_bot=False,
        scan_body=True,
        correlation_window=window,
        client_ip="9.9.9.9",
        route="/api/z",
    )
    assert result.allowed is False
    assert result.reason == "correlation"
    assert result.details["scanner"] is True


def test_api_no_correlation_block_when_window_not_passed():
    req = _FakeRequest(body={"hello": "world"})
    result = check_api(req, check_bot=False, scan_body=True)
    assert result.allowed is True
    assert result.reason == "ok"
