"""Token-Budget Middleware Tests — Python parity with Node tests."""

import pytest

from arcis.middleware.token_budget import (
    TokenBudget,
    TokenBudgetExceeded,
    token_budget,
)


def make_request(body=None, query=None, ip="1.2.3.4", api_key=None):
    """Build a minimal mapping-shaped request that the default estimator
    + key generator handle. Avoids a Flask/FastAPI dep in tests."""
    req = {"body": body, "query": query, "ip": ip, "remote_addr": ip}
    if api_key is not None:
        req["api_key"] = api_key
    return req


# ─── Default behaviour ────────────────────────────────────────────────────


def test_safe_request_passes_and_charges_budget():
    guard = TokenBudget(max_tokens=1000)
    headers = guard.check(make_request(body={"prompt": "short"}, ip="10.0.0.1"))
    # Headers reflect that some tokens were charged
    assert int(headers["X-Token-Budget-Limit"]) == 1000
    assert int(headers["X-Token-Budget-Used"]) > 0
    assert int(headers["X-Token-Budget-Remaining"]) <= 1000
    inspected = guard.inspect("10.0.0.1")
    assert inspected is not None
    assert inspected["used"] > 0


def test_response_headers_set_on_allow():
    guard = TokenBudget(max_tokens=1000)
    headers = guard.check(make_request(body={"prompt": "short"}))
    # All 5 header keys present
    for key in (
        "X-Token-Budget-Limit",
        "X-Token-Budget-Used",
        "X-Token-Budget-Remaining",
        "X-Token-Budget-Reset",
        "X-Token-Budget-Request-Cost",
    ):
        assert key in headers


# ─── Budget exhaustion (429) ──────────────────────────────────────────────


def test_429_when_projected_exceeds_limit():
    # max_tokens=1 ensures any non-empty body blows the budget
    guard = TokenBudget(max_tokens=1)
    with pytest.raises(TokenBudgetExceeded) as info:
        guard.check(make_request(body={"prompt": "this is more than 1 token worth"}, ip="5.5.5.5"))
    err = info.value
    assert err.status_code == 429
    assert err.max_tokens == 1
    assert err.retry_after_seconds >= 0
    assert err.oversize is False
    body = err.to_dict()
    assert body["error"]
    assert body["maxTokens"] == 1


def test_per_key_isolation():
    guard = TokenBudget(max_tokens=5)
    guard.check(make_request(body="hi", ip="1.1.1.1"))
    guard.check(make_request(body="hi", ip="2.2.2.2"))
    a = guard.inspect("1.1.1.1")
    b = guard.inspect("2.2.2.2")
    assert a is not None and b is not None
    assert a["used"] <= 5
    assert b["used"] <= 5


# ─── Per-request cap (413) ────────────────────────────────────────────────


def test_413_on_oversize_request():
    guard = TokenBudget(max_tokens=100_000, max_request_tokens=2)
    with pytest.raises(TokenBudgetExceeded) as info:
        guard.check(make_request(body={"prompt": "this is too long for the per-request cap"}))
    err = info.value
    assert err.status_code == 413
    assert err.oversize is True
    body = err.to_dict()
    assert body["requestTokens"] > 0
    assert body["maxRequestTokens"] == 2


def test_oversize_does_not_charge_budget():
    guard = TokenBudget(max_tokens=100_000, max_request_tokens=2)
    with pytest.raises(TokenBudgetExceeded):
        guard.check(make_request(body={"prompt": "too big"}, ip="7.7.7.7"))
    assert guard.inspect("7.7.7.7") is None


# ─── Custom estimator + key generator ─────────────────────────────────────


def test_custom_key_generator():
    guard = TokenBudget(
        max_tokens=1,
        key_generator=lambda r: r.get("api_key") or "anon",
    )
    with pytest.raises(TokenBudgetExceeded):
        guard.check(make_request(body="this body is large enough", api_key="tenant-A"))
    with pytest.raises(TokenBudgetExceeded):
        guard.check(make_request(body="this body is large enough", api_key="tenant-B"))
    # Each tenant has its own bucket
    assert guard.inspect("tenant-A") is not None
    assert guard.inspect("tenant-B") is not None


def test_custom_estimator():
    guard = TokenBudget(max_tokens=100, estimate_tokens=lambda r: 50)
    guard.check(make_request(ip="9.9.9.9"))
    guard.check(make_request(ip="9.9.9.9"))
    inspected = guard.inspect("9.9.9.9")
    assert inspected is not None
    assert inspected["used"] == 100


# ─── Skip ─────────────────────────────────────────────────────────────────


def test_skip_bypasses_enforcement():
    guard = TokenBudget(max_tokens=1, skip=lambda r: r.get("path") == "/health")
    req = make_request(body="huge huge huge huge")
    req["path"] = "/health"
    headers = guard.check(req)
    # No headers issued for skipped requests; no charge to budget
    assert headers == {}


# ─── Edge cases ───────────────────────────────────────────────────────────


def test_empty_request_does_not_crash():
    guard = TokenBudget(max_tokens=100)
    headers = guard.check({})
    assert int(headers["X-Token-Budget-Used"]) == 0


def test_inspect_unknown_key_returns_none():
    guard = TokenBudget()
    assert guard.inspect("nobody") is None


def test_reset_single_key():
    guard = TokenBudget(max_tokens=100)
    guard.check(make_request(body={"prompt": "spend"}, ip="r.1"))
    assert guard.inspect("r.1") is not None
    guard.reset("r.1")
    assert guard.inspect("r.1") is None


def test_reset_all_keys():
    guard = TokenBudget(max_tokens=100)
    guard.check(make_request(body={"prompt": "x"}, ip="r.1"))
    guard.check(make_request(body={"prompt": "y"}, ip="r.2"))
    guard.reset()
    assert guard.inspect("r.1") is None
    assert guard.inspect("r.2") is None


def test_factory_is_alias_for_class():
    g = token_budget(max_tokens=42)
    assert isinstance(g, TokenBudget)
    assert g.max_tokens == 42
