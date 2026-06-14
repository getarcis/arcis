"""IP-reputation client unit tests (Python parity with the Node client tests).

All offline: the HTTP layer (`_request_json`) is monkeypatched, so no network.
"""

from __future__ import annotations

import time

import pytest

from arcis.intelligence import (
    IntelligenceClient,
    IntelligenceOptions,
    reputation_severity_tier,
)
import arcis.intelligence.client as client_mod


def wait_for(predicate, timeout: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def make_client(**overrides) -> IntelligenceClient:
    opts = IntelligenceOptions(
        endpoint="https://intel.test",
        api_key="ak_test",
        workspace_id="ws1",
        cloud_decisions=["ip-rep"],
        **overrides,
    )
    return IntelligenceClient(opts)


@pytest.fixture
def found_response(monkeypatch):
    """Monkeypatch _request_json to return a 'found' verdict; capture call args."""
    calls = []

    def fake(url, headers, timeout_s):
        calls.append((url, headers, timeout_s))
        return {
            "ip": "203.0.113.7",
            "found": True,
            "severity": 6,
            "categories": ["tor"],
            "sources": ["tor-exit"],
        }

    monkeypatch.setattr(client_mod, "_request_json", fake)
    return calls


def test_construction_requires_endpoint():
    with pytest.raises(TypeError):
        IntelligenceClient(IntelligenceOptions(endpoint=""))


def test_check_skips_private_and_unknown(monkeypatch):
    calls = []
    monkeypatch.setattr(client_mod, "_request_json", lambda *a: calls.append(a) or {})
    client = make_client()
    for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "::1", "unknown", ""]:
        rep = client.check(ip)
        assert rep.found is False
    time.sleep(0.05)
    assert calls == []
    client.close()


def test_check_inert_without_ip_rep(monkeypatch):
    calls = []
    monkeypatch.setattr(client_mod, "_request_json", lambda *a: calls.append(a) or {})
    client = IntelligenceClient(IntelligenceOptions(endpoint="https://intel.test"))
    assert client.check("203.0.113.7").found is False
    time.sleep(0.05)
    assert calls == []
    client.close()


def test_check_miss_then_cached_hit(found_response):
    client = make_client()
    first = client.check("203.0.113.7")
    assert first.found is False  # non-blocking on the miss

    assert wait_for(lambda: client.cache_size == 1)
    second = client.check("203.0.113.7")
    assert second.found is True
    assert second.severity == 6
    assert second.categories == ["tor"]
    client.close()


def test_check_dedupes_concurrent_refreshes(monkeypatch):
    calls = []

    def slow(url, headers, timeout_s):
        calls.append(url)
        time.sleep(0.05)  # widen the in-flight window
        return {"ip": "x", "found": False}

    monkeypatch.setattr(client_mod, "_request_json", slow)
    client = make_client()
    client.check("203.0.113.9")
    client.check("203.0.113.9")
    client.check("203.0.113.9")
    assert wait_for(lambda: len(calls) >= 1)
    time.sleep(0.1)
    assert len(calls) == 1
    client.close()


def test_lookup_normalizes_found_verdict(monkeypatch):
    def fake(url, headers, timeout_s):
        return {
            "ip": "203.0.113.7",
            "found": True,
            "severity": 8,
            "categories": ["tor", "abuse"],
            "sources": ["tor-exit", "abuseipdb"],
            "first_seen": "2026-06-01",
            "last_seen": "2026-06-11",
            "matched": "203.0.113.0/24",
        }

    monkeypatch.setattr(client_mod, "_request_json", fake)
    client = make_client()
    rep = client.lookup("203.0.113.7")
    assert rep.found is True
    assert rep.severity == 8
    assert rep.categories == ["tor", "abuse"]
    assert rep.sources == ["tor-exit", "abuseipdb"]
    assert rep.first_seen == "2026-06-01"
    assert rep.last_seen == "2026-06-11"
    assert rep.matched == "203.0.113.0/24"
    client.close()


def test_lookup_sends_auth_headers_and_encoded_ip(found_response):
    client = make_client()
    client.lookup("203.0.113.7")
    url, headers, _ = found_response[0]
    assert url == "https://intel.test/v1/intel/ip-reputation/203.0.113.7"
    assert headers["authorization"] == "Bearer ak_test"
    assert headers["x-workspace-id"] == "ws1"
    client.close()


def test_lookup_fails_open_on_error(monkeypatch):
    def boom(url, headers, timeout_s):
        raise RuntimeError("HTTP 500")

    monkeypatch.setattr(client_mod, "_request_json", boom)
    errors = []
    client = make_client(on_error=errors.append)
    rep = client.lookup("203.0.113.7")
    assert rep.found is False
    assert len(errors) == 1
    client.close()


def test_lookup_skips_private_ip(monkeypatch):
    calls = []
    monkeypatch.setattr(client_mod, "_request_json", lambda *a: calls.append(a) or {})
    client = make_client()
    rep = client.lookup("10.1.2.3")
    assert rep.found is False
    assert calls == []
    client.close()


def test_clean_verdict_is_cached(monkeypatch):
    calls = []

    def fake(url, headers, timeout_s):
        calls.append(url)
        return {"ip": "203.0.113.50", "found": False}

    monkeypatch.setattr(client_mod, "_request_json", fake)
    client = make_client()
    client.check("203.0.113.50")
    assert wait_for(lambda: client.cache_size == 1)
    client.check("203.0.113.50")  # cache hit, no new fetch
    time.sleep(0.05)
    assert len(calls) == 1
    client.close()


def test_eviction_beyond_cache_max(monkeypatch):
    def fake(url, headers, timeout_s):
        return {"ip": "x", "found": False}

    monkeypatch.setattr(client_mod, "_request_json", fake)
    client = make_client(cache_max=2)
    for ip in ["203.0.113.1", "203.0.113.2", "203.0.113.3"]:
        client.check(ip)
        time.sleep(0.03)  # serialize so insertion order is deterministic
    assert wait_for(lambda: client.cache_size <= 2)
    client.close()


def test_requery_after_ttl(monkeypatch):
    calls = []

    def fake(url, headers, timeout_s):
        calls.append(url)
        return {"ip": "203.0.113.7", "found": False}

    monkeypatch.setattr(client_mod, "_request_json", fake)
    client = make_client(cache_ttl_ms=1000)  # floor is 1000ms
    client.check("203.0.113.7")
    assert wait_for(lambda: client.cache_size == 1)
    assert len(calls) == 1
    time.sleep(1.05)
    client.check("203.0.113.7")  # stale -> schedules a fresh fetch
    assert wait_for(lambda: len(calls) == 2)
    client.close()


def test_no_fetch_after_close(monkeypatch):
    calls = []
    monkeypatch.setattr(client_mod, "_request_json", lambda *a: calls.append(a) or {})
    client = make_client()
    client.close()
    assert client.check("203.0.113.7").found is False
    time.sleep(0.05)
    assert calls == []


def test_reputation_severity_tier():
    assert reputation_severity_tier(10) == "critical"
    assert reputation_severity_tier(9) == "critical"
    assert reputation_severity_tier(8) == "high"
    assert reputation_severity_tier(5) == "medium"
    assert reputation_severity_tier(2) == "low"
    assert reputation_severity_tier(None) == "low"
