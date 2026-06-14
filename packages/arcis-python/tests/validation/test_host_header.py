"""Host-header validation tests (V41) — parity with the Node host-header tests."""

import pytest

from arcis import validate_host, is_host_allowed

_ALLOW = ["app.example.com", "*.tenant.example.com"]


@pytest.mark.parametrize("host", [
    "app.example.com",
    "app.example.com:443",      # port stripped
    "APP.EXAMPLE.COM",          # case-insensitive
    "a.tenant.example.com",     # one-level wildcard
    "b.tenant.example.com:8080",
])
def test_allows(host):
    assert validate_host(host, _ALLOW).safe is True


@pytest.mark.parametrize("host", [
    "attacker.com",
    "evil.example.com",            # not under the wildcard
    "a.b.tenant.example.com",      # two levels — wildcard is single-level
    "tenant.example.com",          # wildcard requires a label
    "app.example.com.attacker.com",  # suffix-spoof
])
def test_rejects(host):
    assert validate_host(host, _ALLOW).safe is False


def test_default_deny_empty_allowlist():
    r = validate_host("app.example.com", [])
    assert r.safe is False
    assert "default-deny" in (r.reason or "")


def test_missing_host():
    assert validate_host("", _ALLOW).safe is False


def test_is_host_allowed_wrapper():
    assert is_host_allowed("app.example.com", _ALLOW) is True
    assert is_host_allowed("evil.com", _ALLOW) is False
