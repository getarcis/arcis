"""
Async SSRF tests — validate_url_async resolves DNS and rejects URLs
whose hostname resolves to private/loopback/link-local addresses.

Closes the DNS-rebinding TOCTOU window the sync validate_url_ssrf
leaves open. Tests use a monkeypatched resolver so they're hermetic
(no real DNS calls).
"""

import asyncio
from typing import List
from unittest.mock import patch

import pytest

from arcis.validation.url import (
    ValidateUrlOptions,
    validate_url_async,
)


# ── Hermetic fake resolver ─────────────────────────────────────────────


def _patched_resolver(mapping):
    """Return an async function that resolves hostnames per `mapping`.

    mapping: {hostname_lower: [ip_strs]}.
    """
    async def fake_resolve(hostname: str) -> List[str]:
        return list(mapping.get(hostname.lower(), []))
    return fake_resolve


# ── Literal IPs short-circuit DNS ──────────────────────────────────────


class TestLiteralIpFastPath:
    """When the hostname is already an IP literal, sync validation
    catches the private ones; async function shouldn't re-resolve."""

    @pytest.mark.asyncio
    async def test_loopback_literal_blocked_sync(self):
        # The sync layer should reject before any DNS work.
        r = await validate_url_async("http://127.0.0.1/")
        assert r.safe is False
        assert "loopback" in r.reason.lower()

    @pytest.mark.asyncio
    async def test_link_local_literal_blocked(self):
        r = await validate_url_async("http://169.254.169.254/latest/")
        assert r.safe is False

    @pytest.mark.asyncio
    async def test_public_ip_literal_allowed(self):
        r = await validate_url_async("http://8.8.8.8/")
        assert r.safe is True


# ── DNS rebinding catches ──────────────────────────────────────────────


class TestDnsRebindingProtection:
    """The whole point of validate_url_async: catch hostnames that
    sync-validate-clean but resolve to private/loopback IPs."""

    @pytest.mark.asyncio
    async def test_hostname_resolves_to_loopback_blocked(self):
        # Hostname looks public; resolves to 127.0.0.1.
        fake = _patched_resolver({"7f000001.rebind.it": ["127.0.0.1"]})
        with patch("arcis.validation.url._resolve_async", fake):
            r = await validate_url_async("http://7f000001.rebind.it/")
        assert r.safe is False
        assert "loopback" in r.reason.lower()
        assert "127.0.0.1" in r.reason

    @pytest.mark.asyncio
    async def test_hostname_resolves_to_private_blocked(self):
        fake = _patched_resolver({"internal.example": ["10.0.0.5"]})
        with patch("arcis.validation.url._resolve_async", fake):
            r = await validate_url_async("http://internal.example/")
        assert r.safe is False
        assert "10.0.0.0/8" in r.reason

    @pytest.mark.asyncio
    async def test_hostname_resolves_to_link_local_blocked(self):
        fake = _patched_resolver({"meta.example": ["169.254.169.254"]})
        with patch("arcis.validation.url._resolve_async", fake):
            r = await validate_url_async("http://meta.example/")
        assert r.safe is False
        assert "link-local" in r.reason

    @pytest.mark.asyncio
    async def test_hostname_with_mixed_answers_fails_closed(self):
        # First A record is public, second is loopback. The classic
        # rebind shape — fail-closed even though one IP is "fine".
        fake = _patched_resolver(
            {"mixed.example": ["8.8.8.8", "127.0.0.1"]}
        )
        with patch("arcis.validation.url._resolve_async", fake):
            r = await validate_url_async("http://mixed.example/")
        assert r.safe is False
        assert "loopback" in r.reason.lower()

    @pytest.mark.asyncio
    async def test_hostname_resolves_to_all_public_allowed(self):
        fake = _patched_resolver(
            {"public.example": ["8.8.8.8", "1.1.1.1"]}
        )
        with patch("arcis.validation.url._resolve_async", fake):
            r = await validate_url_async("http://public.example/")
        assert r.safe is True


# ── Edge cases ─────────────────────────────────────────────────────────


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_dns_returns_no_addresses_fail_closed(self):
        fake = _patched_resolver({"nowhere.example": []})
        with patch("arcis.validation.url._resolve_async", fake):
            r = await validate_url_async("http://nowhere.example/")
        assert r.safe is False
        assert "no addresses" in r.reason.lower()

    @pytest.mark.asyncio
    async def test_dns_resolver_raises_fail_closed(self):
        async def boom(hostname):
            raise RuntimeError("DNS server down")

        with patch("arcis.validation.url._resolve_async", boom):
            r = await validate_url_async("http://example.com/")
        assert r.safe is False
        assert "dns resolution failed" in r.reason.lower()

    @pytest.mark.asyncio
    async def test_dns_timeout_fail_closed(self):
        async def slow(hostname):
            await asyncio.sleep(10)
            return ["8.8.8.8"]

        with patch("arcis.validation.url._resolve_async", slow):
            r = await validate_url_async(
                "http://slow.example/", timeout_seconds=0.05
            )
        assert r.safe is False
        assert "timed out" in r.reason.lower()

    @pytest.mark.asyncio
    async def test_allowed_hosts_skips_dns_check(self):
        # User explicitly trusts internal.example; don't resolve.
        opts = ValidateUrlOptions(allowed_hosts=["internal.example"])
        # The fake resolver returns loopback — but we should never call it.
        fake = _patched_resolver({"internal.example": ["127.0.0.1"]})
        with patch("arcis.validation.url._resolve_async", fake):
            r = await validate_url_async(
                "http://internal.example/", opts
            )
        assert r.safe is True

    @pytest.mark.asyncio
    async def test_sync_check_failure_short_circuits(self):
        # If the sync layer rejects (e.g., disallowed protocol), we
        # shouldn't even start a DNS lookup.
        called = {"count": 0}

        async def counting_resolve(hostname):
            called["count"] += 1
            return ["8.8.8.8"]

        with patch("arcis.validation.url._resolve_async", counting_resolve):
            r = await validate_url_async("file:///etc/passwd")
        assert r.safe is False
        assert called["count"] == 0
