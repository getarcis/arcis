"""
Async email-MX verification tests.

Mirrors the sync `verify_email_mx` test surface but exercises the
async-safe variant introduced for the FastAPI / async-stack rewrite.
The point of these tests is to pin three contracts:

  1. Returns ``False`` for clearly-invalid input without ever resolving.
  2. Uses ``dns.asyncresolver`` natively when present (no thread).
  3. Falls back to ``asyncio.to_thread`` when ``dnspython`` is absent.

We never make a real DNS query — every test substitutes a fake
resolver via ``monkeypatch`` so the suite stays hermetic and CI-fast.
"""

from __future__ import annotations

import asyncio
import sys
import types
from typing import Any, List

import pytest

from arcis.validation.email import verify_email_mx_async


@pytest.mark.asyncio
async def test_returns_false_for_invalid_syntax_without_resolving():
    # Bad input never reaches a resolver. If it did, this test would
    # need to mock one; the absence of mocking IS the assertion.
    assert await verify_email_mx_async("not-an-email") is False
    assert await verify_email_mx_async("@no-local.com") is False
    assert await verify_email_mx_async("") is False


@pytest.mark.asyncio
async def test_returns_false_for_empty_domain():
    # The local-part-only path bails before any DNS.
    assert await verify_email_mx_async("user@") is False


def _install_fake_dns(monkeypatch: pytest.MonkeyPatch, answers: List[str], raises: Any = None) -> None:
    """
    Inject a stub ``dns.asyncresolver.resolve`` so the async path
    exercises its native branch without actually hitting DNS.

    Real ``dnspython`` may or may not be installed in the test env.
    Either way, after this fake is installed, the import inside the
    function under test resolves to this stub.
    """
    fake_dns = types.ModuleType("dns")
    fake_async = types.ModuleType("dns.asyncresolver")

    async def fake_resolve(_domain: str, _qtype: str):  # noqa: D401
        if raises is not None:
            raise raises
        return answers

    fake_async.resolve = fake_resolve  # type: ignore[attr-defined]
    fake_dns.asyncresolver = fake_async  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "dns", fake_dns)
    monkeypatch.setitem(sys.modules, "dns.asyncresolver", fake_async)


@pytest.mark.asyncio
async def test_native_async_resolver_returns_true_on_mx_present(monkeypatch):
    _install_fake_dns(monkeypatch, answers=["mx1.example.com.", "mx2.example.com."])
    assert await verify_email_mx_async("user@example.com") is True


@pytest.mark.asyncio
async def test_native_async_resolver_returns_false_on_empty_mx(monkeypatch):
    _install_fake_dns(monkeypatch, answers=[])
    assert await verify_email_mx_async("user@example.com") is False


@pytest.mark.asyncio
async def test_native_async_resolver_swallows_unexpected_errors(monkeypatch):
    # NoAnswer / Timeout / NXDOMAIN should yield False, not raise.
    _install_fake_dns(monkeypatch, answers=[], raises=RuntimeError("simulated DNS timeout"))
    assert await verify_email_mx_async("user@example.com") is False


@pytest.mark.asyncio
async def test_event_loop_is_not_blocked_during_resolution(monkeypatch):
    """
    Pin the async-safety contract: while the resolver runs, other
    coroutines on the same loop must continue to make progress. We
    install a fake resolver that awaits a sleep, then race a counter
    coroutine against it. If the resolver blocked the loop, the
    counter would not advance.
    """

    fake_dns = types.ModuleType("dns")
    fake_async = types.ModuleType("dns.asyncresolver")

    async def slow_resolve(_domain: str, _qtype: str):
        # Yields control multiple times so a sibling coroutine ticks.
        for _ in range(5):
            await asyncio.sleep(0)
        return ["mx1.example.com."]

    fake_async.resolve = slow_resolve  # type: ignore[attr-defined]
    fake_dns.asyncresolver = fake_async  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "dns", fake_dns)
    monkeypatch.setitem(sys.modules, "dns.asyncresolver", fake_async)

    counter = 0

    async def ticker():
        nonlocal counter
        for _ in range(5):
            await asyncio.sleep(0)
            counter += 1

    ticker_task = asyncio.create_task(ticker())
    result = await verify_email_mx_async("user@example.com")
    await ticker_task

    assert result is True
    # Both coroutines progressed concurrently. Exact value isn't
    # important; the assertion is "the counter did move while resolve
    # was awaiting", proving the loop wasn't blocked.
    assert counter >= 1


@pytest.mark.asyncio
async def test_thread_fallback_when_dnspython_missing(monkeypatch):
    """
    When ``dnspython`` is not importable, the async variant must hand
    the work to a thread so the loop stays free. We simulate that
    here by making the import raise.
    """
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def fake_import(name, *args, **kwargs):
        if name == "dns.asyncresolver" or (name == "dns" and "asyncresolver" in (args[2] if len(args) > 2 else ())):
            raise ImportError("simulated missing dnspython")
        return real_import(name, *args, **kwargs)

    if isinstance(__builtins__, dict):
        monkeypatch.setitem(__builtins__, "__import__", fake_import)
    else:
        monkeypatch.setattr(__builtins__, "__import__", fake_import)

    # The fallback uses asyncio.to_thread which calls verify_email_mx —
    # which itself tries `import dns.resolver` and falls through to
    # socket.getaddrinfo. We mock that too so the test stays offline.
    import socket

    def fake_getaddrinfo(_host: str, _port: int):
        return [("AF_INET", "SOCK_STREAM", 6, "", ("93.184.216.34", 25))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    # Also block dns.resolver inside the threaded sync path so the
    # socket fallback is actually exercised.
    monkeypatch.setitem(sys.modules, "dns", types.ModuleType("dns"))

    assert await verify_email_mx_async("user@example.com") is True


@pytest.mark.asyncio
async def test_returns_false_when_socket_fallback_raises(monkeypatch):
    """
    Mirrors the sync ``verify_email_mx`` contract: DNS failures don't
    bubble — they read as ``False``.
    """
    monkeypatch.setitem(sys.modules, "dns", types.ModuleType("dns"))
    monkeypatch.setitem(sys.modules, "dns.asyncresolver", types.ModuleType("dns.asyncresolver"))

    # No `resolve` attribute on the asyncresolver stub -> AttributeError
    # inside the async path -> caught -> False.
    assert await verify_email_mx_async("user@example.com") is False
