"""
Token-budget protection middleware for Python.

Caps per-key token spend over a sliding window — meant for routes that proxy
LLM calls, where a tight 100-req/min rate limit isn't enough because a single
50KB prompt costs the same as 1000 small requests.

Mirrors the Node implementation at
``packages/arcis-node/src/middleware/token-budget.ts``.

Usage with Flask:

.. code-block:: python

    from flask import Flask, request, jsonify
    from arcis.middleware.token_budget import TokenBudget, TokenBudgetExceeded

    app = Flask(__name__)
    guard = TokenBudget(max_tokens=100_000, window_seconds=3600,
                        max_request_tokens=5_000)

    @app.post("/chat")
    def chat():
        try:
            guard.check(request)
        except TokenBudgetExceeded as e:
            return jsonify(e.to_dict()), e.status_code
        # ...

Or as a FastAPI dependency:

.. code-block:: python

    from fastapi import FastAPI, Request, Depends, HTTPException
    from arcis.middleware.token_budget import TokenBudget, TokenBudgetExceeded

    guard = TokenBudget(max_tokens=100_000)

    async def enforce_budget(request: Request):
        try:
            await guard.acheck(request)
        except TokenBudgetExceeded as e:
            raise HTTPException(status_code=e.status_code, detail=e.message)

    @app.post("/chat", dependencies=[Depends(enforce_budget)])
    async def chat(): ...
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional


# ─── Defaults ──────────────────────────────────────────────────────────────

_DEFAULT_MAX_TOKENS = 100_000
_DEFAULT_WINDOW_SECONDS = 60 * 60  # 1 hour
_DEFAULT_MESSAGE = "Token budget exceeded for this window."
_DEFAULT_MESSAGE_OVERSIZE = "Request exceeds the per-request token limit."


@dataclass
class _Entry:
    used: int
    reset_time: float


class TokenBudgetExceeded(Exception):
    """Raised when a request would push a key past its token budget.

    Carries enough information for the caller to construct a 429 (or 413
    when ``oversize=True``) response with proper headers.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        used: int,
        max_tokens: int,
        request_tokens: int,
        retry_after_seconds: int,
        oversize: bool = False,
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.used = used
        self.max_tokens = max_tokens
        self.request_tokens = request_tokens
        self.retry_after_seconds = retry_after_seconds
        self.oversize = oversize

    def to_dict(self) -> Dict[str, Any]:
        body: Dict[str, Any] = {"error": self.message}
        if self.oversize:
            body["requestTokens"] = self.request_tokens
            body["maxRequestTokens"] = self.max_tokens
        else:
            body["used"] = self.used
            body["maxTokens"] = self.max_tokens
            body["retryAfter"] = self.retry_after_seconds
        return body


def _default_key_generator(request: Any) -> str:
    """Default key: client IP, fall back to ``unknown``.

    Reads the IP from the most common shapes (Flask ``request.remote_addr``,
    Starlette/FastAPI ``request.client.host``, raw mappings) without
    depending on any web framework being installed.
    """
    if hasattr(request, "remote_addr"):
        ip = getattr(request, "remote_addr", None)
        if ip:
            return str(ip)
    client = getattr(request, "client", None)
    if client is not None and getattr(client, "host", None):
        return str(client.host)
    if isinstance(request, dict):
        ip = request.get("ip") or request.get("remote_addr")
        if ip:
            return str(ip)
    return "unknown"


def _default_estimate_tokens(request: Any) -> int:
    """Approximate OpenAI's "1 token ≈ 4 characters" rule.

    Reads body / json / query off whatever shape the request happens to be,
    falling back to ``getattr`` so it works with Flask, FastAPI, Django, and
    plain mappings without import-time framework coupling.
    """

    def _byte_length(obj: Any) -> int:
        if obj is None:
            return 0
        if isinstance(obj, (bytes, bytearray)):
            return len(obj)
        if isinstance(obj, str):
            return len(obj.encode("utf-8"))
        try:
            return len(json.dumps(obj, default=str).encode("utf-8"))
        except (TypeError, ValueError):
            return 0

    bytes_total = 0
    # Flask: request.get_json(silent=True) / request.data / request.form
    if hasattr(request, "get_json"):
        try:
            json_body = request.get_json(silent=True)  # type: ignore[call-arg]
        except (TypeError, ValueError):
            json_body = None
        if json_body is not None:
            bytes_total += _byte_length(json_body)
    if hasattr(request, "data"):
        bytes_total += _byte_length(getattr(request, "data", None))
    # FastAPI/Starlette: request.body would be async — use cached attrs only
    cached_body = getattr(request, "_body", None)
    if cached_body is not None:
        bytes_total += _byte_length(cached_body)
    # Plain Python mapping (tests, custom adapters)
    if isinstance(request, dict):
        bytes_total += _byte_length(request.get("body"))
        bytes_total += _byte_length(request.get("query"))
    # Query string
    if hasattr(request, "args"):
        try:
            bytes_total += _byte_length(dict(request.args.items()))
        except (TypeError, ValueError):
            pass
    if hasattr(request, "query_params"):
        try:
            bytes_total += _byte_length(dict(request.query_params))
        except (TypeError, ValueError):
            pass
    return max(0, -(-bytes_total // 4))  # ceil division by 4


# ─── Public API ────────────────────────────────────────────────────────────


class TokenBudget:
    """Per-key sliding-window token-budget enforcer.

    Thread-safe in-memory store — fine for single-process apps. For
    multi-instance deployments wire a custom store via ``key_generator`` that
    proxies to Redis (Phase B).
    """

    def __init__(
        self,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
        window_seconds: float = _DEFAULT_WINDOW_SECONDS,
        max_request_tokens: Optional[int] = None,
        key_generator: Optional[Callable[[Any], str]] = None,
        estimate_tokens: Optional[Callable[[Any], int]] = None,
        status_code: int = 429,
        status_code_oversize: int = 413,
        message: str = _DEFAULT_MESSAGE,
        message_oversize: str = _DEFAULT_MESSAGE_OVERSIZE,
        skip: Optional[Callable[[Any], bool]] = None,
    ):
        self.max_tokens = max_tokens
        self.window_seconds = window_seconds
        self.max_request_tokens = max_request_tokens
        self.key_generator = key_generator or _default_key_generator
        self.estimate_tokens = estimate_tokens or _default_estimate_tokens
        self.status_code = status_code
        self.status_code_oversize = status_code_oversize
        self.message = message
        self.message_oversize = message_oversize
        self.skip = skip
        self._store: Dict[str, _Entry] = {}
        self._lock = threading.Lock()

    # ── core ────────────────────────────────────────────────────────────

    def check(self, request: Any) -> Dict[str, Any]:
        """Charge this request against the budget. Raise on violations.

        Raises:
            TokenBudgetExceeded: When the request alone exceeds the
                per-request cap, OR when the projected window total would
                exceed ``max_tokens``.

        Returns:
            Dict of headers to apply to the eventual response — caller is
            expected to forward these to the framework's response object.
        """
        if self.skip is not None and self.skip(request):
            return {}

        try:
            estimated = self.estimate_tokens(request)
        except Exception:
            estimated = 0
        if not isinstance(estimated, int) or estimated < 0:
            estimated = 0

        # Per-request cap (rejected before charging the budget)
        if (
            self.max_request_tokens is not None
            and estimated > self.max_request_tokens
        ):
            raise TokenBudgetExceeded(
                self.message_oversize,
                status_code=self.status_code_oversize,
                used=0,
                max_tokens=self.max_request_tokens,
                request_tokens=estimated,
                retry_after_seconds=0,
                oversize=True,
            )

        key = self.key_generator(request)
        now = time.monotonic()

        with self._lock:
            entry = self._store.get(key)
            if entry is None or entry.reset_time < now:
                entry = _Entry(used=0, reset_time=now + self.window_seconds)
                self._store[key] = entry

            projected = entry.used + estimated
            reset_seconds = max(0, int(entry.reset_time - now + 0.999))

            if projected > self.max_tokens:
                raise TokenBudgetExceeded(
                    self.message,
                    status_code=self.status_code,
                    used=entry.used,
                    max_tokens=self.max_tokens,
                    request_tokens=estimated,
                    retry_after_seconds=reset_seconds,
                )

            entry.used = projected
            remaining = max(0, self.max_tokens - entry.used)

            return {
                "X-Token-Budget-Limit": str(self.max_tokens),
                "X-Token-Budget-Used": str(entry.used),
                "X-Token-Budget-Remaining": str(remaining),
                "X-Token-Budget-Reset": str(reset_seconds),
                "X-Token-Budget-Request-Cost": str(estimated),
            }

    async def acheck(self, request: Any) -> Dict[str, Any]:
        """Async wrapper around :meth:`check` for FastAPI/Starlette."""
        return self.check(request)

    # ── inspection ──────────────────────────────────────────────────────

    def inspect(self, key: str) -> Optional[Dict[str, float]]:
        """Read-only view of a key's current budget state. Returns None if
        the key has never been charged (or its window has expired)."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            return {"used": entry.used, "reset_time": entry.reset_time}

    def reset(self, key: Optional[str] = None) -> None:
        """Clear a single key's budget, or every key if ``key`` is None.
        Mainly for tests."""
        with self._lock:
            if key is None:
                self._store.clear()
            else:
                self._store.pop(key, None)


def token_budget(**kwargs: Any) -> TokenBudget:
    """Convenience factory mirroring Node's ``tokenBudget(opts)`` API."""
    return TokenBudget(**kwargs)


__all__ = [
    "TokenBudget",
    "TokenBudgetExceeded",
    "token_budget",
]
