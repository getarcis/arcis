"""
Guards API for Python.

Same Arcis decisioning (rate limit, bot detect, prompt injection, token
budget) applied to non-HTTP contexts where there is no request/response
pair. Use this for job queue workers, agent tool-call handlers,
WebSocket / SSE / gRPC handlers, background processors.

Mirrors the Node implementation at ``packages/arcis-node/src/guards.ts``.

Example:

.. code-block:: python

    from arcis.guards import Guards

    guards = Guards(
        rate_limit={"max": 50, "window_ms": 60_000},
        token_budget={"max_tokens": 100_000, "window_ms": 3_600_000},
        prompt_injection={"deny_at": "medium"},
        bot={"deny": ["AUTOMATED"]},
    )

    # In a Celery task or queue worker:
    decision = guards.run(
        key=job_user_id,
        text=user_prompt,
        tokens=estimate_tokens(user_prompt),
    )
    if not decision.ok:
        raise GuardDenied(f"{decision.vector}: {decision.reason}")
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, List, Literal, Optional, Tuple, Union

from .middleware.bot_detection import detect_bot
from .sanitizers.prompt_injection import detect_prompt_injection


GuardsVector = Literal["rate-limit", "token-budget", "prompt-injection", "bot"]
GuardsSeverity = Literal["low", "medium", "high"]


@dataclass
class GuardsDecision:
    """Result of evaluating a guards input.

    `ok` is True when every configured vector passes. When False, `vector`
    names the first denying vector and the rest of the fields describe it.
    `matches` carries prompt-injection signature matches even when the
    deny threshold was not crossed, so callers can log low-severity hits
    without blocking on them.
    """
    ok: bool
    vector: Optional[GuardsVector] = None
    reason: Optional[str] = None
    severity: Optional[GuardsSeverity] = None
    retry_after_seconds: Optional[int] = None
    matches: List[Tuple[str, GuardsSeverity]] = field(default_factory=list)


@dataclass
class _RLEntry:
    count: int
    reset_time: float


@dataclass
class _TBEntry:
    used: int
    reset_time: float


_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
_DEFAULT_BOT_ALLOW = frozenset({"SEARCH_ENGINE", "SOCIAL", "MONITORING"})
_DEFAULT_BOT_DENY = frozenset({"AUTOMATED"})


def _coerce(option: Any) -> dict:
    """Treat ``True`` as ``{}`` (use defaults) and dicts as themselves.
    Anything else means the vector is disabled."""
    if option is True:
        return {}
    if isinstance(option, dict):
        return option
    return {}


class Guards:
    """Per-instance state for rate-limit and token-budget buckets.

    Construct once with the vectors you care about, then call
    :meth:`run` per request/event. Thread-safe in-memory store. Call
    :meth:`close` to release the periodic-cleanup background thread.
    """

    def __init__(
        self,
        rate_limit: Optional[Union[dict, bool]] = None,
        token_budget: Optional[Union[dict, bool]] = None,
        prompt_injection: Optional[Union[dict, bool]] = None,
        bot: Optional[Union[dict, bool]] = None,
    ):
        self._rl = _coerce(rate_limit) if rate_limit else None
        self._tb = _coerce(token_budget) if token_budget else None
        self._pi = _coerce(prompt_injection) if prompt_injection else None
        self._bot = _coerce(bot) if bot else None

        deny_at = (self._pi or {}).get("deny_at", "medium")
        self._pi_deny_rank = _SEVERITY_RANK[deny_at]

        self._rl_store: dict[str, _RLEntry] = {}
        self._tb_store: dict[str, _TBEntry] = {}
        self._lock = threading.Lock()

        # Background cleanup only when a time-windowed vector is configured.
        self._stop_cleanup: Optional[threading.Event] = None
        self._cleanup_thread: Optional[threading.Thread] = None
        if self._rl or self._tb:
            window_ms = (
                (self._rl or {}).get("window_ms")
                or (self._tb or {}).get("window_ms")
                or 60_000
            )
            self._stop_cleanup = threading.Event()
            self._cleanup_thread = threading.Thread(
                target=self._sweep_loop,
                args=(window_ms / 1000.0,),
                daemon=True,
            )
            self._cleanup_thread.start()

    def run(
        self,
        key: str,
        text: Optional[str] = None,
        tokens: Optional[int] = None,
        user_agent: Optional[str] = None,
    ) -> GuardsDecision:
        """Evaluate every configured vector against the input.

        Returns a :class:`GuardsDecision`. The first denying vector
        short-circuits the rest, so a prompt-injection deny does not
        charge the per-key token budget.
        """
        if not isinstance(key, str) or not key:
            return GuardsDecision(ok=False, reason="guards: missing required `key`")

        # 1. Rate limit
        if self._rl is not None:
            decision = self._check_rate_limit(key)
            if not decision.ok:
                return decision

        # 2. Bot detection (only when a UA was supplied)
        if self._bot is not None and user_agent:
            decision = self._check_bot(user_agent)
            if not decision.ok:
                return decision

        # 3. Prompt injection (only when text was supplied)
        pi_matches: List[Tuple[str, GuardsSeverity]] = []
        if self._pi is not None and isinstance(text, str) and text:
            r = detect_prompt_injection(text)
            pi_matches = [(m.rule, m.severity) for m in r.matches]
            if (
                r.detected
                and r.severity != "none"
                and _SEVERITY_RANK[r.severity] >= self._pi_deny_rank
            ):
                top = next((m for m in r.matches if m.severity == r.severity), None)
                return GuardsDecision(
                    ok=False,
                    vector="prompt-injection",
                    severity=r.severity,
                    reason=(
                        f"Prompt injection detected ({top.rule}): {top.description}"
                        if top else "Prompt injection detected"
                    ),
                    matches=pi_matches,
                )

        # 4. Token budget
        if self._tb is not None and isinstance(tokens, (int, float)):
            decision = self._check_token_budget(key, tokens)
            if not decision.ok:
                decision.matches = pi_matches
                return decision

        return GuardsDecision(ok=True, matches=pi_matches)

    def inspect_rate_limit(self, key: str) -> Optional[dict]:
        with self._lock:
            e = self._rl_store.get(key)
            return {"count": e.count, "reset_time": e.reset_time} if e else None

    def inspect_token_budget(self, key: str) -> Optional[dict]:
        with self._lock:
            e = self._tb_store.get(key)
            return {"used": e.used, "reset_time": e.reset_time} if e else None

    def reset(self, key: Optional[str] = None) -> None:
        """Clear a single key's state, or every key if ``key`` is None."""
        with self._lock:
            if key is None:
                self._rl_store.clear()
                self._tb_store.clear()
            else:
                self._rl_store.pop(key, None)
                self._tb_store.pop(key, None)

    def close(self) -> None:
        """Stop the background cleanup thread. Idempotent."""
        if self._stop_cleanup is not None and self._cleanup_thread is not None:
            self._stop_cleanup.set()
            self._cleanup_thread.join(timeout=0.1)

    # ── internals ────────────────────────────────────────────────────────

    def _check_rate_limit(self, key: str) -> GuardsDecision:
        cfg = self._rl or {}
        max_n = int(cfg.get("max", 100))
        window_ms = int(cfg.get("window_ms", 60_000))
        now = time.monotonic()
        with self._lock:
            entry = self._rl_store.get(key)
            if entry is None or entry.reset_time < now:
                entry = _RLEntry(count=0, reset_time=now + window_ms / 1000.0)
                self._rl_store[key] = entry
            entry.count += 1
            if entry.count > max_n:
                retry = max(0, int(entry.reset_time - now + 0.999))
                return GuardsDecision(
                    ok=False,
                    vector="rate-limit",
                    severity="medium",
                    reason=f"Rate limit exceeded ({entry.count}/{max_n} per {window_ms}ms)",
                    retry_after_seconds=retry,
                )
        return GuardsDecision(ok=True)

    def _check_token_budget(self, key: str, tokens: float) -> GuardsDecision:
        cfg = self._tb or {}
        cost = max(0, int(tokens)) if isinstance(tokens, (int, float)) and tokens == tokens else 0
        max_t = int(cfg.get("max_tokens", 100_000))
        window_ms = int(cfg.get("window_ms", 60 * 60 * 1000))
        per_req = cfg.get("max_request_tokens")

        if per_req is not None and cost > int(per_req):
            return GuardsDecision(
                ok=False,
                vector="token-budget",
                severity="high",
                reason=f"Per-call token budget exceeded ({cost} > {int(per_req)})",
            )

        now = time.monotonic()
        with self._lock:
            entry = self._tb_store.get(key)
            if entry is None or entry.reset_time < now:
                entry = _TBEntry(used=0, reset_time=now + window_ms / 1000.0)
                self._tb_store[key] = entry
            projected = entry.used + cost
            if projected > max_t:
                retry = max(0, int(entry.reset_time - now + 0.999))
                return GuardsDecision(
                    ok=False,
                    vector="token-budget",
                    severity="medium",
                    reason=f"Window token budget exceeded ({entry.used} + {cost} > {max_t})",
                    retry_after_seconds=retry,
                )
            entry.used = projected
        return GuardsDecision(ok=True)

    def _check_bot(self, user_agent: str) -> GuardsDecision:
        # Build a request-shaped object detect_bot can read off without
        # importing a web framework.
        class _Req:
            def __init__(self, ua: str):
                self.headers = {
                    "user-agent": ua,
                    "accept": "text/html",
                    "accept-language": "en-US",
                    "accept-encoding": "gzip",
                }
        result = detect_bot(_Req(user_agent))
        if not result.is_bot:
            return GuardsDecision(ok=True)

        cfg = self._bot or {}
        allow = set(cfg.get("allow")) if cfg.get("allow") else _DEFAULT_BOT_ALLOW
        deny = set(cfg.get("deny")) if cfg.get("deny") else _DEFAULT_BOT_DENY
        default_action = cfg.get("default_action", "allow")

        if result.category in allow:
            return GuardsDecision(ok=True)
        if result.category in deny:
            return GuardsDecision(
                ok=False,
                vector="bot",
                severity="medium",
                reason=(
                    f"Bot denied: {result.name}" if result.name
                    else f"Bot denied ({result.category})"
                ),
            )
        if default_action == "deny":
            return GuardsDecision(
                ok=False,
                vector="bot",
                severity="low",
                reason="Uncategorized bot under default_action=deny",
            )
        return GuardsDecision(ok=True)

    def _sweep_loop(self, interval_seconds: float) -> None:
        assert self._stop_cleanup is not None
        while not self._stop_cleanup.wait(interval_seconds):
            now = time.monotonic()
            with self._lock:
                for store in (self._rl_store, self._tb_store):
                    expired = [k for k, e in store.items() if e.reset_time < now]
                    for k in expired:
                        del store[k]


__all__ = [
    "Guards",
    "GuardsDecision",
    "GuardsVector",
    "GuardsSeverity",
]
