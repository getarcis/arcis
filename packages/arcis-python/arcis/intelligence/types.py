"""
Types for the optional cloud intelligence client (IP reputation refresh).

Python parity with packages/arcis-node/src/intelligence/types.ts.

Opt-in: when unconfigured, the SDK does zero network work and stays fully
local. The data is served by an Arcis intelligence endpoint (the dashboard's
/v1/intel/* routes). Reputation is one signal in a multi-signal decision,
never a standalone verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass
class IpReputation:
    """Result of an IP reputation lookup. ``found=False`` for unknown/clean IPs."""

    ip: str
    found: bool
    severity: Optional[int] = None
    categories: Optional[List[str]] = None
    sources: Optional[List[str]] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    matched: Optional[str] = None


@dataclass
class IntelligenceOptions:
    """Configuration for the cloud intelligence client.

    Mirrors the Node ``IntelligenceOptions`` shape.
    """

    # Base URL of the Arcis intelligence service, e.g. "https://arcis.mycorp.com".
    # The client appends "/v1/intel/ip-reputation/:ip". Required to activate.
    endpoint: str
    # Sent as ``Authorization: Bearer <api_key>``.
    api_key: Optional[str] = None
    # Sent as ``x-workspace-id``.
    workspace_id: Optional[str] = None
    # Which cloud decisions to enable. Include "ip-rep" to turn on IP reputation
    # lookups. Empty / omitted = the client is inert (no network calls).
    cloud_decisions: List[str] = field(default_factory=list)
    # Block when the looked-up IP severity is at or above this threshold (1-10).
    # None = never block on reputation alone (annotate only). Reputation is a
    # signal, not a binary gate, so observe-only is the default.
    block_threshold: Optional[int] = None
    # Local LRU cache capacity (entries). Default 1000.
    cache_max: int = 1000
    # Local cache TTL in milliseconds. Default 3600000 (1 hour).
    cache_ttl_ms: int = 3_600_000
    # Per-lookup network timeout in milliseconds. Default 2000.
    timeout_ms: int = 2000
    # Periodic bot-corpus refresh interval in seconds. Default weekly, matching
    # the Node SDK's setInterval refresh. 0 disables periodic refresh (the
    # startup fetch still runs).
    bot_corpus_refresh_secs: int = 7 * 24 * 60 * 60
    # Error hook for network/HTTP failures. None = swallowed silently
    # (fail-open: an unreachable service never affects requests).
    on_error: Optional[Callable[[Exception], None]] = None


__all__ = ["IpReputation", "IntelligenceOptions"]
