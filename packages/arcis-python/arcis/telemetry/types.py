"""
Telemetry contract — mirrors spec/API_SPEC.md §9 and the Node SDK
(packages/arcis-node/src/telemetry/types.ts) field-for-field.

Shape accepted by the Arcis dashboard server's POST /v1/events endpoint.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Literal, Optional


TelemetryDecision = Literal["allow", "deny", "challenge"]
TelemetrySeverity = Literal["critical", "high", "medium", "low"]


@dataclass
class TelemetryEvent:
    """A single decision event emitted by the Arcis middleware.

    Required: ip, method, path, decision, status.
    Optional fields are omitted from the wire payload when None — the server
    fills sensible defaults (ts=now(), userAgent="", country=GeoIP, etc.).
    """

    ip: str
    method: str
    path: str
    decision: TelemetryDecision
    status: int
    ts: Optional[str] = None
    vector: Optional[str] = None
    rule: Optional[str] = None
    severity: Optional[TelemetrySeverity] = None
    country: Optional[str] = None
    user_agent: Optional[str] = None
    reason: Optional[str] = None
    matched_pattern: Optional[str] = None
    latency_ms: Optional[float] = None

    def to_wire(self) -> dict[str, Any]:
        """Serialize to the JSON shape the dashboard server accepts.

        Field name mapping: snake_case (Python) -> camelCase (wire).
        Drops keys whose value is None so payloads stay lean and the server's
        defaults take effect.
        """
        wire: dict[str, Any] = {
            "ip": self.ip,
            "method": self.method,
            "path": self.path,
            "decision": self.decision,
            "status": self.status,
        }
        if self.ts is not None:
            wire["ts"] = self.ts
        if self.vector is not None:
            wire["vector"] = self.vector
        if self.rule is not None:
            wire["rule"] = self.rule
        if self.severity is not None:
            wire["severity"] = self.severity
        if self.country is not None:
            wire["country"] = self.country
        if self.user_agent is not None:
            wire["userAgent"] = self.user_agent
        if self.reason is not None:
            wire["reason"] = self.reason
        if self.matched_pattern is not None:
            wire["matchedPattern"] = self.matched_pattern
        if self.latency_ms is not None:
            wire["latencyMs"] = self.latency_ms
        return wire


@dataclass
class TelemetryOptions:
    """User-provided configuration for the telemetry client.

    Matches Node's TelemetryOptions. Field defaults match the spec
    (batch_size=50, flush_interval_ms=5000) and are clamped by the client
    constructor to the spec-allowed ranges.
    """

    endpoint: str
    api_key: Optional[str] = None
    workspace_id: Optional[str] = None
    batch_size: int = 50
    flush_interval_ms: int = 5000
    # Bound the in-memory queue to prevent OOM during sustained dashboard
    # outage. Drop-oldest semantics keep the most recent events. 10k ~= 10 MB.
    max_queue_size: int = 10_000
    on_error: Optional[Callable[[Exception], None]] = None
    # Called once per overflow event with the count of events dropped in
    # the current outage window. Resets on successful flush.
    on_queue_overflow: Optional[Callable[[int], None]] = None


__all__ = [
    "TelemetryDecision",
    "TelemetrySeverity",
    "TelemetryEvent",
    "TelemetryOptions",
]
