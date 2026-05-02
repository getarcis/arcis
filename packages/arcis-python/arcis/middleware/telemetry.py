"""
Telemetry middleware bridge — Python parity with
packages/arcis-node/src/middleware/telemetry.ts.

Provides helpers used by the FastAPI/Starlette adapter (``arcis.fastapi``) and
the WSGI adapter (``arcis.middleware.main.Arcis`` -> Flask) to:

* attach a per-request attribution marker (vector, rule, severity, decision,
  matched_pattern, reason)
* infer the final decision from the response status when no marker is set
* build a ``TelemetryEvent`` with the captured latency
* hand the event to a ``TelemetryClient`` / ``AsyncTelemetryClient``
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from ..telemetry.types import (
    TelemetryDecision,
    TelemetryEvent,
    TelemetryOptions,
    TelemetrySeverity,
)


# Map internal threat-type names (raised by sanitizers) to the public
# ``vector`` taxonomy used in the dashboard. Mirrors Node's THREAT_TO_VECTOR.
_THREAT_TO_VECTOR: dict[str, str] = {
    "xss": "xss",
    "sql_injection": "sql",
    "nosql_injection": "nosql",
    "path_traversal": "path",
    "command_injection": "command",
    "prototype_pollution": "prototype",
    "header_injection": "header",
    "ssti": "ssti",
    "xxe": "xxe",
}


#: Attribute name used to stash the per-request telemetry marker on
#: ``request.state`` (FastAPI) or ``flask.g`` (Flask). Single leading
#: underscore so Python's class-scope name mangling doesn't rewrite
#: ``request.state.__name`` to ``_OuterClass__name`` in callers.
ARCIS_MARKER_ATTR = "_arcis_marker"


@dataclass
class ArcisTelemetryMarker:
    """Per-request attribution written by inner middlewares (sanitizer,
    rate limiter, validators) and read by the emitter on response complete.

    On Starlette/FastAPI: stored at ``request.state._arcis_marker``.
    On Flask:             stored at ``flask.g._arcis_marker``.

    A marker is optional. If absent, the emitter infers ``decision`` from the
    response status code (see ``infer_decision``).
    """

    vector: Optional[str] = None
    rule: Optional[str] = None
    severity: Optional[TelemetrySeverity] = None
    matched_pattern: Optional[str] = None
    reason: Optional[str] = None
    decision: Optional[TelemetryDecision] = None


def threat_to_vector(threat_type: str) -> str:
    """Map a sanitizer threat name to the public vector taxonomy.

    Unknown threat types pass through unchanged so new sanitizers can ship
    without updating this map first.
    """
    return _THREAT_TO_VECTOR.get(threat_type, threat_type)


def infer_decision(status: int) -> TelemetryDecision:
    """Default decision when no marker was set.

    Mirrors Node's inferDecision: 400/403/429 -> ``deny``, everything else
    treated as ``allow``. The middleware is free to set an explicit decision
    via the marker for cases that don't fit (e.g. ``challenge`` on a sanitize-
    in-place rewrite that returned 200).
    """
    if status in (400, 403, 429):
        return "deny"
    return "allow"


def build_event(
    *,
    ip: str,
    method: str,
    path: str,
    status: int,
    user_agent: str,
    latency_ms: float,
    marker: Optional[ArcisTelemetryMarker],
    ts: Optional[str] = None,
) -> TelemetryEvent:
    """Assemble a TelemetryEvent from request metadata + an optional marker.

    Keeps the inference rules in one place so sync (Flask) and async
    (FastAPI) emitters stay in sync.
    """
    decision: TelemetryDecision
    vector: Optional[str]
    rule: Optional[str]
    severity: Optional[TelemetrySeverity]
    matched_pattern: Optional[str]
    reason: Optional[str]

    if marker is not None:
        decision = marker.decision or infer_decision(status)
        vector = marker.vector
        rule = marker.rule
        severity = marker.severity
        matched_pattern = marker.matched_pattern
        reason = marker.reason
    else:
        decision = infer_decision(status)
        vector = None
        rule = None
        severity = None
        matched_pattern = None
        reason = None

    # Rate-limit fallback attribution: a 429 with no marker should still show
    # up as a rate-limit denial in the dashboard.
    if status == 429 and vector is None:
        vector = "rate-limit"
        rule = "rate-limit/exceeded"
        severity = "medium"

    return TelemetryEvent(
        ts=ts,
        ip=ip,
        method=method.upper() if method else "GET",
        path=path or "/",
        decision=decision,
        vector=vector,
        rule=rule,
        severity=severity,
        user_agent=user_agent or "",
        reason=reason,
        status=status,
        matched_pattern=matched_pattern,
        latency_ms=max(0.0, latency_ms),
    )


def extract_starlette_ip(request: Any) -> str:
    """Pull a client IP from a Starlette/FastAPI request.

    Tries (in order): ``X-Forwarded-For`` first hop, ``X-Real-IP``,
    ``request.client.host``. Falls back to ``"0.0.0.0"`` so the spec's
    required ``ip`` field is never empty.
    """
    headers: Mapping[str, str] = getattr(request, "headers", {}) or {}
    fwd = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For")
    if fwd:
        first = fwd.split(",")[0].strip()
        if first:
            return first
    real = headers.get("x-real-ip") or headers.get("X-Real-IP")
    if real:
        return real.strip()
    client = getattr(request, "client", None)
    host = getattr(client, "host", None) if client is not None else None
    return host or "0.0.0.0"


def tag_marker(
    request: Any,
    *,
    vector: str,
    rule: str,
    reason: str,
    severity: TelemetrySeverity = "high",
) -> None:
    """Best-effort write of an ArcisTelemetryMarker to the per-request
    attribute that the dashboard emitter reads.

    Supports both Starlette/FastAPI ``request.state`` and Flask ``g`` —
    the helper figures out which framework the caller is in. Silent on
    any failure; telemetry tagging must NEVER break a response.

    Used by the deny paths of ``BotProtection``, ``CsrfProtection``, and
    ``SignupProtection`` so the dashboard surfaces the right vector
    instead of falling back to ``vector=null``.
    """
    try:
        marker = ArcisTelemetryMarker(
            vector=vector,
            rule=rule,
            severity=severity,
            decision="deny",
            reason=reason,
        )
        # Starlette / FastAPI request — most common case.
        state = getattr(request, "state", None)
        if state is not None:
            try:
                setattr(state, ARCIS_MARKER_ATTR, marker)
                return
            except Exception:
                pass
        # Flask request — write to flask.g (only valid in a request ctx).
        try:
            from flask import g, has_request_context  # type: ignore[import-untyped]
            if has_request_context():
                setattr(g, ARCIS_MARKER_ATTR, marker)
                return
        except Exception:
            pass
    except Exception:
        # Never let telemetry break the response.
        return


def telemetry_options_from_env() -> Optional[TelemetryOptions]:
    """Build TelemetryOptions from ``ARCIS_*`` env vars.

    Returns None when ``ARCIS_ENDPOINT`` is unset — preserving the zero-
    overhead, opt-in contract. Recognized env vars:

    - ``ARCIS_ENDPOINT``           (required to activate)
    - ``ARCIS_WORKSPACE_ID``       (optional)
    - ``ARCIS_KEY``                (optional)
    - ``ARCIS_BATCH_SIZE``         (optional integer; default 50)
    - ``ARCIS_FLUSH_INTERVAL_MS``  (optional integer; default 5000)

    Explicit ``telemetry`` config passed to ``ArcisMiddleware`` always wins
    over env. This helper is only consulted when no explicit config is given.
    """
    endpoint = os.environ.get("ARCIS_ENDPOINT")
    if not endpoint:
        return None
    opts = TelemetryOptions(
        endpoint=endpoint,
        workspace_id=os.environ.get("ARCIS_WORKSPACE_ID"),
        api_key=os.environ.get("ARCIS_KEY"),
    )
    batch = os.environ.get("ARCIS_BATCH_SIZE")
    if batch:
        try:
            opts.batch_size = int(batch)
        except ValueError:
            pass
    flush = os.environ.get("ARCIS_FLUSH_INTERVAL_MS")
    if flush:
        try:
            opts.flush_interval_ms = int(flush)
        except ValueError:
            pass
    return opts


__all__ = [
    "ARCIS_MARKER_ATTR",
    "ArcisTelemetryMarker",
    "tag_marker",
    "threat_to_vector",
    "infer_decision",
    "build_event",
    "extract_starlette_ip",
    "telemetry_options_from_env",
]
