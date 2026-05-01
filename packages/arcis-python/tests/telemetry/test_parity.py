"""
Cross-SDK parity tests — replay spec/TEST_VECTORS.json `telemetry` cases and
assert the Python ``TelemetryEvent.to_wire()`` produces the same shape Node
emits for the same input.

These tests do not start a server. They check that the Python-side shape
matches the spec's ``sdk_emits`` payload field-for-field. This is the same
contract the Node parity tests assert.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from arcis.telemetry.types import TelemetryEvent


def _spec_path() -> Path:
    here = Path(__file__).resolve()
    # file -> tests/telemetry -> tests -> arcis-python -> packages -> arcis
    return here.parents[4] / "spec" / "TEST_VECTORS.json"


def _load_telemetry_vectors() -> dict[str, Any]:
    path = _spec_path()
    if not path.exists():
        pytest.skip(f"spec/TEST_VECTORS.json not found at {path}")
    return json.loads(path.read_text(encoding="utf-8"))["telemetry"]


def _wire_from_spec(spec_event: dict[str, Any]) -> dict[str, Any]:
    """Convert a spec event (camelCase) to a Python TelemetryEvent and back to
    its wire form. The result MUST match the spec event exactly when all
    fields are populated, since spec events use the canonical wire shape.
    """
    event = TelemetryEvent(
        ip=spec_event["ip"],
        method=spec_event["method"],
        path=spec_event["path"],
        decision=spec_event["decision"],
        status=spec_event["status"],
        ts=spec_event.get("ts"),
        vector=spec_event.get("vector"),
        rule=spec_event.get("rule"),
        severity=spec_event.get("severity"),
        country=spec_event.get("country"),
        user_agent=spec_event.get("userAgent"),
        reason=spec_event.get("reason"),
        matched_pattern=spec_event.get("matchedPattern"),
        latency_ms=spec_event.get("latencyMs"),
    )
    return event.to_wire()


class TestSpecParity:
    @pytest.fixture(scope="class")
    def vectors(self) -> dict[str, Any]:
        return _load_telemetry_vectors()

    def test_minimal_deny_event_round_trips(self, vectors: dict[str, Any]) -> None:
        spec = vectors["minimal_deny_event"]["sdk_emits"]
        wire = _wire_from_spec(spec)
        assert wire == spec

    def test_minimal_allow_event_round_trips(self, vectors: dict[str, Any]) -> None:
        spec = vectors["minimal_allow_event"]["sdk_emits"]
        wire = _wire_from_spec(spec)
        assert wire == spec

    def test_challenge_event_round_trips(self, vectors: dict[str, Any]) -> None:
        spec = vectors["challenge_event"]["sdk_emits"]
        wire = _wire_from_spec(spec)
        assert wire == spec

    def test_batch_ingest_each_event_round_trips(self, vectors: dict[str, Any]) -> None:
        events = vectors["batch_ingest"]["sdk_emits"]["events"]
        for spec_event in events:
            wire = _wire_from_spec(spec_event)
            assert wire == spec_event

    def test_optional_fields_dropped_when_none(self) -> None:
        # A minimal event with no optional fields should produce a wire payload
        # containing only the required keys. This matches Node's serializer.
        event = TelemetryEvent(
            ip="1.2.3.4",
            method="GET",
            path="/",
            decision="allow",
            status=200,
        )
        wire = event.to_wire()
        assert set(wire.keys()) == {"ip", "method", "path", "decision", "status"}
