"""Arcis telemetry — Python parity with @arcis/node telemetry.

Public exports mirror the Node SDK's ``@arcis/node/telemetry`` subpath so the
shape of the public API is identical across SDKs.
"""

from .client import (
    AsyncTelemetryClient,
    TelemetryClient,
    TelemetryHttpError,
)
from .types import (
    TelemetryDecision,
    TelemetryEvent,
    TelemetryOptions,
    TelemetrySeverity,
)

__all__ = [
    "AsyncTelemetryClient",
    "TelemetryClient",
    "TelemetryHttpError",
    "TelemetryDecision",
    "TelemetryEvent",
    "TelemetryOptions",
    "TelemetrySeverity",
]
