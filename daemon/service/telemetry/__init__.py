"""Telemetry module - Privacy-aware analytics collection."""

from .buffer import (
    TelemetryLevel,
    EventType,
    TelemetryEvent,
    TelemetryConfig,
    TelemetryBuffer,
    get_telemetry,
)

__all__ = [
    "TelemetryLevel",
    "EventType",
    "TelemetryEvent",
    "TelemetryConfig",
    "TelemetryBuffer",
    "get_telemetry",
]
