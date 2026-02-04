"""
Telemetry Buffer - Backpressure-aware telemetry collection.

This module provides optional analytics collection with:
- Configurable buffering
- Backpressure handling
- Privacy controls
- Batch uploads
"""

import asyncio
import gzip
import hashlib
import json
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
import aiofiles

logger = logging.getLogger("service.telemetry")


class TelemetryLevel(Enum):
    """Telemetry collection levels."""

    OFF = "off"  # No telemetry
    ERRORS = "errors"  # Only errors and crashes
    BASIC = "basic"  # Basic usage stats (no PII)
    DETAILED = "detailed"  # Detailed analytics (anonymized)
    FULL = "full"  # Full telemetry (development only)


class EventType(Enum):
    """Types of telemetry events."""

    # Guard lifecycle
    GUARD_START = "guard_start"
    GUARD_STOP = "guard_stop"
    GUARD_ERROR = "guard_error"

    # Decision events
    DECISION_ALLOW = "decision_allow"
    DECISION_DENY = "decision_deny"
    DECISION_PENDING = "decision_pending"

    # Approval events
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_EXPIRED = "approval_expired"

    # Policy events
    POLICY_LOAD = "policy_load"
    POLICY_CHANGE = "policy_change"

    # Anomaly events
    ANOMALY_DETECTED = "anomaly_detected"
    ANOMALY_BLOCKED = "anomaly_blocked"

    # Performance events
    LATENCY_SAMPLE = "latency_sample"
    MEMORY_SAMPLE = "memory_sample"


@dataclass
class TelemetryEvent:
    """Represents a telemetry event."""

    event_type: EventType
    timestamp: float = field(default_factory=time.time)
    session_id: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "type": self.event_type.value,
            "ts": self.timestamp,
            "sid": self.session_id,
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "TelemetryEvent":
        return cls(
            event_type=EventType(d["type"]),
            timestamp=d["ts"],
            session_id=d.get("sid", ""),
            data=d.get("data", {}),
        )


@dataclass
class TelemetryConfig:
    """Configuration for telemetry collection."""

    level: TelemetryLevel = TelemetryLevel.BASIC
    buffer_size: int = 1000
    flush_interval_seconds: int = 300  # 5 minutes
    max_batch_size: int = 100
    upload_url: Optional[str] = None
    local_storage_path: str = "/tmp/faramesh-guard-telemetry"
    max_local_storage_mb: int = 50
    compress: bool = True
    anonymize_agent_ids: bool = True
    anonymize_commands: bool = True

    @classmethod
    def from_env(cls) -> "TelemetryConfig":
        """Load config from environment variables."""
        return cls(
            level=TelemetryLevel(os.getenv("GUARD_TELEMETRY_LEVEL", "basic")),
            buffer_size=int(os.getenv("GUARD_TELEMETRY_BUFFER_SIZE", "1000")),
            flush_interval_seconds=int(
                os.getenv("GUARD_TELEMETRY_FLUSH_INTERVAL", "300")
            ),
            upload_url=os.getenv("GUARD_TELEMETRY_URL"),
            local_storage_path=os.getenv(
                "GUARD_TELEMETRY_PATH", "/tmp/faramesh-guard-telemetry"
            ),
            anonymize_agent_ids=os.getenv("GUARD_TELEMETRY_ANONYMIZE", "true").lower()
            == "true",
        )


class TelemetryBuffer:
    """
    Buffered telemetry collection with backpressure handling.

    Features:
    - In-memory ring buffer
    - Automatic flushing
    - Local file persistence
    - Optional remote upload
    - Privacy-aware anonymization
    """

    def __init__(self, config: Optional[TelemetryConfig] = None):
        self.config = config or TelemetryConfig()
        self.buffer: deque = deque(maxlen=self.config.buffer_size)
        self.session_id = self._generate_session_id()
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False
        self._stats = {
            "events_recorded": 0,
            "events_dropped": 0,
            "flushes_completed": 0,
            "flushes_failed": 0,
            "bytes_written": 0,
        }

        # Ensure storage directory exists
        Path(self.config.local_storage_path).mkdir(parents=True, exist_ok=True)

    def _generate_session_id(self) -> str:
        """Generate a unique session ID."""
        return hashlib.sha256(f"{os.getpid()}-{time.time()}".encode()).hexdigest()[:16]

    def start(self) -> None:
        """Start the telemetry background tasks."""
        if self._running:
            return

        self._running = True

        if self.config.level != TelemetryLevel.OFF:
            self._flush_task = asyncio.create_task(self._flush_loop())
            self.record(
                EventType.GUARD_START,
                {
                    "telemetry_level": self.config.level.value,
                },
            )
            logger.info(f"Telemetry started (level: {self.config.level.value})")

    async def stop(self) -> None:
        """Stop telemetry and flush remaining events."""
        if not self._running:
            return

        self._running = False

        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        # Final flush
        self.record(EventType.GUARD_STOP, {})
        await self._flush()

        logger.info("Telemetry stopped")

    def record(
        self,
        event_type: EventType,
        data: Dict[str, Any],
    ) -> bool:
        """
        Record a telemetry event.

        Returns True if recorded, False if dropped (backpressure).
        """
        # Check if telemetry is enabled
        if self.config.level == TelemetryLevel.OFF:
            return False

        # Check event level
        if not self._should_record(event_type):
            return False

        # Anonymize data if configured
        if self.config.anonymize_agent_ids or self.config.anonymize_commands:
            data = self._anonymize(data)

        # Create event
        event = TelemetryEvent(
            event_type=event_type,
            session_id=self.session_id,
            data=data,
        )

        # Add to buffer (ring buffer handles overflow)
        try:
            if len(self.buffer) >= self.config.buffer_size:
                self._stats["events_dropped"] += 1
            self.buffer.append(event)
            self._stats["events_recorded"] += 1
            return True
        except Exception as e:
            logger.warning(f"Failed to record telemetry: {e}")
            return False

    def _should_record(self, event_type: EventType) -> bool:
        """Check if event should be recorded based on level."""
        level = self.config.level

        if level == TelemetryLevel.OFF:
            return False

        if level == TelemetryLevel.ERRORS:
            # Only errors
            return event_type in (
                EventType.GUARD_ERROR,
                EventType.ANOMALY_BLOCKED,
            )

        if level == TelemetryLevel.BASIC:
            # Basic stats, no detailed decisions
            return event_type in (
                EventType.GUARD_START,
                EventType.GUARD_STOP,
                EventType.GUARD_ERROR,
                EventType.POLICY_LOAD,
                EventType.POLICY_CHANGE,
                EventType.LATENCY_SAMPLE,
            )

        # DETAILED and FULL record everything
        return True

    def _anonymize(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize sensitive data."""
        result = data.copy()

        if self.config.anonymize_agent_ids:
            if "agent_id" in result:
                result["agent_id"] = hashlib.sha256(
                    result["agent_id"].encode()
                ).hexdigest()[:12]

        if self.config.anonymize_commands:
            if "command" in result:
                # Keep only the command name, not arguments
                cmd = result["command"]
                if isinstance(cmd, str):
                    result["command"] = cmd.split()[0] if cmd else ""

        return result

    async def _flush_loop(self) -> None:
        """Background flush loop."""
        while self._running:
            try:
                await asyncio.sleep(self.config.flush_interval_seconds)
                await self._flush()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Telemetry flush error: {e}")

    async def _flush(self) -> None:
        """Flush buffer to storage/upload."""
        if not self.buffer:
            return

        # Drain buffer
        events = []
        while self.buffer and len(events) < self.config.max_batch_size:
            events.append(self.buffer.popleft())

        if not events:
            return

        # Serialize
        batch = {
            "version": "1.0",
            "session_id": self.session_id,
            "timestamp": time.time(),
            "events": [e.to_dict() for e in events],
        }

        # Try upload first
        if self.config.upload_url:
            if await self._upload(batch):
                self._stats["flushes_completed"] += 1
                return

        # Fall back to local storage
        if await self._store_locally(batch):
            self._stats["flushes_completed"] += 1
        else:
            self._stats["flushes_failed"] += 1

    async def _upload(self, batch: Dict) -> bool:
        """Upload batch to telemetry server."""
        if not self.config.upload_url:
            return False

        try:
            import aiohttp

            payload = json.dumps(batch).encode()
            if self.config.compress:
                payload = gzip.compress(payload)

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.config.upload_url,
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Content-Encoding": (
                            "gzip" if self.config.compress else "identity"
                        ),
                    },
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        self._stats["bytes_written"] += len(payload)
                        return True
                    else:
                        logger.warning(f"Telemetry upload failed: {resp.status}")
                        return False
        except Exception as e:
            logger.warning(f"Telemetry upload error: {e}")
            return False

    async def _store_locally(self, batch: Dict) -> bool:
        """Store batch to local file."""
        try:
            # Check storage limit
            await self._cleanup_old_files()

            # Generate filename
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"telemetry_{timestamp}_{self.session_id[:8]}.json"
            if self.config.compress:
                filename += ".gz"

            filepath = Path(self.config.local_storage_path) / filename

            # Write file
            payload = json.dumps(batch, indent=2).encode()
            if self.config.compress:
                payload = gzip.compress(payload)

            async with aiofiles.open(filepath, "wb") as f:
                await f.write(payload)

            self._stats["bytes_written"] += len(payload)
            return True

        except Exception as e:
            logger.warning(f"Local telemetry storage error: {e}")
            return False

    async def _cleanup_old_files(self) -> None:
        """Clean up old telemetry files to stay under storage limit."""
        try:
            storage_path = Path(self.config.local_storage_path)
            if not storage_path.exists():
                return

            # Get all telemetry files sorted by modification time
            files = sorted(
                storage_path.glob("telemetry_*.json*"),
                key=lambda f: f.stat().st_mtime,
            )

            # Calculate total size
            total_size = sum(f.stat().st_size for f in files)
            max_bytes = self.config.max_local_storage_mb * 1024 * 1024

            # Remove oldest files until under limit
            while total_size > max_bytes and files:
                oldest = files.pop(0)
                total_size -= oldest.stat().st_size
                oldest.unlink()
                logger.debug(f"Removed old telemetry file: {oldest}")

        except Exception as e:
            logger.warning(f"Telemetry cleanup error: {e}")

    def get_stats(self) -> Dict:
        """Get telemetry statistics."""
        return {
            **self._stats,
            "buffer_size": len(self.buffer),
            "buffer_capacity": self.config.buffer_size,
            "level": self.config.level.value,
            "session_id": self.session_id,
            "running": self._running,
        }

    # Convenience methods for common events

    def record_decision(
        self,
        allowed: bool,
        tool_name: str,
        risk_level: str,
        latency_ms: float,
    ) -> None:
        """Record a decision event."""
        event_type = EventType.DECISION_ALLOW if allowed else EventType.DECISION_DENY
        self.record(
            event_type,
            {
                "tool": tool_name,
                "risk": risk_level,
                "latency_ms": latency_ms,
            },
        )

    def record_anomaly(
        self,
        anomaly_type: str,
        severity: float,
        blocked: bool,
    ) -> None:
        """Record an anomaly event."""
        event_type = (
            EventType.ANOMALY_BLOCKED if blocked else EventType.ANOMALY_DETECTED
        )
        self.record(
            event_type,
            {
                "type": anomaly_type,
                "severity": severity,
            },
        )

    def record_error(
        self,
        error_type: str,
        message: str,
    ) -> None:
        """Record an error event."""
        self.record(
            EventType.GUARD_ERROR,
            {
                "error_type": error_type,
                "message": message[:200],  # Truncate for privacy
            },
        )

    def record_latency(
        self,
        operation: str,
        latency_ms: float,
    ) -> None:
        """Record a latency sample."""
        self.record(
            EventType.LATENCY_SAMPLE,
            {
                "operation": operation,
                "latency_ms": latency_ms,
            },
        )


# Singleton instance
_telemetry: Optional[TelemetryBuffer] = None


def get_telemetry(config: Optional[TelemetryConfig] = None) -> TelemetryBuffer:
    """Get or create singleton telemetry buffer."""
    global _telemetry
    if _telemetry is None:
        _telemetry = TelemetryBuffer(config or TelemetryConfig.from_env())
    return _telemetry
