"""
Guard Watchdog - Self-Integrity Monitoring

From guard-plan-v1.md Meta-Layer 7: Guard Self-Integrity Monitoring

Implements:
- Guard health monitoring
- Binary integrity verification
- Service availability checks
- Automatic recovery/alerting
"""

import asyncio
import hashlib
import logging
import os
import signal
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Callable
import json

logger = logging.getLogger(__name__)


@dataclass
class HealthCheck:
    """Result of a single health check."""

    name: str
    status: str  # "ok", "warning", "error", "critical"
    message: str
    last_checked: datetime
    details: Dict = None

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "last_checked": self.last_checked.isoformat(),
            "details": self.details or {},
        }


@dataclass
class HealthStatus:
    """Aggregated health status."""

    overall_status: str  # "healthy", "degraded", "unhealthy"
    checks: List[HealthCheck]
    timestamp: datetime
    uptime_seconds: float

    def has_issues(self) -> bool:
        return any(c.status in ["error", "critical"] for c in self.checks)

    def to_dict(self) -> Dict:
        return {
            "overall_status": self.overall_status,
            "checks": [c.to_dict() for c in self.checks],
            "timestamp": self.timestamp.isoformat(),
            "uptime_seconds": self.uptime_seconds,
            "has_issues": self.has_issues(),
        }


class GuardWatchdog:
    """
    Monitors Guard daemon health and integrity.

    Runs periodic health checks and alerts on issues.
    """

    def __init__(
        self,
        check_interval_seconds: int = 60,
        alert_callback: Optional[Callable[[HealthStatus], None]] = None,
    ):
        self.check_interval = check_interval_seconds
        self.alert_callback = alert_callback
        self.start_time = datetime.utcnow()

        # Binary hash at startup (for tamper detection)
        self._binary_hash = self._compute_binary_hash()

        # Health check functions
        self._health_checks: List[Callable[[], HealthCheck]] = [
            self._check_process_health,
            self._check_memory_usage,
            self._check_policy_integrity,
            self._check_audit_log,
            self._check_pending_actions,
        ]

        # Running state
        self._running = False
        self._task: Optional[asyncio.Task] = None

        # Alert history
        self._alert_history: List[Dict] = []

        logger.info("GuardWatchdog initialized")

    def _compute_binary_hash(self) -> str:
        """Compute hash of Guard binary/script."""
        try:
            # Hash the main script
            main_path = Path(__file__).parent.parent.parent / "main.py"
            if main_path.exists():
                content = main_path.read_bytes()
                return hashlib.sha256(content).hexdigest()
        except Exception as e:
            logger.warning(f"Could not compute binary hash: {e}")

        return "unknown"

    def _check_process_health(self) -> HealthCheck:
        """Check if Guard process is healthy."""
        try:
            # Check process is alive
            pid = os.getpid()

            return HealthCheck(
                name="process_health",
                status="ok",
                message=f"Process running (PID: {pid})",
                last_checked=datetime.utcnow(),
                details={"pid": pid},
            )
        except Exception as e:
            return HealthCheck(
                name="process_health",
                status="error",
                message=f"Process health check failed: {e}",
                last_checked=datetime.utcnow(),
            )

    def _check_memory_usage(self) -> HealthCheck:
        """Check memory usage of Guard process."""
        try:
            import resource

            # Get memory usage (in bytes)
            usage = resource.getrusage(resource.RUSAGE_SELF)
            memory_mb = usage.ru_maxrss / (1024 * 1024)  # Convert to MB

            # macOS returns bytes, Linux returns KB
            if sys.platform == "darwin":
                memory_mb = usage.ru_maxrss / (1024 * 1024)
            else:
                memory_mb = usage.ru_maxrss / 1024

            # Thresholds
            if memory_mb > 500:
                status = "warning"
                message = f"High memory usage: {memory_mb:.1f} MB"
            elif memory_mb > 1000:
                status = "error"
                message = f"Critical memory usage: {memory_mb:.1f} MB"
            else:
                status = "ok"
                message = f"Memory usage normal: {memory_mb:.1f} MB"

            return HealthCheck(
                name="memory_usage",
                status=status,
                message=message,
                last_checked=datetime.utcnow(),
                details={"memory_mb": round(memory_mb, 1)},
            )
        except Exception as e:
            return HealthCheck(
                name="memory_usage",
                status="warning",
                message=f"Could not check memory: {e}",
                last_checked=datetime.utcnow(),
            )

    def _check_policy_integrity(self) -> HealthCheck:
        """Check policy file integrity."""
        try:
            from .policy_hash import get_policy_verifier

            verifier = get_policy_verifier()
            result = verifier.verify_integrity()

            if result.passed:
                return HealthCheck(
                    name="policy_integrity",
                    status="ok",
                    message="Policy integrity verified",
                    last_checked=datetime.utcnow(),
                    details={"hash": result.actual_hash},
                )
            else:
                return HealthCheck(
                    name="policy_integrity",
                    status="critical",
                    message=result.message,
                    last_checked=datetime.utcnow(),
                    details={
                        "expected": result.expected_hash,
                        "actual": result.actual_hash,
                        "tampered_files": result.tampered_files,
                    },
                )
        except Exception as e:
            return HealthCheck(
                name="policy_integrity",
                status="warning",
                message=f"Could not verify policy: {e}",
                last_checked=datetime.utcnow(),
            )

    def _check_audit_log(self) -> HealthCheck:
        """Check audit log health."""
        try:
            audit_path = Path.home() / ".faramesh-guard" / "audit" / "audit.jsonl"

            if not audit_path.exists():
                return HealthCheck(
                    name="audit_log",
                    status="warning",
                    message="Audit log not found",
                    last_checked=datetime.utcnow(),
                )

            # Check file size
            size_mb = audit_path.stat().st_size / (1024 * 1024)

            # Check for recent writes
            mtime = datetime.fromtimestamp(audit_path.stat().st_mtime)
            age = datetime.utcnow() - mtime

            if size_mb > 100:
                status = "warning"
                message = f"Audit log large: {size_mb:.1f} MB"
            else:
                status = "ok"
                message = f"Audit log healthy: {size_mb:.1f} MB"

            return HealthCheck(
                name="audit_log",
                status=status,
                message=message,
                last_checked=datetime.utcnow(),
                details={
                    "size_mb": round(size_mb, 2),
                    "last_write_age_seconds": age.total_seconds(),
                },
            )
        except Exception as e:
            return HealthCheck(
                name="audit_log",
                status="warning",
                message=f"Could not check audit log: {e}",
                last_checked=datetime.utcnow(),
            )

    def _check_pending_actions(self) -> HealthCheck:
        """Check pending actions health."""
        try:
            db_path = Path.home() / ".faramesh-guard" / "pending_actions.db"

            if not db_path.exists():
                return HealthCheck(
                    name="pending_actions",
                    status="ok",
                    message="No pending actions database",
                    last_checked=datetime.utcnow(),
                )

            # Check database size and integrity
            size_kb = db_path.stat().st_size / 1024

            return HealthCheck(
                name="pending_actions",
                status="ok",
                message=f"Pending actions DB healthy: {size_kb:.1f} KB",
                last_checked=datetime.utcnow(),
                details={"size_kb": round(size_kb, 1)},
            )
        except Exception as e:
            return HealthCheck(
                name="pending_actions",
                status="warning",
                message=f"Could not check pending actions: {e}",
                last_checked=datetime.utcnow(),
            )

    def verify_binary_integrity(self) -> HealthCheck:
        """Verify Guard binary hasn't been tampered with."""
        current_hash = self._compute_binary_hash()

        if current_hash == "unknown":
            return HealthCheck(
                name="binary_integrity",
                status="warning",
                message="Could not verify binary integrity",
                last_checked=datetime.utcnow(),
            )

        if current_hash != self._binary_hash:
            return HealthCheck(
                name="binary_integrity",
                status="critical",
                message="BINARY TAMPERING DETECTED: Guard binary hash mismatch",
                last_checked=datetime.utcnow(),
                details={"expected": self._binary_hash, "actual": current_hash},
            )

        return HealthCheck(
            name="binary_integrity",
            status="ok",
            message="Binary integrity verified",
            last_checked=datetime.utcnow(),
            details={"hash": current_hash},
        )

    def run_all_checks(self) -> HealthStatus:
        """Run all health checks and aggregate results."""
        checks = []

        for check_fn in self._health_checks:
            try:
                result = check_fn()
                checks.append(result)
            except Exception as e:
                checks.append(
                    HealthCheck(
                        name=check_fn.__name__,
                        status="error",
                        message=f"Check failed: {e}",
                        last_checked=datetime.utcnow(),
                    )
                )

        # Add binary integrity check
        checks.append(self.verify_binary_integrity())

        # Determine overall status
        statuses = [c.status for c in checks]

        if "critical" in statuses:
            overall = "unhealthy"
        elif "error" in statuses:
            overall = "degraded"
        elif "warning" in statuses:
            overall = "degraded"
        else:
            overall = "healthy"

        uptime = (datetime.utcnow() - self.start_time).total_seconds()

        return HealthStatus(
            overall_status=overall,
            checks=checks,
            timestamp=datetime.utcnow(),
            uptime_seconds=uptime,
        )

    async def _watchdog_loop(self):
        """Background watchdog loop."""
        while self._running:
            try:
                health = self.run_all_checks()

                if health.has_issues():
                    logger.warning(
                        f"Guard health issue detected: {health.overall_status}"
                    )

                    # Record alert
                    self._alert_history.append(
                        {
                            "timestamp": datetime.utcnow().isoformat(),
                            "status": health.overall_status,
                            "issues": [
                                c.to_dict()
                                for c in health.checks
                                if c.status in ["error", "critical"]
                            ],
                        }
                    )

                    # Trim history
                    if len(self._alert_history) > 100:
                        self._alert_history = self._alert_history[-100:]

                    # Call alert callback if registered
                    if self.alert_callback:
                        try:
                            self.alert_callback(health)
                        except Exception as e:
                            logger.error(f"Alert callback failed: {e}")

                await asyncio.sleep(self.check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Watchdog error: {e}")
                await asyncio.sleep(5)  # Short delay on error

    def start(self):
        """Start the watchdog background task."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._watchdog_loop())
        logger.info("Watchdog started")

    def stop(self):
        """Stop the watchdog."""
        self._running = False
        if self._task:
            self._task.cancel()
        logger.info("Watchdog stopped")

    def get_stats(self) -> Dict:
        """Get watchdog statistics."""
        health = self.run_all_checks()

        return {
            "running": self._running,
            "check_interval_seconds": self.check_interval,
            "uptime_seconds": (datetime.utcnow() - self.start_time).total_seconds(),
            "start_time": self.start_time.isoformat(),
            "current_status": health.to_dict(),
            "recent_alerts": self._alert_history[-10:],
        }


# Global instance
_watchdog: Optional[GuardWatchdog] = None


def get_watchdog() -> GuardWatchdog:
    """Get or create the global watchdog."""
    global _watchdog
    if _watchdog is None:
        _watchdog = GuardWatchdog()
    return _watchdog
