"""
Soft Restart Scheduler for Faramesh Guard.

Manages graceful restarts with connection draining, state preservation,
and minimal downtime.
"""

import asyncio
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
import aiofiles

logger = logging.getLogger(__name__)


class RestartReason(str, Enum):
    """Reasons for restart."""

    SCHEDULED = "scheduled"
    CONFIG_CHANGE = "config_change"
    UPDATE = "update"
    MEMORY_PRESSURE = "memory_pressure"
    ERROR_RECOVERY = "error_recovery"
    MANUAL = "manual"


class RestartState(str, Enum):
    """State of restart process."""

    IDLE = "idle"
    SCHEDULED = "scheduled"
    DRAINING = "draining"
    SAVING_STATE = "saving_state"
    RESTARTING = "restarting"
    CANCELLED = "cancelled"


@dataclass
class ScheduledRestart:
    """A scheduled restart."""

    restart_id: str
    scheduled_for: str
    reason: str

    # Options
    drain_timeout_seconds: int = 30
    save_state: bool = True

    # Status
    state: str = RestartState.SCHEDULED.value
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Execution
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DrainStatus:
    """Status of connection draining."""

    active_connections: int = 0
    pending_requests: int = 0
    is_accepting: bool = True
    drain_started: Optional[str] = None


class SoftRestartScheduler:
    """
    Manages graceful daemon restarts.

    Features:
    - Scheduled restarts at low-activity times
    - Connection draining before restart
    - State preservation and restoration
    - Update-aware restarts
    - Restart history
    """

    def __init__(
        self,
        data_dir: str = "/var/lib/faramesh-guard/restart",
        default_drain_timeout: int = 30,
    ):
        self.data_dir = Path(data_dir)
        self.default_drain_timeout = default_drain_timeout

        self._scheduled: Optional[ScheduledRestart] = None
        self._state = RestartState.IDLE
        self._drain_status = DrainStatus()
        self._history: List[ScheduledRestart] = []
        self._lock = asyncio.Lock()

        # Callbacks
        self._pre_restart_hooks: List[Callable] = []
        self._state_savers: List[Callable] = []

        # Connection tracking
        self._active_connections: Set[str] = set()
        self._pending_requests: Dict[str, float] = {}

        logger.info("SoftRestartScheduler initialized")

    async def start(self):
        """Start the scheduler."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        await self._load_history()

        # Start scheduler loop
        asyncio.create_task(self._scheduler_loop())

    async def stop(self):
        """Stop gracefully."""
        await self._save_history()

    async def schedule_restart(
        self,
        at: datetime,
        reason: RestartReason = RestartReason.SCHEDULED,
        drain_timeout: Optional[int] = None,
        save_state: bool = True,
    ) -> ScheduledRestart:
        """
        Schedule a restart.

        Args:
            at: When to restart
            reason: Why we're restarting
            drain_timeout: How long to drain connections
            save_state: Whether to save state before restart
        """
        import hashlib

        restart_id = hashlib.sha256(
            f"{at.isoformat()}:{reason.value}".encode()
        ).hexdigest()[:12]

        restart = ScheduledRestart(
            restart_id=restart_id,
            scheduled_for=at.isoformat(),
            reason=reason.value,
            drain_timeout_seconds=drain_timeout or self.default_drain_timeout,
            save_state=save_state,
        )

        async with self._lock:
            # Cancel existing if any
            if self._scheduled:
                self._scheduled.state = RestartState.CANCELLED.value
                self._history.append(self._scheduled)

            self._scheduled = restart
            self._state = RestartState.SCHEDULED

        logger.info(f"Restart scheduled for {at.isoformat()} (reason: {reason.value})")

        return restart

    async def schedule_restart_in(
        self,
        minutes: int,
        reason: RestartReason = RestartReason.SCHEDULED,
        **kwargs,
    ) -> ScheduledRestart:
        """Schedule restart in N minutes."""
        at = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        return await self.schedule_restart(at, reason, **kwargs)

    async def schedule_at_low_activity(
        self,
        reason: RestartReason = RestartReason.SCHEDULED,
        max_wait_hours: int = 24,
        **kwargs,
    ) -> ScheduledRestart:
        """
        Schedule restart at next low-activity period.

        Low activity is determined by request patterns and time of day.
        """
        now = datetime.now(timezone.utc)

        # Simple heuristic: schedule for 3 AM local time
        # In production, you'd analyze actual activity patterns
        target_hour = 3

        target = now.replace(hour=target_hour, minute=0, second=0, microsecond=0)

        if target <= now:
            target += timedelta(days=1)

        # Don't wait more than max_wait_hours
        max_time = now + timedelta(hours=max_wait_hours)
        if target > max_time:
            target = max_time

        return await self.schedule_restart(target, reason, **kwargs)

    async def cancel_scheduled(self) -> bool:
        """Cancel scheduled restart."""
        async with self._lock:
            if self._scheduled and self._state == RestartState.SCHEDULED:
                self._scheduled.state = RestartState.CANCELLED.value
                self._history.append(self._scheduled)
                self._scheduled = None
                self._state = RestartState.IDLE
                logger.info("Scheduled restart cancelled")
                return True
        return False

    async def restart_now(
        self,
        reason: RestartReason = RestartReason.MANUAL,
        drain_timeout: Optional[int] = None,
        save_state: bool = True,
    ) -> bool:
        """
        Initiate immediate restart.

        Returns True if restart initiated.
        """
        restart = await self.schedule_restart(
            at=datetime.now(timezone.utc),
            reason=reason,
            drain_timeout=drain_timeout,
            save_state=save_state,
        )

        # Execute immediately
        await self._execute_restart(restart)
        return True

    async def _scheduler_loop(self):
        """Check for scheduled restarts."""
        while True:
            await asyncio.sleep(10)  # Check every 10 seconds

            try:
                async with self._lock:
                    if not self._scheduled or self._state != RestartState.SCHEDULED:
                        continue

                    scheduled_time = datetime.fromisoformat(
                        self._scheduled.scheduled_for.replace("Z", "+00:00")
                    )

                    if datetime.now(timezone.utc) >= scheduled_time:
                        restart = self._scheduled
                        self._scheduled = None

                # Execute outside lock
                await self._execute_restart(restart)

            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")

    async def _execute_restart(self, restart: ScheduledRestart):
        """Execute the restart process."""
        logger.info(f"Starting restart: {restart.restart_id}")
        restart.started_at = datetime.now(timezone.utc).isoformat()

        try:
            # Phase 1: Stop accepting new connections
            async with self._lock:
                self._state = RestartState.DRAINING
                self._drain_status.is_accepting = False
                self._drain_status.drain_started = datetime.now(
                    timezone.utc
                ).isoformat()

            # Phase 2: Drain existing connections
            await self._drain_connections(restart.drain_timeout_seconds)

            # Phase 3: Run pre-restart hooks
            for hook in self._pre_restart_hooks:
                try:
                    if asyncio.iscoroutinefunction(hook):
                        await hook()
                    else:
                        hook()
                except Exception as e:
                    logger.error(f"Pre-restart hook error: {e}")

            # Phase 4: Save state
            if restart.save_state:
                async with self._lock:
                    self._state = RestartState.SAVING_STATE

                await self._save_all_state()

            # Phase 5: Restart
            async with self._lock:
                self._state = RestartState.RESTARTING

            restart.completed_at = datetime.now(timezone.utc).isoformat()
            self._history.append(restart)
            await self._save_history()

            # Perform actual restart
            await self._perform_restart()

        except Exception as e:
            logger.error(f"Restart failed: {e}")
            restart.error = str(e)
            restart.state = "failed"
            self._history.append(restart)

            # Restore accepting connections
            async with self._lock:
                self._state = RestartState.IDLE
                self._drain_status.is_accepting = True

    async def _drain_connections(self, timeout_seconds: int):
        """Wait for connections to drain."""
        logger.info(f"Draining connections (timeout: {timeout_seconds}s)")

        start = time.time()
        check_interval = 0.5

        while time.time() - start < timeout_seconds:
            async with self._lock:
                self._drain_status.active_connections = len(self._active_connections)
                self._drain_status.pending_requests = len(self._pending_requests)

                if not self._active_connections and not self._pending_requests:
                    logger.info("All connections drained")
                    return

            await asyncio.sleep(check_interval)

        remaining = len(self._active_connections) + len(self._pending_requests)
        logger.warning(f"Drain timeout with {remaining} remaining connections/requests")

    async def _save_all_state(self):
        """Save state from all registered savers."""
        logger.info("Saving state before restart")

        for saver in self._state_savers:
            try:
                if asyncio.iscoroutinefunction(saver):
                    await saver()
                else:
                    saver()
            except Exception as e:
                logger.error(f"State saver error: {e}")

    async def _perform_restart(self):
        """Perform the actual restart."""
        logger.info("Performing restart...")

        # Save restart marker
        marker_file = self.data_dir / "restart_marker"
        async with aiofiles.open(marker_file, "w") as f:
            await f.write(
                json.dumps(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "pid": os.getpid(),
                    }
                )
            )

        # Option 1: Exec new process (preserves PID)
        if sys.platform != "win32":
            try:
                os.execv(sys.executable, [sys.executable] + sys.argv)
            except Exception as e:
                logger.error(f"Exec failed: {e}")

        # Option 2: Signal parent to restart us (for systemd/launchd)
        os.kill(os.getpid(), signal.SIGTERM)

    # Connection tracking methods (to be called by server)

    def register_connection(self, conn_id: str):
        """Register an active connection."""
        self._active_connections.add(conn_id)
        self._drain_status.active_connections = len(self._active_connections)

    def unregister_connection(self, conn_id: str):
        """Unregister a connection."""
        self._active_connections.discard(conn_id)
        self._drain_status.active_connections = len(self._active_connections)

    def register_request(self, request_id: str):
        """Register a pending request."""
        self._pending_requests[request_id] = time.time()
        self._drain_status.pending_requests = len(self._pending_requests)

    def unregister_request(self, request_id: str):
        """Unregister a completed request."""
        self._pending_requests.pop(request_id, None)
        self._drain_status.pending_requests = len(self._pending_requests)

    def is_accepting(self) -> bool:
        """Check if accepting new connections."""
        return self._drain_status.is_accepting

    # Hooks

    def add_pre_restart_hook(self, hook: Callable):
        """Add hook to run before restart."""
        self._pre_restart_hooks.append(hook)

    def add_state_saver(self, saver: Callable):
        """Add state saver to run before restart."""
        self._state_savers.append(saver)

    # Status

    def get_status(self) -> Dict[str, Any]:
        """Get scheduler status."""
        return {
            "state": self._state.value,
            "scheduled": (
                {
                    "restart_id": self._scheduled.restart_id,
                    "scheduled_for": self._scheduled.scheduled_for,
                    "reason": self._scheduled.reason,
                }
                if self._scheduled
                else None
            ),
            "drain_status": {
                "accepting": self._drain_status.is_accepting,
                "active_connections": self._drain_status.active_connections,
                "pending_requests": self._drain_status.pending_requests,
                "drain_started": self._drain_status.drain_started,
            },
            "recent_restarts": len(self._history),
        }

    async def _load_history(self):
        """Load restart history."""
        history_file = self.data_dir / "restart_history.json"

        if history_file.exists():
            try:
                async with aiofiles.open(history_file, "r") as f:
                    content = await f.read()

                data = json.loads(content)

                for entry in data.get("history", []):
                    self._history.append(ScheduledRestart(**entry))

                # Keep only last 100
                self._history = self._history[-100:]

            except Exception as e:
                logger.error(f"Error loading restart history: {e}")

    async def _save_history(self):
        """Save restart history."""
        history_file = self.data_dir / "restart_history.json"

        try:
            from dataclasses import asdict

            data = {
                "history": [asdict(r) for r in self._history[-100:]],
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }

            async with aiofiles.open(history_file, "w") as f:
                await f.write(json.dumps(data, indent=2))

        except Exception as e:
            logger.error(f"Error saving restart history: {e}")


# Singleton
_scheduler: Optional[SoftRestartScheduler] = None


def get_restart_scheduler() -> SoftRestartScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = SoftRestartScheduler()
    return _scheduler


def create_restart_routes():
    """Create FastAPI routes for restart scheduling."""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
    from typing import Optional

    router = APIRouter(prefix="/api/v1/guard/restart", tags=["restart"])

    class ScheduleRequest(BaseModel):
        minutes_from_now: Optional[int] = None
        at_low_activity: bool = False
        reason: str = "scheduled"
        drain_timeout_seconds: Optional[int] = None
        save_state: bool = True

    @router.post("/schedule")
    async def schedule_restart(request: ScheduleRequest):
        """Schedule a restart."""
        scheduler = get_restart_scheduler()

        try:
            reason = RestartReason(request.reason)
        except ValueError:
            reason = RestartReason.SCHEDULED

        if request.at_low_activity:
            restart = await scheduler.schedule_at_low_activity(
                reason=reason,
                drain_timeout=request.drain_timeout_seconds,
                save_state=request.save_state,
            )
        elif request.minutes_from_now:
            restart = await scheduler.schedule_restart_in(
                minutes=request.minutes_from_now,
                reason=reason,
                drain_timeout=request.drain_timeout_seconds,
                save_state=request.save_state,
            )
        else:
            raise HTTPException(400, "Specify minutes_from_now or at_low_activity")

        return {
            "restart_id": restart.restart_id,
            "scheduled_for": restart.scheduled_for,
            "reason": restart.reason,
        }

    @router.post("/now")
    async def restart_now(
        reason: str = "manual",
        drain_timeout: int = 30,
        save_state: bool = True,
    ):
        """Restart immediately."""
        scheduler = get_restart_scheduler()

        try:
            reason_enum = RestartReason(reason)
        except ValueError:
            reason_enum = RestartReason.MANUAL

        await scheduler.restart_now(
            reason=reason_enum,
            drain_timeout=drain_timeout,
            save_state=save_state,
        )

        return {"restarting": True}

    @router.post("/cancel")
    async def cancel_restart():
        """Cancel scheduled restart."""
        scheduler = get_restart_scheduler()
        success = await scheduler.cancel_scheduled()

        if not success:
            raise HTTPException(404, "No scheduled restart to cancel")

        return {"cancelled": True}

    @router.get("/status")
    async def get_status():
        """Get restart scheduler status."""
        scheduler = get_restart_scheduler()
        return scheduler.get_status()

    @router.get("/accepting")
    async def is_accepting():
        """Check if accepting new connections."""
        scheduler = get_restart_scheduler()
        return {"accepting": scheduler.is_accepting()}

    return router
