"""
Memory Watchdog for Faramesh Guard.

Monitors memory usage and takes corrective actions to prevent
OOM kills and ensure stable operation.
"""

import asyncio
import gc
import json
import logging
import os
import sys
import tracemalloc
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
import aiofiles

logger = logging.getLogger(__name__)


class MemoryLevel(str, Enum):
    """Memory usage level."""

    NORMAL = "normal"  # < 50% of limit
    ELEVATED = "elevated"  # 50-70% of limit
    HIGH = "high"  # 70-85% of limit
    CRITICAL = "critical"  # > 85% of limit


class MemoryAction(str, Enum):
    """Actions taken by watchdog."""

    NONE = "none"
    GC_COLLECT = "gc_collect"
    CACHE_CLEAR = "cache_clear"
    RESTART_SCHEDULED = "restart_scheduled"
    EMERGENCY_RESTART = "emergency_restart"


@dataclass
class MemorySnapshot:
    """A memory usage snapshot."""

    timestamp: str

    # Process memory
    rss_bytes: int  # Resident Set Size
    vms_bytes: int  # Virtual Memory Size
    percent: float  # % of system memory

    # Python-specific
    python_allocated: int
    gc_objects: int
    gc_collections: Tuple[int, int, int]

    # Level assessment
    level: str = MemoryLevel.NORMAL.value

    # Tracemalloc info (if enabled)
    top_allocations: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class MemoryThresholds:
    """Memory thresholds configuration."""

    # Percentage thresholds
    elevated_percent: float = 50.0
    high_percent: float = 70.0
    critical_percent: float = 85.0

    # Absolute thresholds (bytes)
    max_rss_bytes: Optional[int] = None

    # GC thresholds
    gc_trigger_objects: int = 100000

    # Action cooldowns (seconds)
    gc_cooldown: int = 60
    cache_clear_cooldown: int = 300
    restart_cooldown: int = 3600


@dataclass
class MemoryEvent:
    """A memory-related event."""

    timestamp: str
    level: str
    action: str

    rss_bytes: int
    percent: float

    details: Dict[str, Any] = field(default_factory=dict)


class MemoryWatchdog:
    """
    Monitors memory usage and takes corrective actions.

    Features:
    - Real-time memory monitoring
    - Multi-level thresholds
    - Automatic garbage collection
    - Cache clearing triggers
    - Graceful restart on critical levels
    - Memory leak detection
    - Allocation tracking (via tracemalloc)
    """

    def __init__(
        self,
        data_dir: str = "/var/lib/faramesh-guard/memory",
        check_interval_seconds: int = 30,
        thresholds: Optional[MemoryThresholds] = None,
        enable_tracemalloc: bool = False,
    ):
        self.data_dir = Path(data_dir)
        self.check_interval = check_interval_seconds
        self.thresholds = thresholds or MemoryThresholds()
        self.enable_tracemalloc = enable_tracemalloc

        self._running = False
        self._snapshots: List[MemorySnapshot] = []
        self._events: List[MemoryEvent] = []
        self._current_level = MemoryLevel.NORMAL

        # Action tracking
        self._last_gc_time = 0.0
        self._last_cache_clear_time = 0.0
        self._last_restart_schedule_time = 0.0

        # Callbacks
        self._on_level_change: List[Callable] = []
        self._cache_clearers: List[Callable] = []
        self._restart_trigger: Optional[Callable] = None

        # Tracemalloc
        if self.enable_tracemalloc and not tracemalloc.is_tracing():
            tracemalloc.start(10)  # Keep 10 frames

        logger.info("MemoryWatchdog initialized")

    async def start(self):
        """Start the watchdog."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._running = True

        # Start monitoring loop
        asyncio.create_task(self._monitor_loop())

        logger.info(f"Memory watchdog started (interval: {self.check_interval}s)")

    async def stop(self):
        """Stop the watchdog."""
        self._running = False
        await self._save_history()

    async def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                snapshot = await self._take_snapshot()
                self._snapshots.append(snapshot)

                # Keep last 1000 snapshots
                if len(self._snapshots) > 1000:
                    self._snapshots = self._snapshots[-500:]

                # Assess level
                new_level = self._assess_level(snapshot)

                if new_level != self._current_level:
                    old_level = self._current_level
                    self._current_level = new_level

                    logger.info(
                        f"Memory level changed: {old_level.value} -> {new_level.value}"
                    )

                    for callback in self._on_level_change:
                        try:
                            if asyncio.iscoroutinefunction(callback):
                                await callback(old_level, new_level, snapshot)
                            else:
                                callback(old_level, new_level, snapshot)
                        except Exception as e:
                            logger.error(f"Level change callback error: {e}")

                # Take action based on level
                await self._take_action(snapshot, new_level)

            except Exception as e:
                logger.error(f"Error in memory monitor: {e}")

            await asyncio.sleep(self.check_interval)

    async def _take_snapshot(self) -> MemorySnapshot:
        """Take a memory usage snapshot."""
        import psutil

        process = psutil.Process()
        mem_info = process.memory_info()

        # Get GC stats
        gc_counts = gc.get_count()
        gc_stats = gc.get_stats()
        total_collections = tuple(s["collections"] for s in gc_stats)

        # Get Python allocator info
        try:
            python_allocated = sys.getsizeof(gc.get_objects())
        except Exception:
            python_allocated = 0

        snapshot = MemorySnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            rss_bytes=mem_info.rss,
            vms_bytes=mem_info.vms,
            percent=process.memory_percent(),
            python_allocated=python_allocated,
            gc_objects=len(gc.get_objects()),
            gc_collections=total_collections,
        )

        # Get tracemalloc info if enabled
        if self.enable_tracemalloc and tracemalloc.is_tracing():
            try:
                top = tracemalloc.take_snapshot().statistics("lineno")[:10]
                snapshot.top_allocations = [
                    {
                        "file": str(stat.traceback),
                        "size_kb": stat.size / 1024,
                        "count": stat.count,
                    }
                    for stat in top
                ]
            except Exception:
                pass

        return snapshot

    def _assess_level(self, snapshot: MemorySnapshot) -> MemoryLevel:
        """Assess memory level from snapshot."""
        percent = snapshot.percent

        # Check absolute limit if configured
        if self.thresholds.max_rss_bytes:
            if snapshot.rss_bytes >= self.thresholds.max_rss_bytes:
                return MemoryLevel.CRITICAL

        # Check percentage thresholds
        if percent >= self.thresholds.critical_percent:
            return MemoryLevel.CRITICAL
        elif percent >= self.thresholds.high_percent:
            return MemoryLevel.HIGH
        elif percent >= self.thresholds.elevated_percent:
            return MemoryLevel.ELEVATED
        else:
            return MemoryLevel.NORMAL

    async def _take_action(self, snapshot: MemorySnapshot, level: MemoryLevel):
        """Take corrective action based on memory level."""
        import time

        now = time.time()
        action = MemoryAction.NONE
        details: Dict[str, Any] = {}

        if level == MemoryLevel.ELEVATED:
            # Trigger GC if cooldown passed
            if now - self._last_gc_time >= self.thresholds.gc_cooldown:
                collected = gc.collect()
                self._last_gc_time = now
                action = MemoryAction.GC_COLLECT
                details["collected"] = collected
                logger.info(
                    f"GC triggered (elevated level): collected {collected} objects"
                )

        elif level == MemoryLevel.HIGH:
            # Force GC
            if now - self._last_gc_time >= self.thresholds.gc_cooldown:
                collected = gc.collect(2)  # Full collection
                self._last_gc_time = now
                action = MemoryAction.GC_COLLECT
                details["collected"] = collected
                details["generation"] = 2

            # Clear caches if cooldown passed
            if (
                now - self._last_cache_clear_time
                >= self.thresholds.cache_clear_cooldown
            ):
                cleared = await self._clear_caches()
                self._last_cache_clear_time = now
                action = MemoryAction.CACHE_CLEAR
                details["caches_cleared"] = cleared
                logger.warning(f"Cache clear triggered (high level): {cleared} caches")

        elif level == MemoryLevel.CRITICAL:
            # Clear caches immediately
            cleared = await self._clear_caches()
            action = MemoryAction.CACHE_CLEAR
            details["caches_cleared"] = cleared

            # Schedule restart if cooldown passed
            if (
                now - self._last_restart_schedule_time
                >= self.thresholds.restart_cooldown
            ):
                if self._restart_trigger:
                    try:
                        await self._restart_trigger()
                        action = MemoryAction.RESTART_SCHEDULED
                        self._last_restart_schedule_time = now
                        logger.critical(
                            "Restart scheduled due to critical memory pressure"
                        )
                    except Exception as e:
                        logger.error(f"Failed to schedule restart: {e}")

        # Record event if action taken
        if action != MemoryAction.NONE:
            event = MemoryEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                level=level.value,
                action=action.value,
                rss_bytes=snapshot.rss_bytes,
                percent=snapshot.percent,
                details=details,
            )
            self._events.append(event)

            # Keep last 1000 events
            if len(self._events) > 1000:
                self._events = self._events[-500:]

    async def _clear_caches(self) -> int:
        """Clear registered caches."""
        cleared = 0

        for clearer in self._cache_clearers:
            try:
                if asyncio.iscoroutinefunction(clearer):
                    await clearer()
                else:
                    clearer()
                cleared += 1
            except Exception as e:
                logger.error(f"Cache clearer error: {e}")

        return cleared

    # Public methods

    def get_current_level(self) -> MemoryLevel:
        """Get current memory level."""
        return self._current_level

    async def get_snapshot(self) -> MemorySnapshot:
        """Get current memory snapshot."""
        return await self._take_snapshot()

    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        recent_snapshots = self._snapshots[-60:] if self._snapshots else []

        if recent_snapshots:
            avg_rss = sum(s.rss_bytes for s in recent_snapshots) / len(recent_snapshots)
            max_rss = max(s.rss_bytes for s in recent_snapshots)
            min_rss = min(s.rss_bytes for s in recent_snapshots)
            avg_percent = sum(s.percent for s in recent_snapshots) / len(
                recent_snapshots
            )
        else:
            avg_rss = max_rss = min_rss = 0
            avg_percent = 0.0

        return {
            "current_level": self._current_level.value,
            "snapshots": len(self._snapshots),
            "events": len(self._events),
            "recent_avg_rss_mb": round(avg_rss / (1024 * 1024), 2),
            "recent_max_rss_mb": round(max_rss / (1024 * 1024), 2),
            "recent_min_rss_mb": round(min_rss / (1024 * 1024), 2),
            "recent_avg_percent": round(avg_percent, 2),
            "thresholds": {
                "elevated": self.thresholds.elevated_percent,
                "high": self.thresholds.high_percent,
                "critical": self.thresholds.critical_percent,
            },
            "tracemalloc_enabled": self.enable_tracemalloc,
        }

    def get_recent_events(self, limit: int = 50) -> List[MemoryEvent]:
        """Get recent memory events."""
        return self._events[-limit:]

    def detect_leak(self, window_minutes: int = 30) -> Dict[str, Any]:
        """
        Attempt to detect memory leaks.

        Looks for consistent upward trend in memory usage.
        """
        window_size = (window_minutes * 60) // self.check_interval
        recent = (
            self._snapshots[-window_size:]
            if len(self._snapshots) >= window_size
            else self._snapshots
        )

        if len(recent) < 10:
            return {"detected": False, "reason": "insufficient data"}

        # Calculate trend
        rss_values = [s.rss_bytes for s in recent]
        n = len(rss_values)

        # Simple linear regression
        x_mean = (n - 1) / 2
        y_mean = sum(rss_values) / n

        numerator = sum((i - x_mean) * (rss_values[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))

        if denominator == 0:
            return {"detected": False, "reason": "no variance"}

        slope = numerator / denominator  # bytes per check interval
        slope_per_hour = slope * (3600 / self.check_interval)

        # Detect if growing more than 10MB/hour
        leak_threshold = 10 * 1024 * 1024  # 10 MB

        is_leak = slope_per_hour > leak_threshold

        return {
            "detected": is_leak,
            "slope_mb_per_hour": round(slope_per_hour / (1024 * 1024), 2),
            "samples": n,
            "window_minutes": window_minutes,
            "first_rss_mb": round(rss_values[0] / (1024 * 1024), 2),
            "last_rss_mb": round(rss_values[-1] / (1024 * 1024), 2),
        }

    def force_gc(self) -> int:
        """Force garbage collection."""
        collected = gc.collect(2)
        logger.info(f"Manual GC: collected {collected} objects")
        return collected

    # Registration methods

    def on_level_change(self, callback: Callable):
        """Register callback for level changes."""
        self._on_level_change.append(callback)

    def register_cache_clearer(self, clearer: Callable):
        """Register cache clearing function."""
        self._cache_clearers.append(clearer)

    def set_restart_trigger(self, trigger: Callable):
        """Set function to trigger restart on critical memory."""
        self._restart_trigger = trigger

    async def _save_history(self):
        """Save event history."""
        history_file = self.data_dir / "memory_events.json"

        try:
            from dataclasses import asdict

            data = {
                "events": [asdict(e) for e in self._events[-100:]],
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }

            async with aiofiles.open(history_file, "w") as f:
                await f.write(json.dumps(data, indent=2))

        except Exception as e:
            logger.error(f"Error saving memory history: {e}")


# Singleton
_watchdog: Optional[MemoryWatchdog] = None


def get_memory_watchdog() -> MemoryWatchdog:
    global _watchdog
    if _watchdog is None:
        _watchdog = MemoryWatchdog()
    return _watchdog


def create_memory_routes():
    """Create FastAPI routes for memory monitoring."""
    from fastapi import APIRouter
    from pydantic import BaseModel
    from typing import Optional

    router = APIRouter(prefix="/api/v1/guard/memory", tags=["memory"])

    @router.get("/snapshot")
    async def get_snapshot():
        """Get current memory snapshot."""
        watchdog = get_memory_watchdog()
        snapshot = await watchdog.get_snapshot()

        return {
            "timestamp": snapshot.timestamp,
            "rss_mb": round(snapshot.rss_bytes / (1024 * 1024), 2),
            "vms_mb": round(snapshot.vms_bytes / (1024 * 1024), 2),
            "percent": round(snapshot.percent, 2),
            "level": snapshot.level,
            "gc_objects": snapshot.gc_objects,
            "top_allocations": snapshot.top_allocations[:5],
        }

    @router.get("/level")
    async def get_level():
        """Get current memory level."""
        watchdog = get_memory_watchdog()
        return {"level": watchdog.get_current_level().value}

    @router.get("/stats")
    async def get_stats():
        """Get memory statistics."""
        watchdog = get_memory_watchdog()
        return watchdog.get_stats()

    @router.get("/events")
    async def get_events(limit: int = 50):
        """Get recent memory events."""
        watchdog = get_memory_watchdog()
        events = watchdog.get_recent_events(limit)

        from dataclasses import asdict

        return {"events": [asdict(e) for e in events]}

    @router.get("/leak-detection")
    async def detect_leak(window_minutes: int = 30):
        """Check for potential memory leak."""
        watchdog = get_memory_watchdog()
        return watchdog.detect_leak(window_minutes)

    @router.post("/gc")
    async def force_gc():
        """Force garbage collection."""
        watchdog = get_memory_watchdog()
        collected = watchdog.force_gc()
        return {"collected": collected}

    return router
