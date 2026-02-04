"""
Memory Watchdog module for Faramesh Guard.

Monitors memory usage and takes corrective actions.
"""

from .watchdog import (
    MemoryWatchdog,
    MemorySnapshot,
    MemoryThresholds,
    MemoryEvent,
    MemoryLevel,
    MemoryAction,
    get_memory_watchdog,
    create_memory_routes,
)

__all__ = [
    "MemoryWatchdog",
    "MemorySnapshot",
    "MemoryThresholds",
    "MemoryEvent",
    "MemoryLevel",
    "MemoryAction",
    "get_memory_watchdog",
    "create_memory_routes",
]
