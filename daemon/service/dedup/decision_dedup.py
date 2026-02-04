"""
Decision Deduplication System
=============================

Prevents duplicate approval prompts for the same action within a time window.

From guard-plan-v1.md:
- 60-second deduplication window
- CAR hash-based deduplication
- Request ID tracking
- Prevents user fatigue from repeated prompts

Usage:
    from service.dedup.decision_dedup import DecisionDeduplicator, get_decision_deduplicator

    dedup = get_decision_deduplicator()

    # Check if action is duplicate
    result = await dedup.check_duplicate(car_hash="sha256:...")
    if result.is_duplicate:
        return result.cached_decision

    # After making decision, record it
    await dedup.record_decision(car_hash, decision="allow", request_id="req-123")
"""

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class Decision(Enum):
    """Possible decisions for an action."""

    ALLOW = "allow"
    BLOCK = "block"
    PENDING = "pending"
    UNKNOWN = "unknown"


@dataclass
class DedupeEntry:
    """A cached decision entry."""

    car_hash: str
    decision: Decision
    request_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = field(default_factory=datetime.utcnow)
    hit_count: int = 1
    source_client: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    @property
    def age_seconds(self) -> float:
        return (datetime.utcnow() - self.timestamp).total_seconds()

    @property
    def ttl_seconds(self) -> float:
        remaining = (self.expires_at - datetime.utcnow()).total_seconds()
        return max(0, remaining)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "car_hash": self.car_hash,
            "decision": self.decision.value,
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "is_expired": self.is_expired,
            "age_seconds": self.age_seconds,
            "ttl_seconds": self.ttl_seconds,
            "hit_count": self.hit_count,
            "source_client": self.source_client,
            "metadata": self.metadata,
        }


@dataclass
class DedupeResult:
    """Result of a deduplication check."""

    is_duplicate: bool
    car_hash: str
    cached_entry: Optional[DedupeEntry] = None
    reason: str = ""

    @property
    def cached_decision(self) -> Optional[Decision]:
        if self.cached_entry:
            return self.cached_entry.decision
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_duplicate": self.is_duplicate,
            "car_hash": self.car_hash,
            "cached_decision": (
                self.cached_decision.value if self.cached_decision else None
            ),
            "reason": self.reason,
            "cached_entry": self.cached_entry.to_dict() if self.cached_entry else None,
        }


class DecisionDeduplicator:
    """
    Deduplicates decisions to prevent repeated approval prompts.

    Features:
    - 60-second default deduplication window
    - CAR hash-based caching
    - Request ID tracking
    - Automatic cache cleanup
    - Hit counting for analytics
    - Source client tracking
    """

    DEFAULT_WINDOW_SECONDS = 60.0  # Default dedup window
    DEFAULT_MAX_ENTRIES = 10000  # Maximum cache entries
    DEFAULT_CLEANUP_INTERVAL = 30.0  # Cleanup every 30 seconds

    def __init__(
        self,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        cleanup_interval: float = DEFAULT_CLEANUP_INTERVAL,
    ):
        """
        Initialize the deduplicator.

        Args:
            window_seconds: Time window for deduplication (default 60s)
            max_entries: Maximum cache entries before forced cleanup
            cleanup_interval: Interval for background cleanup
        """
        self._window_seconds = window_seconds
        self._max_entries = max_entries
        self._cleanup_interval = cleanup_interval

        # Main cache: car_hash -> DedupeEntry
        self._cache: Dict[str, DedupeEntry] = {}

        # Request ID index: request_id -> car_hash
        self._request_index: Dict[str, str] = {}

        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        self._start_time = time.time()

        # Statistics
        self._total_checks = 0
        self._cache_hits = 0
        self._cache_misses = 0
        self._evictions = 0

        logger.info(
            f"DecisionDeduplicator initialized: window={window_seconds}s, "
            f"max_entries={max_entries}"
        )

    async def start(self) -> None:
        """Start the deduplicator (background cleanup task)."""
        if self._running:
            return

        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("DecisionDeduplicator started")

    async def stop(self) -> None:
        """Stop the deduplicator."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("DecisionDeduplicator stopped")

    async def _cleanup_loop(self) -> None:
        """Background task to cleanup expired entries."""
        while self._running:
            try:
                await asyncio.sleep(self._cleanup_interval)
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")

    async def _cleanup_expired(self) -> int:
        """Remove expired entries. Returns count of removed entries."""
        removed = 0
        async with self._lock:
            expired_hashes = [
                car_hash for car_hash, entry in self._cache.items() if entry.is_expired
            ]

            for car_hash in expired_hashes:
                entry = self._cache.pop(car_hash)
                # Also remove from request index
                if entry.request_id in self._request_index:
                    del self._request_index[entry.request_id]
                removed += 1
                self._evictions += 1

            if removed > 0:
                logger.debug(f"Cleaned up {removed} expired dedupe entries")

        return removed

    async def _enforce_max_entries(self) -> None:
        """Remove oldest entries if cache exceeds max size."""
        async with self._lock:
            if len(self._cache) <= self._max_entries:
                return

            # Sort by timestamp (oldest first)
            sorted_entries = sorted(self._cache.items(), key=lambda x: x[1].timestamp)

            # Remove oldest entries until under limit
            to_remove = len(self._cache) - self._max_entries
            for i in range(to_remove):
                car_hash, entry = sorted_entries[i]
                del self._cache[car_hash]
                if entry.request_id in self._request_index:
                    del self._request_index[entry.request_id]
                self._evictions += 1

            logger.debug(f"Evicted {to_remove} entries to stay under max limit")

    def _compute_car_hash(self, car_data: Dict[str, Any]) -> str:
        """Compute CAR hash from CAR data."""
        import json

        # Canonical JSON serialization
        canonical = json.dumps(car_data, sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"

    async def check_duplicate(
        self,
        car_hash: Optional[str] = None,
        car_data: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> DedupeResult:
        """
        Check if an action is a duplicate.

        Args:
            car_hash: Pre-computed CAR hash
            car_data: CAR data to hash (if car_hash not provided)
            request_id: Optional request ID to check

        Returns:
            DedupeResult with duplicate status and cached decision
        """
        # Compute hash if not provided
        if car_hash is None:
            if car_data is None:
                raise ValueError("Either car_hash or car_data must be provided")
            car_hash = self._compute_car_hash(car_data)

        self._total_checks += 1

        async with self._lock:
            # First check by CAR hash
            if car_hash in self._cache:
                entry = self._cache[car_hash]
                if not entry.is_expired:
                    entry.hit_count += 1
                    self._cache_hits += 1
                    logger.debug(
                        f"Dedupe hit for {car_hash[:20]}... (hits: {entry.hit_count})"
                    )
                    return DedupeResult(
                        is_duplicate=True,
                        car_hash=car_hash,
                        cached_entry=entry,
                        reason="CAR hash match",
                    )

            # Also check by request ID if provided
            if request_id and request_id in self._request_index:
                cached_hash = self._request_index[request_id]
                if cached_hash in self._cache:
                    entry = self._cache[cached_hash]
                    if not entry.is_expired:
                        entry.hit_count += 1
                        self._cache_hits += 1
                        return DedupeResult(
                            is_duplicate=True,
                            car_hash=car_hash,
                            cached_entry=entry,
                            reason="Request ID match",
                        )

        self._cache_misses += 1
        return DedupeResult(
            is_duplicate=False,
            car_hash=car_hash,
            reason="No duplicate found",
        )

    async def record_decision(
        self,
        car_hash: str,
        decision: str,
        request_id: str = "",
        source_client: str = "",
        window_seconds: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DedupeEntry:
        """
        Record a decision for future deduplication.

        Args:
            car_hash: CAR hash of the action
            decision: Decision made (allow, block, pending)
            request_id: Request ID for additional indexing
            source_client: Client that made the request
            window_seconds: Custom window (or use default)
            metadata: Additional metadata

        Returns:
            The recorded entry
        """
        window = window_seconds or self._window_seconds
        now = datetime.utcnow()

        try:
            decision_enum = Decision(decision.lower())
        except ValueError:
            decision_enum = Decision.UNKNOWN

        entry = DedupeEntry(
            car_hash=car_hash,
            decision=decision_enum,
            request_id=request_id,
            timestamp=now,
            expires_at=now + timedelta(seconds=window),
            source_client=source_client,
            metadata=metadata or {},
        )

        async with self._lock:
            self._cache[car_hash] = entry
            if request_id:
                self._request_index[request_id] = car_hash

        # Enforce max entries
        await self._enforce_max_entries()

        logger.debug(
            f"Recorded decision for {car_hash[:20]}...: {decision} "
            f"(expires in {window}s)"
        )
        return entry

    async def invalidate(
        self,
        car_hash: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> bool:
        """
        Invalidate a cached decision.

        Args:
            car_hash: CAR hash to invalidate
            request_id: Request ID to invalidate

        Returns:
            True if entry was found and removed
        """
        async with self._lock:
            # Find by car_hash
            if car_hash and car_hash in self._cache:
                entry = self._cache.pop(car_hash)
                if entry.request_id in self._request_index:
                    del self._request_index[entry.request_id]
                logger.debug(f"Invalidated cache entry for {car_hash[:20]}...")
                return True

            # Find by request_id
            if request_id and request_id in self._request_index:
                car_hash = self._request_index.pop(request_id)
                if car_hash in self._cache:
                    del self._cache[car_hash]
                logger.debug(f"Invalidated cache entry for request {request_id}")
                return True

        return False

    async def clear(self) -> int:
        """Clear all cached decisions. Returns count of cleared entries."""
        async with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._request_index.clear()
            logger.info(f"Cleared {count} dedupe cache entries")
            return count

    async def get_entry(self, car_hash: str) -> Optional[DedupeEntry]:
        """Get a cached entry by CAR hash."""
        async with self._lock:
            return self._cache.get(car_hash)

    async def get_entry_by_request(self, request_id: str) -> Optional[DedupeEntry]:
        """Get a cached entry by request ID."""
        async with self._lock:
            if request_id not in self._request_index:
                return None
            car_hash = self._request_index[request_id]
            return self._cache.get(car_hash)

    async def get_recent_entries(self, limit: int = 10) -> List[DedupeEntry]:
        """Get most recent cache entries."""
        async with self._lock:
            sorted_entries = sorted(
                self._cache.values(), key=lambda x: x.timestamp, reverse=True
            )
            return sorted_entries[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        hit_rate = (
            self._cache_hits / self._total_checks if self._total_checks > 0 else 0.0
        )

        return {
            "total_checks": self._total_checks,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "hit_rate": round(hit_rate, 4),
            "evictions": self._evictions,
            "cache_size": len(self._cache),
            "max_entries": self._max_entries,
            "window_seconds": self._window_seconds,
            "uptime_seconds": time.time() - self._start_time,
        }


# Global singleton instance
_decision_deduplicator: Optional[DecisionDeduplicator] = None


def get_decision_deduplicator() -> DecisionDeduplicator:
    """Get or create the global decision deduplicator."""
    global _decision_deduplicator
    if _decision_deduplicator is None:
        _decision_deduplicator = DecisionDeduplicator()
    return _decision_deduplicator


async def reset_decision_deduplicator() -> DecisionDeduplicator:
    """Reset the global decision deduplicator."""
    global _decision_deduplicator
    if _decision_deduplicator:
        await _decision_deduplicator.stop()
    _decision_deduplicator = DecisionDeduplicator()
    return _decision_deduplicator


# FastAPI integration
def create_dedup_routes():
    """Create FastAPI routes for deduplication."""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel

    router = APIRouter(prefix="/api/v1/guard", tags=["deduplication"])

    class CheckDuplicateRequest(BaseModel):
        car_hash: Optional[str] = None
        car_data: Optional[Dict[str, Any]] = None
        request_id: Optional[str] = None

    class RecordDecisionRequest(BaseModel):
        car_hash: str
        decision: str
        request_id: str = ""
        source_client: str = ""
        window_seconds: Optional[float] = None

    @router.post("/dedup/check")
    async def check_duplicate(request: CheckDuplicateRequest):
        """Check if an action is a duplicate."""
        dedup = get_decision_deduplicator()

        if not request.car_hash and not request.car_data:
            raise HTTPException(
                status_code=400, detail="Either car_hash or car_data must be provided"
            )

        result = await dedup.check_duplicate(
            car_hash=request.car_hash,
            car_data=request.car_data,
            request_id=request.request_id,
        )
        return result.to_dict()

    @router.post("/dedup/record")
    async def record_decision(request: RecordDecisionRequest):
        """Record a decision for deduplication."""
        dedup = get_decision_deduplicator()
        entry = await dedup.record_decision(
            car_hash=request.car_hash,
            decision=request.decision,
            request_id=request.request_id,
            source_client=request.source_client,
            window_seconds=request.window_seconds,
        )
        return {
            "status": "recorded",
            "entry": entry.to_dict(),
        }

    @router.delete("/dedup/invalidate")
    async def invalidate_entry(
        car_hash: Optional[str] = None, request_id: Optional[str] = None
    ):
        """Invalidate a cached decision."""
        dedup = get_decision_deduplicator()
        success = await dedup.invalidate(car_hash=car_hash, request_id=request_id)

        if not success:
            raise HTTPException(status_code=404, detail="Entry not found")

        return {"status": "invalidated"}

    @router.delete("/dedup/clear")
    async def clear_cache():
        """Clear all cached decisions."""
        dedup = get_decision_deduplicator()
        count = await dedup.clear()
        return {"status": "cleared", "count": count}

    @router.get("/dedup/recent")
    async def get_recent_entries(limit: int = 10):
        """Get recent cache entries."""
        dedup = get_decision_deduplicator()
        entries = await dedup.get_recent_entries(limit)
        return {
            "entries": [e.to_dict() for e in entries],
            "count": len(entries),
        }

    @router.get("/dedup/stats")
    async def get_dedup_stats():
        """Get deduplication statistics."""
        dedup = get_decision_deduplicator()
        return dedup.get_statistics()

    return router
