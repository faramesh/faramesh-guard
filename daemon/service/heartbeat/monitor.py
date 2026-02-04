"""
Heartbeat Monitor + Proof of Interception
==========================================

Implements the heartbeat system from guard-plan-v1.md:
- 5-second heartbeat interval
- last_heartbeat_at tracking
- last_intercept_at tracking (proof of active interception)
- Client health monitoring
- Stale client detection

Usage:
    from service.heartbeat.monitor import HeartbeatMonitor, get_heartbeat_monitor

    monitor = get_heartbeat_monitor()

    # Record heartbeat from client
    monitor.record_heartbeat("client-123", metadata={"version": "1.0.0"})

    # Record interception proof
    monitor.record_interception("client-123", car_hash="sha256:...")

    # Check client health
    health = monitor.get_client_health("client-123")
"""

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class ClientHealth(Enum):
    """Client health status."""

    HEALTHY = "healthy"  # Recent heartbeat and interception
    HEARTBEAT_ONLY = "heartbeat_only"  # Heartbeat OK but no recent interception
    STALE = "stale"  # No recent heartbeat
    UNKNOWN = "unknown"  # Never seen this client
    DISCONNECTED = "disconnected"  # Explicitly disconnected


@dataclass
class InterceptionProof:
    """Proof that interception is actively working."""

    car_hash: str  # CAR hash of intercepted action
    action_type: str  # Type of action (execute, write, etc.)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    decision: str = ""  # allow/block/pending
    latency_ms: float = 0  # Decision latency
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "car_hash": self.car_hash,
            "action_type": self.action_type,
            "timestamp": self.timestamp.isoformat(),
            "decision": self.decision,
            "latency_ms": self.latency_ms,
            "metadata": self.metadata,
        }


@dataclass
class HeartbeatRecord:
    """Record of a heartbeat from a client."""

    client_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    sequence: int = 0
    runtime_info: Dict[str, Any] = field(default_factory=dict)
    plugin_version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "client_id": self.client_id,
            "timestamp": self.timestamp.isoformat(),
            "sequence": self.sequence,
            "runtime_info": self.runtime_info,
            "plugin_version": self.plugin_version,
        }


@dataclass
class ClientState:
    """Full state tracking for a client."""

    client_id: str
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_heartbeat: Optional[HeartbeatRecord] = None
    last_interception: Optional[InterceptionProof] = None
    heartbeat_count: int = 0
    interception_count: int = 0
    missed_heartbeats: int = 0
    is_connected: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def last_heartbeat_at(self) -> Optional[datetime]:
        return self.last_heartbeat.timestamp if self.last_heartbeat else None

    @property
    def last_intercept_at(self) -> Optional[datetime]:
        return self.last_interception.timestamp if self.last_interception else None

    def get_health(
        self,
        heartbeat_timeout_seconds: float = 15.0,
        interception_timeout_seconds: float = 60.0,
    ) -> ClientHealth:
        """Determine client health based on timeouts."""
        if not self.is_connected:
            return ClientHealth.DISCONNECTED

        now = datetime.utcnow()

        # Check heartbeat
        if self.last_heartbeat is None:
            return ClientHealth.UNKNOWN

        heartbeat_age = (now - self.last_heartbeat.timestamp).total_seconds()
        if heartbeat_age > heartbeat_timeout_seconds:
            return ClientHealth.STALE

        # Check interception - if never intercepted but heartbeat OK
        if self.last_interception is None:
            return ClientHealth.HEARTBEAT_ONLY

        interception_age = (now - self.last_interception.timestamp).total_seconds()
        if interception_age > interception_timeout_seconds:
            return ClientHealth.HEARTBEAT_ONLY

        return ClientHealth.HEALTHY

    def to_dict(self) -> Dict[str, Any]:
        return {
            "client_id": self.client_id,
            "first_seen": self.first_seen.isoformat(),
            "last_heartbeat_at": (
                self.last_heartbeat_at.isoformat() if self.last_heartbeat_at else None
            ),
            "last_intercept_at": (
                self.last_intercept_at.isoformat() if self.last_intercept_at else None
            ),
            "heartbeat_count": self.heartbeat_count,
            "interception_count": self.interception_count,
            "missed_heartbeats": self.missed_heartbeats,
            "is_connected": self.is_connected,
            "health": self.get_health().value,
            "metadata": self.metadata,
        }


# Type alias for health change callbacks
HealthChangeCallback = Callable[[str, ClientHealth, ClientHealth], None]


class HeartbeatMonitor:
    """
    Monitor heartbeats and proof of interception from clients.

    Features:
    - 5-second heartbeat tracking
    - Proof of interception (last intercepted action)
    - Client health monitoring
    - Stale client detection
    - Health change callbacks
    - Automatic cleanup of stale clients
    """

    # Default configuration
    DEFAULT_HEARTBEAT_INTERVAL = 5.0  # Expected heartbeat interval (seconds)
    DEFAULT_HEARTBEAT_TIMEOUT = 15.0  # Consider stale after 3 missed heartbeats
    DEFAULT_INTERCEPTION_TIMEOUT = 60.0  # Warning if no interception for 60s
    DEFAULT_CLEANUP_INTERVAL = 60.0  # Cleanup stale clients every 60s
    DEFAULT_STALE_CLIENT_AGE = 300.0  # Remove clients after 5 minutes of no heartbeat

    def __init__(
        self,
        heartbeat_interval: float = DEFAULT_HEARTBEAT_INTERVAL,
        heartbeat_timeout: float = DEFAULT_HEARTBEAT_TIMEOUT,
        interception_timeout: float = DEFAULT_INTERCEPTION_TIMEOUT,
        cleanup_interval: float = DEFAULT_CLEANUP_INTERVAL,
        stale_client_age: float = DEFAULT_STALE_CLIENT_AGE,
    ):
        """
        Initialize the heartbeat monitor.

        Args:
            heartbeat_interval: Expected interval between heartbeats
            heartbeat_timeout: Seconds before client considered stale
            interception_timeout: Seconds before warning about no interception
            cleanup_interval: Interval for cleaning up stale clients
            stale_client_age: Age after which to remove stale clients
        """
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_timeout = heartbeat_timeout
        self._interception_timeout = interception_timeout
        self._cleanup_interval = cleanup_interval
        self._stale_client_age = stale_client_age

        self._clients: Dict[str, ClientState] = {}
        self._callbacks: List[HealthChangeCallback] = []
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        self._start_time = time.time()

        # Statistics
        self._total_heartbeats = 0
        self._total_interceptions = 0

        logger.info(
            f"HeartbeatMonitor initialized: interval={heartbeat_interval}s, "
            f"timeout={heartbeat_timeout}s"
        )

    async def start(self) -> None:
        """Start the heartbeat monitor (background cleanup task)."""
        if self._running:
            return

        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("HeartbeatMonitor started")

    async def stop(self) -> None:
        """Stop the heartbeat monitor."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("HeartbeatMonitor stopped")

    async def _cleanup_loop(self) -> None:
        """Background task to cleanup stale clients."""
        while self._running:
            try:
                await asyncio.sleep(self._cleanup_interval)
                await self._cleanup_stale_clients()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")

    async def _cleanup_stale_clients(self) -> None:
        """Remove clients that have been stale for too long."""
        now = datetime.utcnow()
        to_remove: List[str] = []

        async with self._lock:
            for client_id, state in self._clients.items():
                if state.last_heartbeat:
                    age = (now - state.last_heartbeat.timestamp).total_seconds()
                    if age > self._stale_client_age:
                        to_remove.append(client_id)

            for client_id in to_remove:
                del self._clients[client_id]
                logger.info(f"Removed stale client: {client_id}")

    def register_callback(self, callback: HealthChangeCallback) -> None:
        """Register a callback for health changes."""
        self._callbacks.append(callback)

    def unregister_callback(self, callback: HealthChangeCallback) -> None:
        """Unregister a health change callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    async def _fire_health_change(
        self, client_id: str, old_health: ClientHealth, new_health: ClientHealth
    ) -> None:
        """Fire health change callbacks."""
        if old_health == new_health:
            return

        for callback in self._callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(client_id, old_health, new_health)
                else:
                    callback(client_id, old_health, new_health)
            except Exception as e:
                logger.error(f"Health change callback error: {e}")

    async def record_heartbeat(
        self,
        client_id: str,
        sequence: Optional[int] = None,
        runtime_info: Optional[Dict[str, Any]] = None,
        plugin_version: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> HeartbeatRecord:
        """
        Record a heartbeat from a client.

        Args:
            client_id: Unique client identifier
            sequence: Heartbeat sequence number
            runtime_info: Information about the runtime (IDE, version, etc.)
            plugin_version: Version of the Guard plugin
            metadata: Additional metadata

        Returns:
            The recorded heartbeat
        """
        async with self._lock:
            self._total_heartbeats += 1

            # Get or create client state
            if client_id not in self._clients:
                self._clients[client_id] = ClientState(client_id=client_id)
                logger.info(f"New client registered: {client_id}")

            state = self._clients[client_id]
            old_health = state.get_health(
                self._heartbeat_timeout, self._interception_timeout
            )

            # Check for missed heartbeats
            if state.last_heartbeat:
                expected_time = state.last_heartbeat.timestamp + timedelta(
                    seconds=self._heartbeat_interval * 2  # Allow some slack
                )
                if datetime.utcnow() > expected_time:
                    state.missed_heartbeats += 1

            # Create heartbeat record
            heartbeat = HeartbeatRecord(
                client_id=client_id,
                sequence=sequence or (state.heartbeat_count + 1),
                runtime_info=runtime_info or {},
                plugin_version=plugin_version,
            )

            # Update state
            state.last_heartbeat = heartbeat
            state.heartbeat_count += 1
            state.is_connected = True
            if metadata:
                state.metadata.update(metadata)

            new_health = state.get_health(
                self._heartbeat_timeout, self._interception_timeout
            )

        # Fire callback outside lock
        await self._fire_health_change(client_id, old_health, new_health)

        logger.debug(f"Heartbeat from {client_id}: seq={heartbeat.sequence}")
        return heartbeat

    async def record_interception(
        self,
        client_id: str,
        car_hash: str,
        action_type: str = "unknown",
        decision: str = "",
        latency_ms: float = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> InterceptionProof:
        """
        Record proof of interception (an action was intercepted).

        Args:
            client_id: Client that intercepted the action
            car_hash: CAR hash of the intercepted action
            action_type: Type of action (execute, write, etc.)
            decision: The decision made (allow, block, pending)
            latency_ms: Time taken to make decision
            metadata: Additional metadata

        Returns:
            The recorded interception proof
        """
        async with self._lock:
            self._total_interceptions += 1

            # Get or create client state
            if client_id not in self._clients:
                self._clients[client_id] = ClientState(client_id=client_id)
                logger.info(f"New client registered via interception: {client_id}")

            state = self._clients[client_id]
            old_health = state.get_health(
                self._heartbeat_timeout, self._interception_timeout
            )

            # Create interception proof
            proof = InterceptionProof(
                car_hash=car_hash,
                action_type=action_type,
                decision=decision,
                latency_ms=latency_ms,
                metadata=metadata or {},
            )

            # Update state
            state.last_interception = proof
            state.interception_count += 1
            state.is_connected = True

            new_health = state.get_health(
                self._heartbeat_timeout, self._interception_timeout
            )

        # Fire callback outside lock
        await self._fire_health_change(client_id, old_health, new_health)

        logger.debug(f"Interception from {client_id}: {action_type} -> {decision}")
        return proof

    async def disconnect_client(self, client_id: str) -> bool:
        """
        Mark a client as disconnected.

        Args:
            client_id: Client to disconnect

        Returns:
            True if client existed and was disconnected
        """
        async with self._lock:
            if client_id not in self._clients:
                return False

            state = self._clients[client_id]
            old_health = state.get_health(
                self._heartbeat_timeout, self._interception_timeout
            )
            state.is_connected = False
            new_health = ClientHealth.DISCONNECTED

        await self._fire_health_change(client_id, old_health, new_health)
        logger.info(f"Client disconnected: {client_id}")
        return True

    async def get_client_state(self, client_id: str) -> Optional[ClientState]:
        """Get state for a specific client."""
        async with self._lock:
            return self._clients.get(client_id)

    async def get_client_health(self, client_id: str) -> ClientHealth:
        """Get health status for a specific client."""
        async with self._lock:
            if client_id not in self._clients:
                return ClientHealth.UNKNOWN

            state = self._clients[client_id]
            return state.get_health(self._heartbeat_timeout, self._interception_timeout)

    async def get_all_clients(self) -> Dict[str, Dict[str, Any]]:
        """Get state for all clients."""
        async with self._lock:
            return {
                client_id: state.to_dict() for client_id, state in self._clients.items()
            }

    async def get_healthy_clients(self) -> List[str]:
        """Get list of healthy client IDs."""
        async with self._lock:
            return [
                client_id
                for client_id, state in self._clients.items()
                if state.get_health(self._heartbeat_timeout, self._interception_timeout)
                == ClientHealth.HEALTHY
            ]

    async def get_stale_clients(self) -> List[str]:
        """Get list of stale client IDs."""
        async with self._lock:
            return [
                client_id
                for client_id, state in self._clients.items()
                if state.get_health(self._heartbeat_timeout, self._interception_timeout)
                == ClientHealth.STALE
            ]

    def get_statistics(self) -> Dict[str, Any]:
        """Get heartbeat statistics."""
        return {
            "total_heartbeats": self._total_heartbeats,
            "total_interceptions": self._total_interceptions,
            "client_count": len(self._clients),
            "uptime_seconds": time.time() - self._start_time,
            "heartbeat_interval": self._heartbeat_interval,
            "heartbeat_timeout": self._heartbeat_timeout,
            "interception_timeout": self._interception_timeout,
        }


# Global singleton instance
_heartbeat_monitor: Optional[HeartbeatMonitor] = None


def get_heartbeat_monitor() -> HeartbeatMonitor:
    """Get or create the global heartbeat monitor."""
    global _heartbeat_monitor
    if _heartbeat_monitor is None:
        _heartbeat_monitor = HeartbeatMonitor()
    return _heartbeat_monitor


async def reset_heartbeat_monitor() -> HeartbeatMonitor:
    """Reset the global heartbeat monitor."""
    global _heartbeat_monitor
    if _heartbeat_monitor:
        await _heartbeat_monitor.stop()
    _heartbeat_monitor = HeartbeatMonitor()
    return _heartbeat_monitor


# FastAPI integration
def create_heartbeat_routes():
    """Create FastAPI routes for heartbeat monitoring."""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel

    router = APIRouter(prefix="/api/v1/guard", tags=["heartbeat"])

    class HeartbeatRequest(BaseModel):
        client_id: str
        sequence: Optional[int] = None
        runtime_info: Optional[Dict[str, Any]] = None
        plugin_version: str = ""

    class InterceptionRequest(BaseModel):
        client_id: str
        car_hash: str
        action_type: str = "unknown"
        decision: str = ""
        latency_ms: float = 0

    @router.post("/heartbeat")
    async def record_heartbeat(request: HeartbeatRequest):
        """Record a heartbeat from a client."""
        monitor = get_heartbeat_monitor()
        heartbeat = await monitor.record_heartbeat(
            client_id=request.client_id,
            sequence=request.sequence,
            runtime_info=request.runtime_info,
            plugin_version=request.plugin_version,
        )
        return {
            "status": "ok",
            "heartbeat": heartbeat.to_dict(),
        }

    @router.post("/interception")
    async def record_interception(request: InterceptionRequest):
        """Record proof of interception."""
        monitor = get_heartbeat_monitor()
        proof = await monitor.record_interception(
            client_id=request.client_id,
            car_hash=request.car_hash,
            action_type=request.action_type,
            decision=request.decision,
            latency_ms=request.latency_ms,
        )
        return {
            "status": "ok",
            "proof": proof.to_dict(),
        }

    @router.get("/clients")
    async def get_all_clients():
        """Get all registered clients and their status."""
        monitor = get_heartbeat_monitor()
        clients = await monitor.get_all_clients()
        stats = monitor.get_statistics()
        return {
            "clients": clients,
            "statistics": stats,
        }

    @router.get("/clients/{client_id}")
    async def get_client_status(client_id: str):
        """Get status for a specific client."""
        monitor = get_heartbeat_monitor()
        state = await monitor.get_client_state(client_id)

        if state is None:
            raise HTTPException(
                status_code=404, detail=f"Client not found: {client_id}"
            )

        return state.to_dict()

    @router.get("/clients/{client_id}/health")
    async def get_client_health(client_id: str):
        """Get health status for a specific client."""
        monitor = get_heartbeat_monitor()
        health = await monitor.get_client_health(client_id)

        return {
            "client_id": client_id,
            "health": health.value,
            "is_healthy": health == ClientHealth.HEALTHY,
        }

    @router.post("/clients/{client_id}/disconnect")
    async def disconnect_client(client_id: str):
        """Mark a client as disconnected."""
        monitor = get_heartbeat_monitor()
        success = await monitor.disconnect_client(client_id)

        if not success:
            raise HTTPException(
                status_code=404, detail=f"Client not found: {client_id}"
            )

        return {"status": "disconnected", "client_id": client_id}

    @router.get("/heartbeat/stats")
    async def get_heartbeat_stats():
        """Get heartbeat statistics."""
        monitor = get_heartbeat_monitor()
        return monitor.get_statistics()

    return router
