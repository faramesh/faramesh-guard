"""
Protection State Machine - 9 Canonical States
==============================================

Implements the complete protection state machine from guard-plan-v1.md.

States (ordered by severity - most severe first):
1. RUNTIME_MISSING - No runtime detected
2. RUNTIME_FOUND_PLUGIN_MISSING - Runtime exists but plugin not installed
3. PLUGIN_PRESENT_NOT_LOADED - Plugin installed but not active
4. DAEMON_NOT_RUNNING - Plugin loaded but daemon process not running
5. DAEMON_UNREACHABLE - Daemon running but IPC/network failure
6. AUTH_FAILED - Connection works but authentication failed
7. PERMISSIONS_MISSING - Authenticated but missing required permissions
8. VERSION_INCOMPATIBLE - Version mismatch between plugin and daemon
9. DEGRADED - Partial functionality available
10. PROTECTED - Full protection active

Usage:
    from service.state.protection_state import ProtectionStateMachine, ProtectionState

    machine = ProtectionStateMachine()
    await machine.transition_to(ProtectionState.PROTECTED)
    print(machine.current_state)  # ProtectionState.PROTECTED
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ProtectionState(Enum):
    """9 canonical protection states ordered by severity."""

    RUNTIME_MISSING = auto()  # No runtime (VS Code, IDE) detected
    RUNTIME_FOUND_PLUGIN_MISSING = auto()  # Runtime exists but plugin not installed
    PLUGIN_PRESENT_NOT_LOADED = auto()  # Plugin installed but not active/loaded
    DAEMON_NOT_RUNNING = auto()  # Plugin active but guard daemon not running
    DAEMON_UNREACHABLE = auto()  # Daemon running but can't connect (IPC/network)
    AUTH_FAILED = auto()  # Connected but auth failed (token/key)
    PERMISSIONS_MISSING = auto()  # Authed but missing file/process permissions
    VERSION_INCOMPATIBLE = auto()  # Version mismatch (plugin vs daemon)
    DEGRADED = auto()  # Partial functionality (some features disabled)
    PROTECTED = auto()  # Full protection active

    @property
    def severity(self) -> int:
        """Return severity level (0 = most severe, 9 = least severe/best)."""
        severity_map = {
            ProtectionState.RUNTIME_MISSING: 0,
            ProtectionState.RUNTIME_FOUND_PLUGIN_MISSING: 1,
            ProtectionState.PLUGIN_PRESENT_NOT_LOADED: 2,
            ProtectionState.DAEMON_NOT_RUNNING: 3,
            ProtectionState.DAEMON_UNREACHABLE: 4,
            ProtectionState.AUTH_FAILED: 5,
            ProtectionState.PERMISSIONS_MISSING: 6,
            ProtectionState.VERSION_INCOMPATIBLE: 7,
            ProtectionState.DEGRADED: 8,
            ProtectionState.PROTECTED: 9,
        }
        return severity_map.get(self, 0)

    @property
    def is_blocking(self) -> bool:
        """Return True if this state should block dangerous operations."""
        return self.severity < ProtectionState.PROTECTED.severity

    @property
    def human_readable(self) -> str:
        """Return human-readable description of state."""
        descriptions = {
            ProtectionState.RUNTIME_MISSING: "No supported runtime detected",
            ProtectionState.RUNTIME_FOUND_PLUGIN_MISSING: "Runtime found but Guard plugin not installed",
            ProtectionState.PLUGIN_PRESENT_NOT_LOADED: "Guard plugin installed but not loaded",
            ProtectionState.DAEMON_NOT_RUNNING: "Guard daemon is not running",
            ProtectionState.DAEMON_UNREACHABLE: "Cannot connect to Guard daemon",
            ProtectionState.AUTH_FAILED: "Authentication with Guard daemon failed",
            ProtectionState.PERMISSIONS_MISSING: "Guard daemon missing required permissions",
            ProtectionState.VERSION_INCOMPATIBLE: "Plugin/daemon version mismatch",
            ProtectionState.DEGRADED: "Guard running with reduced functionality",
            ProtectionState.PROTECTED: "Full protection active",
        }
        return descriptions.get(self, "Unknown state")

    @property
    def remediation_hint(self) -> str:
        """Return hint for how to fix this state."""
        hints = {
            ProtectionState.RUNTIME_MISSING: "Launch VS Code or a supported IDE",
            ProtectionState.RUNTIME_FOUND_PLUGIN_MISSING: "Install the Faramesh Guard extension",
            ProtectionState.PLUGIN_PRESENT_NOT_LOADED: "Reload window or enable the extension",
            ProtectionState.DAEMON_NOT_RUNNING: "Run 'faramesh-guard start' or install the service",
            ProtectionState.DAEMON_UNREACHABLE: "Check firewall settings and daemon port (8765)",
            ProtectionState.AUTH_FAILED: "Verify API key or re-authenticate",
            ProtectionState.PERMISSIONS_MISSING: "Grant required filesystem permissions",
            ProtectionState.VERSION_INCOMPATIBLE: "Update plugin and daemon to matching versions",
            ProtectionState.DEGRADED: "Check logs for specific issues",
            ProtectionState.PROTECTED: "No action needed - fully protected",
        }
        return hints.get(self, "Unknown remediation")


@dataclass
class StateTransition:
    """Record of a state transition."""

    from_state: ProtectionState
    to_state: ProtectionState
    timestamp: datetime = field(default_factory=datetime.utcnow)
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_state": self.from_state.name,
            "to_state": self.to_state.name,
            "timestamp": self.timestamp.isoformat(),
            "reason": self.reason,
            "metadata": self.metadata,
        }


@dataclass
class ProtectionStatus:
    """Full protection status snapshot."""

    state: ProtectionState
    since: datetime
    last_check: datetime
    transition_count: int
    uptime_seconds: float
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.name,
            "state_severity": self.state.severity,
            "state_human": self.state.human_readable,
            "state_blocking": self.state.is_blocking,
            "remediation": (
                self.state.remediation_hint if self.state.is_blocking else None
            ),
            "since": self.since.isoformat(),
            "last_check": self.last_check.isoformat(),
            "transition_count": self.transition_count,
            "uptime_seconds": self.uptime_seconds,
            "details": self.details,
        }


# Type alias for state change callbacks
StateChangeCallback = Callable[[ProtectionState, ProtectionState, str], None]


class ProtectionStateMachine:
    """
    State machine managing protection status transitions.

    Features:
    - Valid transition enforcement
    - State change callbacks
    - Transition history
    - Automatic state checks
    - Thread-safe operations
    """

    # Valid state transitions (from_state -> set of valid to_states)
    VALID_TRANSITIONS: Dict[ProtectionState, Set[ProtectionState]] = {
        # From RUNTIME_MISSING - can only go forward as runtime appears
        ProtectionState.RUNTIME_MISSING: {
            ProtectionState.RUNTIME_FOUND_PLUGIN_MISSING,
            ProtectionState.PLUGIN_PRESENT_NOT_LOADED,  # Fast path if both detected
        },
        # From RUNTIME_FOUND_PLUGIN_MISSING - plugin gets installed
        ProtectionState.RUNTIME_FOUND_PLUGIN_MISSING: {
            ProtectionState.RUNTIME_MISSING,  # Runtime disappeared
            ProtectionState.PLUGIN_PRESENT_NOT_LOADED,
        },
        # From PLUGIN_PRESENT_NOT_LOADED - plugin loads
        ProtectionState.PLUGIN_PRESENT_NOT_LOADED: {
            ProtectionState.RUNTIME_MISSING,
            ProtectionState.RUNTIME_FOUND_PLUGIN_MISSING,  # Plugin uninstalled
            ProtectionState.DAEMON_NOT_RUNNING,
        },
        # From DAEMON_NOT_RUNNING - daemon starts
        ProtectionState.DAEMON_NOT_RUNNING: {
            ProtectionState.RUNTIME_MISSING,
            ProtectionState.PLUGIN_PRESENT_NOT_LOADED,
            ProtectionState.DAEMON_UNREACHABLE,  # Started but can't connect yet
            ProtectionState.AUTH_FAILED,
            ProtectionState.PROTECTED,  # Fast path - all good
        },
        # From DAEMON_UNREACHABLE - connection established
        ProtectionState.DAEMON_UNREACHABLE: {
            ProtectionState.DAEMON_NOT_RUNNING,  # Daemon died
            ProtectionState.AUTH_FAILED,
            ProtectionState.PERMISSIONS_MISSING,
            ProtectionState.VERSION_INCOMPATIBLE,
            ProtectionState.PROTECTED,
        },
        # From AUTH_FAILED - auth succeeds
        ProtectionState.AUTH_FAILED: {
            ProtectionState.DAEMON_NOT_RUNNING,
            ProtectionState.DAEMON_UNREACHABLE,
            ProtectionState.PERMISSIONS_MISSING,
            ProtectionState.VERSION_INCOMPATIBLE,
            ProtectionState.PROTECTED,
        },
        # From PERMISSIONS_MISSING - permissions granted
        ProtectionState.PERMISSIONS_MISSING: {
            ProtectionState.DAEMON_NOT_RUNNING,
            ProtectionState.DAEMON_UNREACHABLE,
            ProtectionState.AUTH_FAILED,
            ProtectionState.VERSION_INCOMPATIBLE,
            ProtectionState.DEGRADED,
            ProtectionState.PROTECTED,
        },
        # From VERSION_INCOMPATIBLE - versions updated
        ProtectionState.VERSION_INCOMPATIBLE: {
            ProtectionState.DAEMON_NOT_RUNNING,
            ProtectionState.DAEMON_UNREACHABLE,
            ProtectionState.AUTH_FAILED,
            ProtectionState.PERMISSIONS_MISSING,
            ProtectionState.DEGRADED,
            ProtectionState.PROTECTED,
        },
        # From DEGRADED - issue resolved or worsened
        ProtectionState.DEGRADED: {
            ProtectionState.DAEMON_NOT_RUNNING,
            ProtectionState.DAEMON_UNREACHABLE,
            ProtectionState.AUTH_FAILED,
            ProtectionState.PERMISSIONS_MISSING,
            ProtectionState.VERSION_INCOMPATIBLE,
            ProtectionState.PROTECTED,
        },
        # From PROTECTED - any degradation
        ProtectionState.PROTECTED: {
            ProtectionState.RUNTIME_MISSING,
            ProtectionState.DAEMON_NOT_RUNNING,
            ProtectionState.DAEMON_UNREACHABLE,
            ProtectionState.AUTH_FAILED,
            ProtectionState.PERMISSIONS_MISSING,
            ProtectionState.VERSION_INCOMPATIBLE,
            ProtectionState.DEGRADED,
        },
    }

    def __init__(
        self,
        initial_state: ProtectionState = ProtectionState.DAEMON_NOT_RUNNING,
        max_history: int = 100,
    ):
        """
        Initialize the state machine.

        Args:
            initial_state: Starting state
            max_history: Maximum transitions to keep in history
        """
        self._current_state = initial_state
        self._state_since = datetime.utcnow()
        self._start_time = time.time()
        self._max_history = max_history
        self._transition_history: List[StateTransition] = []
        self._callbacks: List[StateChangeCallback] = []
        self._lock = asyncio.Lock()
        self._details: Dict[str, Any] = {}

        logger.info(
            f"Protection state machine initialized in state: {initial_state.name}"
        )

    @property
    def current_state(self) -> ProtectionState:
        """Return current protection state."""
        return self._current_state

    @property
    def is_protected(self) -> bool:
        """Return True if fully protected."""
        return self._current_state == ProtectionState.PROTECTED

    @property
    def is_degraded(self) -> bool:
        """Return True if in degraded state."""
        return self._current_state == ProtectionState.DEGRADED

    @property
    def is_blocking(self) -> bool:
        """Return True if current state should block dangerous operations."""
        return self._current_state.is_blocking

    @property
    def transition_count(self) -> int:
        """Return total number of transitions."""
        return len(self._transition_history)

    def get_status(self) -> ProtectionStatus:
        """Return full protection status snapshot."""
        now = datetime.utcnow()
        return ProtectionStatus(
            state=self._current_state,
            since=self._state_since,
            last_check=now,
            transition_count=self.transition_count,
            uptime_seconds=time.time() - self._start_time,
            details=self._details.copy(),
        )

    def is_valid_transition(
        self, from_state: ProtectionState, to_state: ProtectionState
    ) -> bool:
        """Check if a transition is valid."""
        if from_state == to_state:
            return True  # Self-transition always valid (refresh)

        valid_targets = self.VALID_TRANSITIONS.get(from_state, set())
        return to_state in valid_targets

    def register_callback(self, callback: StateChangeCallback) -> None:
        """Register a callback for state changes."""
        self._callbacks.append(callback)
        logger.debug(f"Registered state change callback: {callback.__name__}")

    def unregister_callback(self, callback: StateChangeCallback) -> None:
        """Unregister a state change callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
            logger.debug(f"Unregistered state change callback: {callback.__name__}")

    async def transition_to(
        self,
        new_state: ProtectionState,
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> Tuple[bool, str]:
        """
        Attempt to transition to a new state.

        Args:
            new_state: Target state
            reason: Human-readable reason for transition
            metadata: Additional context
            force: If True, skip transition validation

        Returns:
            Tuple of (success, message)
        """
        async with self._lock:
            old_state = self._current_state

            # Self-transition is a no-op
            if old_state == new_state:
                return True, "Already in target state"

            # Validate transition unless forced
            if not force and not self.is_valid_transition(old_state, new_state):
                msg = f"Invalid transition from {old_state.name} to {new_state.name}"
                logger.warning(msg)
                return False, msg

            # Perform transition
            self._current_state = new_state
            self._state_since = datetime.utcnow()

            # Record transition
            transition = StateTransition(
                from_state=old_state,
                to_state=new_state,
                reason=reason,
                metadata=metadata or {},
            )
            self._transition_history.append(transition)

            # Trim history if needed
            if len(self._transition_history) > self._max_history:
                self._transition_history = self._transition_history[
                    -self._max_history :
                ]

            logger.info(
                f"State transition: {old_state.name} -> {new_state.name} "
                f"(reason: {reason or 'none'})"
            )

            # Fire callbacks
            for callback in self._callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(old_state, new_state, reason)
                    else:
                        callback(old_state, new_state, reason)
                except Exception as e:
                    logger.error(f"State change callback error: {e}")

            return True, f"Transitioned from {old_state.name} to {new_state.name}"

    async def set_detail(self, key: str, value: Any) -> None:
        """Set a detail value (thread-safe)."""
        async with self._lock:
            self._details[key] = value

    async def get_detail(self, key: str, default: Any = None) -> Any:
        """Get a detail value (thread-safe)."""
        async with self._lock:
            return self._details.get(key, default)

    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Return recent transition history."""
        recent = self._transition_history[-limit:]
        return [t.to_dict() for t in reversed(recent)]

    def get_state_duration(self) -> float:
        """Return seconds in current state."""
        return (datetime.utcnow() - self._state_since).total_seconds()

    async def auto_detect_state(
        self,
        runtime_detected: bool = True,
        plugin_installed: bool = True,
        plugin_loaded: bool = True,
        daemon_running: bool = True,
        daemon_reachable: bool = True,
        auth_valid: bool = True,
        permissions_ok: bool = True,
        version_compatible: bool = True,
        all_features_ok: bool = True,
    ) -> ProtectionState:
        """
        Auto-detect the correct state based on conditions.

        This method evaluates conditions in order of severity and
        transitions to the appropriate state.
        """
        # Evaluate in order of severity (most severe first)
        if not runtime_detected:
            target = ProtectionState.RUNTIME_MISSING
        elif not plugin_installed:
            target = ProtectionState.RUNTIME_FOUND_PLUGIN_MISSING
        elif not plugin_loaded:
            target = ProtectionState.PLUGIN_PRESENT_NOT_LOADED
        elif not daemon_running:
            target = ProtectionState.DAEMON_NOT_RUNNING
        elif not daemon_reachable:
            target = ProtectionState.DAEMON_UNREACHABLE
        elif not auth_valid:
            target = ProtectionState.AUTH_FAILED
        elif not permissions_ok:
            target = ProtectionState.PERMISSIONS_MISSING
        elif not version_compatible:
            target = ProtectionState.VERSION_INCOMPATIBLE
        elif not all_features_ok:
            target = ProtectionState.DEGRADED
        else:
            target = ProtectionState.PROTECTED

        # Transition if different
        if target != self._current_state:
            await self.transition_to(
                target,
                reason="Auto-detected state change",
                force=True,  # Auto-detect can make any transition
            )

        return target


# Global singleton instance
_protection_state_machine: Optional[ProtectionStateMachine] = None


def get_protection_state_machine() -> ProtectionStateMachine:
    """Get or create the global protection state machine."""
    global _protection_state_machine
    if _protection_state_machine is None:
        _protection_state_machine = ProtectionStateMachine()
    return _protection_state_machine


async def reset_protection_state_machine(
    initial_state: ProtectionState = ProtectionState.DAEMON_NOT_RUNNING,
) -> ProtectionStateMachine:
    """Reset the global protection state machine."""
    global _protection_state_machine
    _protection_state_machine = ProtectionStateMachine(initial_state=initial_state)
    return _protection_state_machine


# FastAPI integration - import these in main.py
def create_protection_state_routes():
    """Create FastAPI routes for protection state."""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel

    router = APIRouter(prefix="/api/v1/guard", tags=["protection-state"])

    class StateTransitionRequest(BaseModel):
        state: str
        reason: str = ""
        force: bool = False

    @router.get("/status")
    async def get_protection_status():
        """Get current protection status."""
        machine = get_protection_state_machine()
        status = machine.get_status()
        return status.to_dict()

    @router.get("/status/history")
    async def get_state_history(limit: int = 10):
        """Get state transition history."""
        machine = get_protection_state_machine()
        return {
            "current_state": machine.current_state.name,
            "history": machine.get_history(limit),
        }

    @router.post("/status/transition")
    async def transition_state(request: StateTransitionRequest):
        """Manually transition to a new state (admin only)."""
        machine = get_protection_state_machine()

        try:
            new_state = ProtectionState[request.state.upper()]
        except KeyError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid state: {request.state}. Valid states: {[s.name for s in ProtectionState]}",
            )

        success, message = await machine.transition_to(
            new_state, reason=request.reason or "Manual transition", force=request.force
        )

        if not success:
            raise HTTPException(status_code=400, detail=message)

        return {
            "success": True,
            "message": message,
            "current_state": machine.current_state.name,
        }

    @router.get("/status/valid-transitions")
    async def get_valid_transitions():
        """Get valid transitions from current state."""
        machine = get_protection_state_machine()
        current = machine.current_state
        valid = ProtectionStateMachine.VALID_TRANSITIONS.get(current, set())

        return {
            "current_state": current.name,
            "valid_transitions": [s.name for s in valid],
            "all_states": [
                {
                    "name": s.name,
                    "severity": s.severity,
                    "human_readable": s.human_readable,
                    "remediation": s.remediation_hint,
                }
                for s in ProtectionState
            ],
        }

    return router
