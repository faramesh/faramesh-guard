"""
Pending Actions Store for Guard.

Manages actions that need human approval (ABSTAIN decisions).
Uses in-memory store with SQLite persistence.
"""

import logging
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class PendingActionStatus(str, Enum):
    """Status of a pending action."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    TIMEOUT = "timeout"


@dataclass
class PendingAction:
    """A pending action awaiting approval."""

    action_id: str
    tool_name: str
    args: Dict[str, Any]
    agent_id: str
    car_hash: str
    reason: str
    risk_level: str
    status: PendingActionStatus
    created_at: str
    expires_at: str
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None
    resolution_reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


class PendingActionsStore:
    """
    Manages pending actions with WebSocket notification.

    Features:
    - In-memory store with SQLite persistence
    - Automatic expiration cleanup
    - WebSocket callbacks for UI updates
    - Thread-safe operations
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        default_ttl_seconds: int = 300,  # 5 minutes
    ):
        self.db_path = db_path or Path.home() / ".faramesh-guard" / "pending_actions.db"
        self.default_ttl = timedelta(seconds=default_ttl_seconds)
        self._callbacks: List[Callable[[PendingAction, str], None]] = []

        # In-memory cache for fast lookups
        self._cache: Dict[str, PendingAction] = {}

        # Initialize database
        self._init_db()
        self._load_pending_from_db()

        logger.info(f"PendingActionsStore initialized with db={self.db_path}")

    def _init_db(self):
        """Initialize SQLite database."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_actions (
                    action_id TEXT PRIMARY KEY,
                    tool_name TEXT NOT NULL,
                    args TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    car_hash TEXT NOT NULL,
                    reason TEXT,
                    risk_level TEXT,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    resolved_at TEXT,
                    resolved_by TEXT,
                    resolution_reason TEXT,
                    metadata TEXT
                )
            """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_status ON pending_actions(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_expires ON pending_actions(expires_at)"
            )
            conn.commit()

    def _load_pending_from_db(self):
        """Load pending actions from database into cache."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM pending_actions WHERE status = ?",
                (PendingActionStatus.PENDING.value,),
            )
            for row in cursor:
                action = PendingAction(
                    action_id=row["action_id"],
                    tool_name=row["tool_name"],
                    args=json.loads(row["args"]),
                    agent_id=row["agent_id"],
                    car_hash=row["car_hash"],
                    reason=row["reason"],
                    risk_level=row["risk_level"],
                    status=PendingActionStatus(row["status"]),
                    created_at=row["created_at"],
                    expires_at=row["expires_at"],
                    resolved_at=row["resolved_at"],
                    resolved_by=row["resolved_by"],
                    resolution_reason=row["resolution_reason"],
                    metadata=json.loads(row["metadata"]) if row["metadata"] else None,
                )
                self._cache[action.action_id] = action

    def register_callback(self, callback: Callable[[PendingAction, str], None]):
        """Register a callback for action updates."""
        self._callbacks.append(callback)

    def _notify(self, action: PendingAction, event_type: str):
        """Notify all registered callbacks."""
        for callback in self._callbacks:
            try:
                callback(action, event_type)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    def add(
        self,
        action_id: str,
        tool_name: str,
        args: Dict[str, Any],
        agent_id: str,
        car_hash: str,
        reason: str,
        risk_level: str = "medium",
        ttl_seconds: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PendingAction:
        """Add a new pending action."""
        now = datetime.utcnow()
        ttl = timedelta(seconds=ttl_seconds) if ttl_seconds else self.default_ttl

        action = PendingAction(
            action_id=action_id,
            tool_name=tool_name,
            args=args,
            agent_id=agent_id,
            car_hash=car_hash,
            reason=reason,
            risk_level=risk_level,
            status=PendingActionStatus.PENDING,
            created_at=now.isoformat() + "Z",
            expires_at=(now + ttl).isoformat() + "Z",
            metadata=metadata,
        )

        # Save to database
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                INSERT INTO pending_actions
                (action_id, tool_name, args, agent_id, car_hash, reason, risk_level,
                 status, created_at, expires_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    action.action_id,
                    action.tool_name,
                    json.dumps(action.args),
                    action.agent_id,
                    action.car_hash,
                    action.reason,
                    action.risk_level,
                    action.status.value,
                    action.created_at,
                    action.expires_at,
                    json.dumps(action.metadata) if action.metadata else None,
                ),
            )
            conn.commit()

        # Add to cache
        self._cache[action_id] = action

        # Notify callbacks
        self._notify(action, "pending")

        logger.info(f"Added pending action: {action_id} ({tool_name})")
        return action

    def get(self, action_id: str) -> Optional[PendingAction]:
        """Get a pending action by ID."""
        # Check cache first
        if action_id in self._cache:
            action = self._cache[action_id]
            # Check if expired
            if action.status == PendingActionStatus.PENDING:
                if datetime.utcnow().isoformat() > action.expires_at:
                    self._expire(action_id)
                    return self._cache.get(action_id)
            return action

        # Fall back to database
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM pending_actions WHERE action_id = ?", (action_id,)
            )
            row = cursor.fetchone()
            if row:
                action = PendingAction(
                    action_id=row["action_id"],
                    tool_name=row["tool_name"],
                    args=json.loads(row["args"]),
                    agent_id=row["agent_id"],
                    car_hash=row["car_hash"],
                    reason=row["reason"],
                    risk_level=row["risk_level"],
                    status=PendingActionStatus(row["status"]),
                    created_at=row["created_at"],
                    expires_at=row["expires_at"],
                    resolved_at=row["resolved_at"],
                    resolved_by=row["resolved_by"],
                    resolution_reason=row["resolution_reason"],
                    metadata=json.loads(row["metadata"]) if row["metadata"] else None,
                )
                return action

        return None

    def list_pending(self) -> List[PendingAction]:
        """List all pending actions."""
        # Expire old actions first
        self._expire_old()

        return [
            a for a in self._cache.values() if a.status == PendingActionStatus.PENDING
        ]

    def approve(
        self,
        action_id: str,
        approved_by: str = "user",
        reason: Optional[str] = None,
    ) -> Optional[PendingAction]:
        """Approve a pending action."""
        action = self.get(action_id)
        if not action:
            return None

        if action.status != PendingActionStatus.PENDING:
            logger.warning(
                f"Cannot approve non-pending action: {action_id} ({action.status})"
            )
            return action

        now = datetime.utcnow().isoformat() + "Z"
        action.status = PendingActionStatus.APPROVED
        action.resolved_at = now
        action.resolved_by = approved_by
        action.resolution_reason = reason

        # Update database
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                UPDATE pending_actions
                SET status = ?, resolved_at = ?, resolved_by = ?, resolution_reason = ?
                WHERE action_id = ?
            """,
                (
                    action.status.value,
                    action.resolved_at,
                    action.resolved_by,
                    action.resolution_reason,
                    action_id,
                ),
            )
            conn.commit()

        # Notify callbacks
        self._notify(action, "approved")

        logger.info(f"Approved action: {action_id} by {approved_by}")
        return action

    def deny(
        self,
        action_id: str,
        denied_by: str = "user",
        reason: Optional[str] = None,
    ) -> Optional[PendingAction]:
        """Deny a pending action."""
        action = self.get(action_id)
        if not action:
            return None

        if action.status != PendingActionStatus.PENDING:
            logger.warning(
                f"Cannot deny non-pending action: {action_id} ({action.status})"
            )
            return action

        now = datetime.utcnow().isoformat() + "Z"
        action.status = PendingActionStatus.DENIED
        action.resolved_at = now
        action.resolved_by = denied_by
        action.resolution_reason = reason

        # Update database
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                UPDATE pending_actions
                SET status = ?, resolved_at = ?, resolved_by = ?, resolution_reason = ?
                WHERE action_id = ?
            """,
                (
                    action.status.value,
                    action.resolved_at,
                    action.resolved_by,
                    action.resolution_reason,
                    action_id,
                ),
            )
            conn.commit()

        # Notify callbacks
        self._notify(action, "denied")

        logger.info(f"Denied action: {action_id} by {denied_by}")
        return action

    def _expire(self, action_id: str):
        """Mark an action as expired."""
        action = self._cache.get(action_id)
        if not action:
            return

        action.status = PendingActionStatus.EXPIRED
        action.resolved_at = datetime.utcnow().isoformat() + "Z"

        # Update database
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                UPDATE pending_actions
                SET status = ?, resolved_at = ?
                WHERE action_id = ?
            """,
                (
                    action.status.value,
                    action.resolved_at,
                    action_id,
                ),
            )
            conn.commit()

        # Notify callbacks
        self._notify(action, "expired")

        logger.info(f"Action expired: {action_id}")

    def _expire_old(self):
        """Expire all old pending actions."""
        now = datetime.utcnow().isoformat()
        to_expire = [
            action_id
            for action_id, action in self._cache.items()
            if action.status == PendingActionStatus.PENDING and action.expires_at < now
        ]
        for action_id in to_expire:
            self._expire(action_id)

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about pending actions."""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.execute(
                """
                SELECT status, COUNT(*) as count
                FROM pending_actions
                GROUP BY status
            """
            )
            status_counts = {row[0]: row[1] for row in cursor}

        return {
            "pending": status_counts.get(PendingActionStatus.PENDING.value, 0),
            "approved": status_counts.get(PendingActionStatus.APPROVED.value, 0),
            "denied": status_counts.get(PendingActionStatus.DENIED.value, 0),
            "expired": status_counts.get(PendingActionStatus.EXPIRED.value, 0),
            "cached": len(self._cache),
        }
