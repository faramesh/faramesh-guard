"""
Permit Use Tracking - Database Layer

Tracks permit issuance and usage for:
1. Replay attack detection
2. Audit trail
3. Usage analytics
4. Anomaly detection

Following plan-farameshGuardV1Enhanced.prompt.md:
- SQLite for persistence
- Track permit lifecycle
- Detect multiple use attempts
- Enable forensics
"""

import sqlite3
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class PermitRecord:
    """Record of a permit in the database"""

    permit_id: str
    issued_at: datetime
    expires_at: datetime
    issuer: str
    subject: str  # agent_id
    car_hash: str
    tool: str
    operation: str
    signature: str
    metadata: str  # JSON string

    # Usage tracking
    use_count: int = 0
    first_used_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None

    # Status
    is_revoked: bool = False
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None


@dataclass
class PermitUsage:
    """Record of a single permit usage"""

    usage_id: int
    permit_id: str
    used_at: datetime
    execution_result: str  # 'success' or 'failure'
    error_message: Optional[str]
    execution_duration_ms: Optional[float]


class PermitDatabase:
    """
    SQLite database for permit tracking.

    Schema:
    - permits: Core permit data
    - permit_usage: Individual usage events
    - permit_revocations: Revocation history
    """

    def __init__(self, db_path: str = "guard_permits.db"):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._initialize_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create database connection"""
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None,  # Autocommit mode
            )
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _initialize_db(self):
        """Create database schema"""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Permits table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS permits (
                permit_id TEXT PRIMARY KEY,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                issuer TEXT NOT NULL,
                subject TEXT NOT NULL,
                car_hash TEXT NOT NULL,
                tool TEXT NOT NULL,
                operation TEXT NOT NULL,
                signature TEXT NOT NULL,
                metadata TEXT,
                use_count INTEGER DEFAULT 0,
                first_used_at TEXT,
                last_used_at TEXT,
                is_revoked INTEGER DEFAULT 0,
                revoked_at TEXT,
                revoked_reason TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        # Permit usage table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS permit_usage (
                usage_id INTEGER PRIMARY KEY AUTOINCREMENT,
                permit_id TEXT NOT NULL,
                used_at TEXT NOT NULL,
                execution_result TEXT NOT NULL,
                error_message TEXT,
                execution_duration_ms REAL,
                FOREIGN KEY (permit_id) REFERENCES permits(permit_id)
            )
        """
        )

        # Indices for performance
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_permits_car_hash
            ON permits(car_hash)
        """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_permits_subject
            ON permits(subject)
        """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_permits_issued_at
            ON permits(issued_at)
        """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_usage_permit_id
            ON permit_usage(permit_id)
        """
        )

        conn.commit()
        logger.info(f"Permit database initialized: {self.db_path}")

    def store_permit(self, permit: Dict[str, Any]) -> bool:
        """
        Store a newly issued permit.

        Args:
            permit: Permit dictionary from PermitMinter

        Returns:
            True if stored successfully
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO permits (
                    permit_id, issued_at, expires_at, issuer, subject,
                    car_hash, tool, operation, signature, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    permit["permit_id"],
                    permit["issued_at"],
                    permit["expires_at"],
                    permit["issuer"],
                    permit["subject"],
                    permit["car_hash"],
                    permit["caveats"]["tool"],
                    permit["caveats"]["operation"],
                    permit["signature"],
                    str(permit.get("metadata", {})),
                ),
            )

            logger.info(f"Stored permit: {permit['permit_id']}")
            return True

        except sqlite3.IntegrityError as e:
            logger.warning(f"Permit already exists: {permit['permit_id']}")
            return False
        except Exception as e:
            logger.error(f"Failed to store permit: {e}")
            return False

    def record_usage(
        self,
        permit_id: str,
        success: bool,
        error_message: Optional[str] = None,
        duration_ms: Optional[float] = None,
    ) -> bool:
        """
        Record a permit usage event.

        Args:
            permit_id: The permit being used
            success: Whether execution succeeded
            error_message: Error if failed
            duration_ms: Execution time

        Returns:
            True if recorded successfully
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()

            # Insert usage record
            cursor.execute(
                """
                INSERT INTO permit_usage (
                    permit_id, used_at, execution_result,
                    error_message, execution_duration_ms
                ) VALUES (?, ?, ?, ?, ?)
            """,
                (
                    permit_id,
                    now,
                    "success" if success else "failure",
                    error_message,
                    duration_ms,
                ),
            )

            # Update permit use count
            cursor.execute(
                """
                UPDATE permits
                SET use_count = use_count + 1,
                    first_used_at = COALESCE(first_used_at, ?),
                    last_used_at = ?
                WHERE permit_id = ?
            """,
                (now, now, permit_id),
            )

            logger.debug(f"Recorded usage for permit: {permit_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to record usage: {e}")
            return False

    def get_permit(self, permit_id: str) -> Optional[PermitRecord]:
        """Retrieve a permit by ID"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM permits WHERE permit_id = ?
            """,
                (permit_id,),
            )

            row = cursor.fetchone()
            if not row:
                return None

            return PermitRecord(
                permit_id=row["permit_id"],
                issued_at=datetime.fromisoformat(row["issued_at"].replace("Z", "")),
                expires_at=datetime.fromisoformat(row["expires_at"].replace("Z", "")),
                issuer=row["issuer"],
                subject=row["subject"],
                car_hash=row["car_hash"],
                tool=row["tool"],
                operation=row["operation"],
                signature=row["signature"],
                metadata=row["metadata"],
                use_count=row["use_count"],
                first_used_at=(
                    datetime.fromisoformat(row["first_used_at"])
                    if row["first_used_at"]
                    else None
                ),
                last_used_at=(
                    datetime.fromisoformat(row["last_used_at"])
                    if row["last_used_at"]
                    else None
                ),
                is_revoked=bool(row["is_revoked"]),
                revoked_at=(
                    datetime.fromisoformat(row["revoked_at"])
                    if row["revoked_at"]
                    else None
                ),
                revoked_reason=row["revoked_reason"],
            )

        except Exception as e:
            logger.error(f"Failed to get permit: {e}")
            return None

    def check_replay_attack(self, permit_id: str, car_hash: str) -> bool:
        """
        Check if permit is being replayed for different action.

        Returns:
            True if replay attack detected
        """
        permit = self.get_permit(permit_id)
        if not permit:
            return False

        # If CAR hash doesn't match, it's a replay attempt
        if permit.car_hash != car_hash:
            logger.warning(
                f"REPLAY ATTACK DETECTED: Permit {permit_id} "
                f"issued for CAR {permit.car_hash} but used for {car_hash}"
            )
            return True

        # Check if permit used too many times (if max_uses caveat exists)
        # TODO: Parse metadata for max_uses

        return False

    def revoke_permit(self, permit_id: str, reason: str) -> bool:
        """Revoke a permit"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()

            cursor.execute(
                """
                UPDATE permits
                SET is_revoked = 1,
                    revoked_at = ?,
                    revoked_reason = ?
                WHERE permit_id = ?
            """,
                (now, reason, permit_id),
            )

            logger.warning(f"Permit revoked: {permit_id} - {reason}")
            return True

        except Exception as e:
            logger.error(f"Failed to revoke permit: {e}")
            return False

    def is_revoked(self, permit_id: str) -> bool:
        """Check if permit is revoked"""
        permit = self.get_permit(permit_id)
        return permit.is_revoked if permit else False

    def get_usage_history(self, permit_id: str) -> List[PermitUsage]:
        """Get all usage events for a permit"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM permit_usage
                WHERE permit_id = ?
                ORDER BY used_at DESC
            """,
                (permit_id,),
            )

            rows = cursor.fetchall()
            return [
                PermitUsage(
                    usage_id=row["usage_id"],
                    permit_id=row["permit_id"],
                    used_at=datetime.fromisoformat(row["used_at"]),
                    execution_result=row["execution_result"],
                    error_message=row["error_message"],
                    execution_duration_ms=row["execution_duration_ms"],
                )
                for row in rows
            ]

        except Exception as e:
            logger.error(f"Failed to get usage history: {e}")
            return []

    def get_agent_permits(self, agent_id: str, limit: int = 100) -> List[PermitRecord]:
        """Get recent permits for an agent"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM permits
                WHERE subject = ?
                ORDER BY issued_at DESC
                LIMIT ?
            """,
                (agent_id, limit),
            )

            rows = cursor.fetchall()
            return [self._row_to_permit(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get agent permits: {e}")
            return []

    def _row_to_permit(self, row: sqlite3.Row) -> PermitRecord:
        """Convert database row to PermitRecord"""
        return PermitRecord(
            permit_id=row["permit_id"],
            issued_at=datetime.fromisoformat(row["issued_at"].replace("Z", "")),
            expires_at=datetime.fromisoformat(row["expires_at"].replace("Z", "")),
            issuer=row["issuer"],
            subject=row["subject"],
            car_hash=row["car_hash"],
            tool=row["tool"],
            operation=row["operation"],
            signature=row["signature"],
            metadata=row["metadata"],
            use_count=row["use_count"],
            first_used_at=(
                datetime.fromisoformat(row["first_used_at"])
                if row["first_used_at"]
                else None
            ),
            last_used_at=(
                datetime.fromisoformat(row["last_used_at"])
                if row["last_used_at"]
                else None
            ),
            is_revoked=bool(row["is_revoked"]),
            revoked_at=(
                datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None
            ),
            revoked_reason=row["revoked_reason"],
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) as total FROM permits")
            total_permits = cursor.fetchone()["total"]

            cursor.execute(
                "SELECT COUNT(*) as active FROM permits WHERE is_revoked = 0"
            )
            active_permits = cursor.fetchone()["active"]

            cursor.execute(
                "SELECT COUNT(*) as revoked FROM permits WHERE is_revoked = 1"
            )
            revoked_permits = cursor.fetchone()["revoked"]

            cursor.execute("SELECT COUNT(*) as usages FROM permit_usage")
            total_usages = cursor.fetchone()["usages"]

            cursor.execute(
                """
                SELECT COUNT(*) as replay_attempts
                FROM permit_usage
                WHERE execution_result = 'failure'
                AND error_message LIKE '%replay%'
            """
            )
            replay_attempts = cursor.fetchone()["replay_attempts"]

            return {
                "total_permits": total_permits,
                "active_permits": active_permits,
                "revoked_permits": revoked_permits,
                "total_usages": total_usages,
                "replay_attempts": replay_attempts,
            }

        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {}

    def cleanup_expired(self) -> int:
        """Remove expired permits from database"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()

            cursor.execute(
                """
                DELETE FROM permits
                WHERE expires_at < ? AND is_revoked = 0
            """,
                (now,),
            )

            deleted = cursor.rowcount
            logger.info(f"Cleaned up {deleted} expired permits")
            return deleted

        except Exception as e:
            logger.error(f"Failed to cleanup: {e}")
            return 0

    def close(self):
        """Close database connection"""
        if self._conn:
            self._conn.close()
            self._conn = None


# Global database instance
_global_db: Optional[PermitDatabase] = None


def get_permit_database(db_path: str = "guard_permits.db") -> PermitDatabase:
    """Get or create the global permit database"""
    global _global_db
    if _global_db is None:
        _global_db = PermitDatabase(db_path)
    return _global_db
