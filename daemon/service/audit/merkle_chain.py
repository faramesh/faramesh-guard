"""
Merkle Chain Audit Log - Tamper-Evident Audit Trail

Implements cryptographic audit logs using hash chains (Merkle chains).
Each entry is cryptographically bound to the previous entry, making
tampering detectable.

Key Features:
- Tamper-evident: any modification breaks the chain
- Cryptographic integrity: SHA256 hash chains
- Verifiable: full chain verification
- Append-only: no modification or deletion

Following guard-plan-v1.md: Tamper-Evident Audit Logs
"""

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """Single audit log entry."""

    timestamp: str  # ISO format
    action_id: str  # CAR hash
    event_type: str  # "action_authorized", "action_denied", "permit_minted", etc.
    decision: str  # "ALLOW", "DENY", "ABSTAIN"
    risk_score: float
    metadata: Dict[str, Any]
    prev_hash: str  # Hash of previous entry (Merkle chain)
    entry_hash: str  # Hash of this entry


@dataclass
class ChainVerification:
    """Result of chain verification."""

    valid: bool
    total_entries: int
    first_hash: str
    last_hash: str
    broken_links: List[int]  # Indices where chain is broken
    message: str


class MerkleAuditLog:
    """
    Tamper-evident audit log using Merkle chains.

    Each entry contains:
    - Entry data (timestamp, action, decision, etc.)
    - prev_hash: hash of previous entry
    - entry_hash: hash of (entry_data || prev_hash)

    Tampering with any entry breaks the chain.
    """

    def __init__(self, log_file: Optional[Path] = None):
        if log_file is None:
            log_file = Path.home() / ".faramesh-guard" / "audit" / "audit.jsonl"

        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        # Genesis hash (for first entry)
        self.genesis_hash = "0" * 64

        # Cache last hash for fast append
        self._last_hash = None

        logger.info(f"MerkleAuditLog initialized with log_file={log_file}")

    def append(
        self,
        action_id: str,
        event_type: str,
        decision: str,
        risk_score: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Append entry to audit log.

        Args:
            action_id: CAR hash of action
            event_type: Type of event
            decision: Decision made (ALLOW/DENY/ABSTAIN)
            risk_score: Risk score [0,1]
            metadata: Additional metadata

        Returns:
            Entry hash (can be used to verify entry later)
        """
        if metadata is None:
            metadata = {}

        # Get previous hash
        prev_hash = self._get_last_hash()

        # Create entry
        timestamp = datetime.utcnow().isoformat()
        entry_data = {
            "timestamp": timestamp,
            "action_id": action_id,
            "event_type": event_type,
            "decision": decision,
            "risk_score": risk_score,
            "metadata": metadata,
            "prev_hash": prev_hash,
        }

        # Compute entry hash: H(entry_data || prev_hash)
        entry_hash = self._compute_hash(entry_data)
        entry_data["entry_hash"] = entry_hash

        # Write to log
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry_data) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
            raise

        # Update cache
        self._last_hash = entry_hash

        logger.debug(
            f"Audit entry appended: {event_type} for {action_id[:12]} "
            f"(hash={entry_hash[:12]})"
        )

        return entry_hash

    def verify_chain(self) -> ChainVerification:
        """
        Verify entire audit chain integrity.

        Returns:
            ChainVerification with results
        """
        if not self.log_file.exists():
            return ChainVerification(
                valid=True,
                total_entries=0,
                first_hash="",
                last_hash="",
                broken_links=[],
                message="No audit log exists yet",
            )

        entries = self._read_all_entries()
        if not entries:
            return ChainVerification(
                valid=True,
                total_entries=0,
                first_hash="",
                last_hash="",
                broken_links=[],
                message="Audit log is empty",
            )

        broken_links = []
        expected_prev_hash = self.genesis_hash

        for i, entry in enumerate(entries):
            # Verify prev_hash matches expected
            if entry["prev_hash"] != expected_prev_hash:
                broken_links.append(i)
                logger.warning(
                    f"Chain broken at entry {i}: "
                    f"expected prev_hash={expected_prev_hash[:12]}, "
                    f"got={entry['prev_hash'][:12]}"
                )

            # Verify entry_hash is correct
            computed_hash = self._compute_hash(entry)
            if entry["entry_hash"] != computed_hash:
                broken_links.append(i)
                logger.warning(
                    f"Entry {i} has invalid hash: "
                    f"stored={entry['entry_hash'][:12]}, "
                    f"computed={computed_hash[:12]}"
                )

            expected_prev_hash = entry["entry_hash"]

        valid = len(broken_links) == 0

        return ChainVerification(
            valid=valid,
            total_entries=len(entries),
            first_hash=entries[0]["entry_hash"] if entries else "",
            last_hash=entries[-1]["entry_hash"] if entries else "",
            broken_links=broken_links,
            message=f"Chain valid: {valid}, {len(entries)} entries, "
            f"{len(broken_links)} broken links",
        )

    def get_entries(self, start_index: int = 0, limit: int = 100) -> List[AuditEntry]:
        """
        Get entries from audit log.

        Args:
            start_index: Starting index (0-based)
            limit: Maximum number of entries

        Returns:
            List of AuditEntry objects
        """
        entries = self._read_all_entries()
        selected = entries[start_index : start_index + limit]

        return [
            AuditEntry(
                timestamp=e["timestamp"],
                action_id=e["action_id"],
                event_type=e["event_type"],
                decision=e["decision"],
                risk_score=e["risk_score"],
                metadata=e["metadata"],
                prev_hash=e["prev_hash"],
                entry_hash=e["entry_hash"],
            )
            for e in selected
        ]

    def search(
        self, action_id: Optional[str] = None, event_type: Optional[str] = None
    ) -> List[AuditEntry]:
        """
        Search audit log by criteria.

        Args:
            action_id: Filter by CAR hash
            event_type: Filter by event type

        Returns:
            Matching entries
        """
        entries = self._read_all_entries()
        results = []

        for e in entries:
            if action_id and e["action_id"] != action_id:
                continue
            if event_type and e["event_type"] != event_type:
                continue

            results.append(
                AuditEntry(
                    timestamp=e["timestamp"],
                    action_id=e["action_id"],
                    event_type=e["event_type"],
                    decision=e["decision"],
                    risk_score=e["risk_score"],
                    metadata=e["metadata"],
                    prev_hash=e["prev_hash"],
                    entry_hash=e["entry_hash"],
                )
            )

        return results

    def _get_last_hash(self) -> str:
        """Get hash of last entry (for fast append)."""
        if self._last_hash:
            return self._last_hash

        if not self.log_file.exists():
            return self.genesis_hash

        # Read last line
        try:
            with open(self.log_file, "r") as f:
                lines = f.readlines()
                if not lines:
                    return self.genesis_hash

                last_line = lines[-1].strip()
                if not last_line:
                    return self.genesis_hash

                last_entry = json.loads(last_line)
                return last_entry["entry_hash"]
        except Exception as e:
            logger.error(f"Failed to read last hash: {e}")
            return self.genesis_hash

    def _read_all_entries(self) -> List[Dict]:
        """Read all entries from log file."""
        if not self.log_file.exists():
            return []

        entries = []
        try:
            with open(self.log_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        entries.append(entry)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse log line: {e}")
        except Exception as e:
            logger.error(f"Failed to read audit log: {e}")

        return entries

    def _compute_hash(self, entry_data: Dict) -> str:
        """
        Compute hash of entry.

        Hash = SHA256(entry_data || prev_hash)
        """
        # Create canonical representation
        canonical = {
            "timestamp": entry_data["timestamp"],
            "action_id": entry_data["action_id"],
            "event_type": entry_data["event_type"],
            "decision": entry_data["decision"],
            "risk_score": entry_data["risk_score"],
            "metadata": entry_data["metadata"],
            "prev_hash": entry_data["prev_hash"],
        }

        # Compute hash
        data_str = json.dumps(canonical, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()

    def get_recent(self, limit: int = 100) -> List[Dict]:
        """Get most recent entries (newest first)."""
        entries = self._read_all_entries()
        # Return last N entries in reverse order (newest first)
        return list(reversed(entries[-limit:]))

    def count(self) -> int:
        """Count total entries in audit log."""
        return len(self._read_all_entries())


# Singleton instance
_audit_log: Optional[MerkleAuditLog] = None


def get_audit_log() -> MerkleAuditLog:
    """Get or create singleton MerkleAuditLog instance."""
    global _audit_log
    if _audit_log is None:
        _audit_log = MerkleAuditLog()
    return _audit_log
