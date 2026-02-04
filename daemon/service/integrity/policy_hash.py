"""
Policy Integrity Monitoring - Tamper Detection

From guard-plan-v1.md Meta-Layer 7: Guard Self-Integrity Monitoring

Implements:
- Policy file hash computation
- Signed policy change log (hash chain)
- Tamper detection on policy files
- Integrity verification API
"""

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PolicyIntegrityRecord:
    """
    Tamper-evident record of policy state.

    Each change creates a signed record linked to the previous.
    """

    record_id: str
    policy_hash: str  # Merkle root of all policy files
    timestamp: datetime
    changed_by: str  # User/system that made change
    change_type: str  # "user_edit", "learning", "mode_switch", "reset"
    description: str
    previous_hash: str  # Hash of previous record
    signature: str  # HMAC of record data

    def to_dict(self) -> Dict:
        return {
            "record_id": self.record_id,
            "policy_hash": self.policy_hash,
            "timestamp": self.timestamp.isoformat(),
            "changed_by": self.changed_by,
            "change_type": self.change_type,
            "description": self.description,
            "previous_hash": self.previous_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "PolicyIntegrityRecord":
        return cls(
            record_id=data["record_id"],
            policy_hash=data["policy_hash"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            changed_by=data["changed_by"],
            change_type=data["change_type"],
            description=data["description"],
            previous_hash=data["previous_hash"],
            signature=data["signature"],
        )


@dataclass
class IntegrityVerificationResult:
    """Result of integrity verification."""

    passed: bool
    message: str
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    last_authorized_change: Optional[datetime] = None
    tampering_detected: bool = False
    tampered_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "passed": self.passed,
            "message": self.message,
            "expected_hash": self.expected_hash,
            "actual_hash": self.actual_hash,
            "last_authorized_change": (
                self.last_authorized_change.isoformat()
                if self.last_authorized_change
                else None
            ),
            "tampering_detected": self.tampering_detected,
            "tampered_files": self.tampered_files,
        }


class PolicyIntegrityVerifier:
    """
    Detect unauthorized policy modifications.

    Maintains a hash chain of authorized policy changes
    and verifies current policy state matches expectations.
    """

    def __init__(
        self,
        policy_dir: Path,
        secret_key: Optional[bytes] = None,
        integrity_log_path: Optional[Path] = None,
    ):
        self.policy_dir = Path(policy_dir)

        # Generate or load secret key for HMAC signing
        if secret_key:
            self.secret_key = secret_key
        else:
            self.secret_key = self._load_or_create_key()

        # Integrity log path
        self.integrity_log_path = (
            integrity_log_path
            or Path.home() / ".faramesh-guard" / "policy_integrity.jsonl"
        )
        self.integrity_log_path.parent.mkdir(parents=True, exist_ok=True)

        # Load existing integrity log
        self.integrity_log: List[PolicyIntegrityRecord] = []
        self._load_integrity_log()

        # Initialize if empty
        if not self.integrity_log:
            self._initialize_baseline()

        logger.info(f"PolicyIntegrityVerifier initialized for {policy_dir}")

    def _load_or_create_key(self) -> bytes:
        """Load or create HMAC signing key."""
        key_path = Path.home() / ".faramesh-guard" / ".policy_key"
        key_path.parent.mkdir(parents=True, exist_ok=True)

        if key_path.exists():
            return key_path.read_bytes()
        else:
            # Generate new key
            key = os.urandom(32)
            key_path.write_bytes(key)
            key_path.chmod(0o600)  # Restrict permissions
            return key

    def _load_integrity_log(self):
        """Load integrity log from disk."""
        if not self.integrity_log_path.exists():
            return

        try:
            with open(self.integrity_log_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        data = json.loads(line)
                        record = PolicyIntegrityRecord.from_dict(data)
                        self.integrity_log.append(record)

            logger.info(f"Loaded {len(self.integrity_log)} integrity records")
        except Exception as e:
            logger.error(f"Failed to load integrity log: {e}")

    def _save_record(self, record: PolicyIntegrityRecord):
        """Append record to integrity log."""
        with open(self.integrity_log_path, "a") as f:
            f.write(json.dumps(record.to_dict()) + "\n")

    def _initialize_baseline(self):
        """Create initial baseline record."""
        self.record_change(
            changed_by="system",
            change_type="initialization",
            description="Initial policy integrity baseline",
        )

    def compute_policy_hash(self) -> str:
        """
        Compute deterministic hash of all policy files.

        Returns Merkle root hash of all policy files.
        """
        # Find all policy files
        policy_extensions = [".yaml", ".yml", ".rego", ".cedar", ".json"]
        policy_files = []

        if self.policy_dir.exists():
            for ext in policy_extensions:
                policy_files.extend(self.policy_dir.glob(f"**/*{ext}"))

        # Sort for deterministic ordering
        policy_files = sorted(policy_files)

        # Compute hash of each file
        file_hashes = {}
        for path in policy_files:
            try:
                content = path.read_text(encoding="utf-8")
                file_hash = hashlib.sha256(content.encode()).hexdigest()
                rel_path = str(path.relative_to(self.policy_dir))
                file_hashes[rel_path] = file_hash
            except Exception as e:
                logger.warning(f"Failed to hash {path}: {e}")

        # Compute Merkle root
        if not file_hashes:
            return hashlib.sha256(b"empty").hexdigest()

        combined = json.dumps(file_hashes, sort_keys=True)
        return hashlib.sha256(combined.encode()).hexdigest()

    def _compute_file_hashes(self) -> Dict[str, str]:
        """Get individual file hashes for detailed reporting."""
        policy_extensions = [".yaml", ".yml", ".rego", ".cedar", ".json"]
        file_hashes = {}

        if self.policy_dir.exists():
            for ext in policy_extensions:
                for path in self.policy_dir.glob(f"**/*{ext}"):
                    try:
                        content = path.read_text(encoding="utf-8")
                        file_hash = hashlib.sha256(content.encode()).hexdigest()
                        rel_path = str(path.relative_to(self.policy_dir))
                        file_hashes[rel_path] = file_hash
                    except Exception:
                        pass

        return file_hashes

    def _sign_record(
        self, policy_hash: str, changed_by: str, change_type: str, timestamp: datetime
    ) -> str:
        """Sign policy change record with HMAC."""
        message = f"{policy_hash}|{changed_by}|{change_type}|{timestamp.isoformat()}"
        return hmac.new(self.secret_key, message.encode(), hashlib.sha256).hexdigest()

    def _verify_signature(self, record: PolicyIntegrityRecord) -> bool:
        """Verify record signature."""
        expected = self._sign_record(
            record.policy_hash, record.changed_by, record.change_type, record.timestamp
        )
        return hmac.compare_digest(expected, record.signature)

    def record_change(
        self, changed_by: str, change_type: str, description: str
    ) -> PolicyIntegrityRecord:
        """
        Record authorized policy change in integrity log.

        Call this whenever policy is legitimately modified.
        """
        current_hash = self.compute_policy_hash()
        previous = self.integrity_log[-1] if self.integrity_log else None
        previous_hash = previous.policy_hash if previous else "genesis"

        timestamp = datetime.utcnow()
        signature = self._sign_record(current_hash, changed_by, change_type, timestamp)

        record = PolicyIntegrityRecord(
            record_id=hashlib.sha256(
                f"{current_hash}{timestamp.isoformat()}".encode()
            ).hexdigest()[:16],
            policy_hash=current_hash,
            timestamp=timestamp,
            changed_by=changed_by,
            change_type=change_type,
            description=description,
            previous_hash=previous_hash,
            signature=signature,
        )

        self.integrity_log.append(record)
        self._save_record(record)

        logger.info(f"Policy change recorded: {change_type} by {changed_by}")
        return record

    def verify_integrity(self) -> IntegrityVerificationResult:
        """
        Verify policy hasn't been tampered with.

        Compares current policy hash against last recorded hash.
        """
        current_hash = self.compute_policy_hash()
        last_record = self.integrity_log[-1] if self.integrity_log else None

        if not last_record:
            return IntegrityVerificationResult(
                passed=True, message="No integrity baseline yet (first run)"
            )

        # Check if hash matches
        if current_hash != last_record.policy_hash:
            # Detect which files changed
            tampered_files = self._detect_tampered_files()

            return IntegrityVerificationResult(
                passed=False,
                message="POLICY TAMPERING DETECTED: Policy hash mismatch",
                expected_hash=last_record.policy_hash,
                actual_hash=current_hash,
                last_authorized_change=last_record.timestamp,
                tampering_detected=True,
                tampered_files=tampered_files,
            )

        # Verify signature chain
        for i, record in enumerate(self.integrity_log):
            if not self._verify_signature(record):
                return IntegrityVerificationResult(
                    passed=False,
                    message=f"SIGNATURE INVALID: Record #{i} signature verification failed",
                    tampering_detected=True,
                )

        return IntegrityVerificationResult(
            passed=True,
            message="Policy integrity verified",
            expected_hash=current_hash,
            actual_hash=current_hash,
            last_authorized_change=last_record.timestamp,
        )

    def _detect_tampered_files(self) -> List[str]:
        """Identify which files were tampered with."""
        if not self.integrity_log:
            return []

        # This would require storing individual file hashes
        # For now, just indicate the policy was modified
        return ["<policy files modified>"]

    def verify_chain(self) -> IntegrityVerificationResult:
        """Verify the entire integrity chain."""
        if not self.integrity_log:
            return IntegrityVerificationResult(
                passed=True, message="No integrity chain to verify"
            )

        # Verify each record
        broken_links = []
        for i in range(len(self.integrity_log)):
            record = self.integrity_log[i]

            # Verify signature
            if not self._verify_signature(record):
                broken_links.append(f"Record {i}: Invalid signature")

            # Verify chain link (except first)
            if i > 0:
                prev_record = self.integrity_log[i - 1]
                if record.previous_hash != prev_record.policy_hash:
                    broken_links.append(f"Record {i}: Chain link broken")

        if broken_links:
            return IntegrityVerificationResult(
                passed=False,
                message=f"Chain verification failed: {len(broken_links)} issues",
                tampering_detected=True,
                tampered_files=broken_links,
            )

        return IntegrityVerificationResult(
            passed=True,
            message=f"Chain verified: {len(self.integrity_log)} records valid",
        )

    def get_stats(self) -> Dict:
        """Get integrity monitoring statistics."""
        last_record = self.integrity_log[-1] if self.integrity_log else None

        return {
            "total_records": len(self.integrity_log),
            "policy_dir": str(self.policy_dir),
            "current_hash": self.compute_policy_hash(),
            "last_change": last_record.timestamp.isoformat() if last_record else None,
            "last_change_by": last_record.changed_by if last_record else None,
            "last_change_type": last_record.change_type if last_record else None,
        }


# Global instance
_policy_verifier: Optional[PolicyIntegrityVerifier] = None


def get_policy_verifier(policy_dir: Optional[Path] = None) -> PolicyIntegrityVerifier:
    """Get or create the global policy integrity verifier."""
    global _policy_verifier
    if _policy_verifier is None:
        if policy_dir is None:
            policy_dir = Path(__file__).parent.parent / "policy" / "cold_start"
        _policy_verifier = PolicyIntegrityVerifier(policy_dir)
    return _policy_verifier
