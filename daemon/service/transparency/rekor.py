"""
Rekor Transparency Log Integration

Implements transparency logging using Sigstore's Rekor-style approach.
Provides cryptographic proof that audit entries were recorded.

Features:
- Submit audit entries to transparency log
- Verify inclusion proofs
- Signed timestamps (SCTs)
- Merkle tree verification
- Local fallback when offline

Reference: https://docs.sigstore.dev/rekor/overview/
"""

import json
import hashlib
import hmac
import base64
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import logging
import urllib.request
import urllib.error
import threading

logger = logging.getLogger("guard.transparency.rekor")

# Rekor API endpoint
REKOR_API_URL = "https://rekor.sigstore.dev"
GUARD_TRANSPARENCY_URL = "https://transparency.faramesh.ai"  # Our own log


class EntryType(Enum):
    """Types of transparency log entries."""
    DECISION = "guard:decision"
    POLICY_CHANGE = "guard:policy_change"
    PERMIT = "guard:permit"
    AUDIT = "guard:audit"


@dataclass
class SignedTimestamp:
    """Signed Certificate Timestamp (SCT) from transparency log."""
    timestamp: str  # ISO timestamp
    signature: str  # Base64-encoded signature
    log_id: str  # Identity of the log

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "signature": self.signature,
            "log_id": self.log_id
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SignedTimestamp":
        return cls(
            timestamp=data["timestamp"],
            signature=data["signature"],
            log_id=data["log_id"]
        )


@dataclass
class InclusionProof:
    """Merkle tree inclusion proof."""
    log_index: int  # Position in log
    root_hash: str  # Merkle root at time of inclusion
    tree_size: int  # Size of tree at inclusion
    hashes: List[str]  # Proof hashes (path to root)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_index": self.log_index,
            "root_hash": self.root_hash,
            "tree_size": self.tree_size,
            "hashes": self.hashes
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InclusionProof":
        return cls(
            log_index=data["log_index"],
            root_hash=data["root_hash"],
            tree_size=data["tree_size"],
            hashes=data["hashes"]
        )


@dataclass
class TransparencyEntry:
    """Entry in the transparency log."""
    entry_id: str  # UUID
    entry_type: EntryType
    body: Dict[str, Any]  # The actual content
    body_hash: str  # SHA-256 of canonical body

    # Transparency proofs
    sct: Optional[SignedTimestamp] = None
    inclusion_proof: Optional[InclusionProof] = None

    # Metadata
    submitted_at: str = ""
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "entry_type": self.entry_type.value,
            "body": self.body,
            "body_hash": self.body_hash,
            "sct": self.sct.to_dict() if self.sct else None,
            "inclusion_proof": self.inclusion_proof.to_dict() if self.inclusion_proof else None,
            "submitted_at": self.submitted_at,
            "verified": self.verified
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TransparencyEntry":
        return cls(
            entry_id=data["entry_id"],
            entry_type=EntryType(data["entry_type"]),
            body=data["body"],
            body_hash=data["body_hash"],
            sct=SignedTimestamp.from_dict(data["sct"]) if data.get("sct") else None,
            inclusion_proof=InclusionProof.from_dict(data["inclusion_proof"]) if data.get("inclusion_proof") else None,
            submitted_at=data.get("submitted_at", ""),
            verified=data.get("verified", False)
        )


class LocalTransparencyLog:
    """
    Local transparency log with Merkle tree structure.
    Used when online log is unavailable, entries are synced later.
    """

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path or Path.home() / ".faramesh-guard" / "transparency" / "local_log.jsonl"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        self.tree_path = self.log_path.parent / "merkle_tree.json"

        # In-memory state
        self.entries: List[TransparencyEntry] = []
        self.leaf_hashes: List[str] = []
        self.root_hash: str = ""

        self._load_state()
        self._lock = threading.Lock()

    def _load_state(self) -> None:
        """Load existing log state."""
        if self.tree_path.exists():
            try:
                with open(self.tree_path) as f:
                    state = json.load(f)
                    self.leaf_hashes = state.get("leaf_hashes", [])
                    self.root_hash = state.get("root_hash", "")
            except:
                pass

    def _save_state(self) -> None:
        """Save log state."""
        with open(self.tree_path, "w") as f:
            json.dump({
                "leaf_hashes": self.leaf_hashes,
                "root_hash": self.root_hash,
                "tree_size": len(self.leaf_hashes)
            }, f)

    def append(self, entry: TransparencyEntry) -> TransparencyEntry:
        """
        Append entry to local log with Merkle proof.
        """
        with self._lock:
            # Compute leaf hash
            leaf_hash = self._hash_entry(entry)

            # Add to tree
            log_index = len(self.leaf_hashes)
            self.leaf_hashes.append(leaf_hash)

            # Recompute root
            old_root = self.root_hash
            self.root_hash = self._compute_root()

            # Generate inclusion proof
            proof_hashes = self._compute_inclusion_proof(log_index)

            entry.inclusion_proof = InclusionProof(
                log_index=log_index,
                root_hash=self.root_hash,
                tree_size=len(self.leaf_hashes),
                hashes=proof_hashes
            )

            # Generate local SCT
            entry.sct = SignedTimestamp(
                timestamp=datetime.utcnow().isoformat() + "Z",
                signature=self._sign_sct(entry.body_hash, self.root_hash),
                log_id="local"
            )

            entry.submitted_at = datetime.utcnow().isoformat() + "Z"

            # Write to log file
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry.to_dict()) + "\n")

            self._save_state()

            logger.debug(f"Appended entry {entry.entry_id} at index {log_index}")
            return entry

    def _hash_entry(self, entry: TransparencyEntry) -> str:
        """Compute leaf hash for entry."""
        canonical = json.dumps(entry.body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _compute_root(self) -> str:
        """Compute Merkle root from leaf hashes."""
        if not self.leaf_hashes:
            return hashlib.sha256(b"").hexdigest()

        # Build tree
        level = self.leaf_hashes[:]

        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                combined = hashlib.sha256((left + right).encode()).hexdigest()
                next_level.append(combined)
            level = next_level

        return level[0]

    def _compute_inclusion_proof(self, index: int) -> List[str]:
        """Compute Merkle inclusion proof for entry at index."""
        if not self.leaf_hashes:
            return []

        proof = []
        level = self.leaf_hashes[:]
        current_index = index

        while len(level) > 1:
            # Get sibling
            if current_index % 2 == 0:
                sibling_index = current_index + 1 if current_index + 1 < len(level) else current_index
            else:
                sibling_index = current_index - 1

            proof.append(level[sibling_index])

            # Move to next level
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                combined = hashlib.sha256((left + right).encode()).hexdigest()
                next_level.append(combined)

            level = next_level
            current_index = current_index // 2

        return proof

    def _sign_sct(self, body_hash: str, root_hash: str) -> str:
        """Sign SCT (local key for offline mode)."""
        # In production, use proper key management
        local_key = b"guard-local-transparency-key"
        message = f"{body_hash}|{root_hash}|{datetime.utcnow().isoformat()}"
        signature = hmac.new(local_key, message.encode(), hashlib.sha256).hexdigest()
        return base64.b64encode(signature.encode()).decode()

    def verify_inclusion(self, entry: TransparencyEntry) -> bool:
        """Verify entry's inclusion proof."""
        if not entry.inclusion_proof:
            return False

        proof = entry.inclusion_proof

        # Compute leaf hash
        leaf_hash = self._hash_entry(entry)

        # Walk up the tree using proof
        current = leaf_hash
        index = proof.log_index

        for sibling_hash in proof.hashes:
            if index % 2 == 0:
                current = hashlib.sha256((current + sibling_hash).encode()).hexdigest()
            else:
                current = hashlib.sha256((sibling_hash + current).encode()).hexdigest()
            index = index // 2

        # Compare with root
        return current == proof.root_hash

    def get_pending_sync(self) -> List[TransparencyEntry]:
        """Get entries that haven't been synced to online log."""
        pending = []

        if self.log_path.exists():
            with open(self.log_path) as f:
                for line in f:
                    try:
                        entry = TransparencyEntry.from_dict(json.loads(line))
                        if entry.sct and entry.sct.log_id == "local":
                            pending.append(entry)
                    except:
                        continue

        return pending


class RekorClient:
    """
    Client for Sigstore Rekor transparency log.
    Supports both public Rekor and private Guard transparency log.
    """

    def __init__(
        self,
        api_url: str = GUARD_TRANSPARENCY_URL,
        fallback_to_local: bool = True
    ):
        self.api_url = api_url.rstrip("/")
        self.fallback_to_local = fallback_to_local
        self.local_log = LocalTransparencyLog()

        self._online = None  # Unknown until first request

    def submit_entry(
        self,
        entry_type: EntryType,
        body: Dict[str, Any]
    ) -> TransparencyEntry:
        """
        Submit an entry to the transparency log.

        Args:
            entry_type: Type of entry
            body: Entry content

        Returns:
            TransparencyEntry with proofs
        """
        import uuid

        # Create entry
        canonical_body = json.dumps(body, sort_keys=True, separators=(",", ":"))
        body_hash = hashlib.sha256(canonical_body.encode()).hexdigest()

        entry = TransparencyEntry(
            entry_id=str(uuid.uuid4()),
            entry_type=entry_type,
            body=body,
            body_hash=body_hash
        )

        # Try online submission
        if self._is_online():
            try:
                return self._submit_online(entry)
            except Exception as e:
                logger.warning(f"Online submission failed: {e}")
                if not self.fallback_to_local:
                    raise

        # Fallback to local
        return self.local_log.append(entry)

    def verify_entry(self, entry: TransparencyEntry) -> Tuple[bool, Optional[str]]:
        """
        Verify an entry's inclusion proof.

        Returns:
            (valid, error_message)
        """
        if not entry.inclusion_proof:
            return False, "No inclusion proof"

        # Check local proof first
        if entry.sct and entry.sct.log_id == "local":
            valid = self.local_log.verify_inclusion(entry)
            return valid, None if valid else "Local inclusion proof invalid"

        # Verify online proof
        if self._is_online():
            try:
                return self._verify_online(entry)
            except Exception as e:
                return False, f"Online verification failed: {e}"

        return False, "Cannot verify online proof while offline"

    def get_proof(self, entry_id: str) -> Optional[InclusionProof]:
        """
        Get inclusion proof for an entry by ID.
        """
        if self._is_online():
            try:
                return self._fetch_proof_online(entry_id)
            except:
                pass
        return None

    def sync_local_entries(self) -> int:
        """
        Sync locally logged entries to online log.

        Returns:
            Number of entries synced
        """
        if not self._is_online():
            return 0

        pending = self.local_log.get_pending_sync()
        synced = 0

        for entry in pending:
            try:
                online_entry = self._submit_online(entry)
                # Update local entry with online proof
                # TODO: Update local log file
                synced += 1
            except Exception as e:
                logger.warning(f"Failed to sync entry {entry.entry_id}: {e}")

        logger.info(f"Synced {synced}/{len(pending)} entries to online log")
        return synced

    def _is_online(self) -> bool:
        """Check if online log is reachable."""
        if self._online is not None:
            return self._online

        try:
            request = urllib.request.Request(
                f"{self.api_url}/api/v1/log",
                method="GET"
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                self._online = response.status == 200
        except:
            self._online = False

        return self._online

    def _submit_online(self, entry: TransparencyEntry) -> TransparencyEntry:
        """Submit entry to online transparency log."""
        request_body = {
            "kind": entry.entry_type.value,
            "apiVersion": "0.0.1",
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": entry.body_hash
                    },
                    "content": base64.b64encode(
                        json.dumps(entry.body).encode()
                    ).decode()
                }
            }
        }

        request = urllib.request.Request(
            f"{self.api_url}/api/v1/log/entries",
            data=json.dumps(request_body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode())

        # Parse response
        # Rekor returns: {"uuid": {...entry...}}
        for log_entry_id, log_entry in result.items():
            entry.entry_id = log_entry_id

            # Extract verification data
            verification = log_entry.get("verification", {})

            if "signedEntryTimestamp" in verification:
                entry.sct = SignedTimestamp(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    signature=verification["signedEntryTimestamp"],
                    log_id=self.api_url
                )

            if "inclusionProof" in verification:
                proof = verification["inclusionProof"]
                entry.inclusion_proof = InclusionProof(
                    log_index=proof.get("logIndex", 0),
                    root_hash=proof.get("rootHash", ""),
                    tree_size=proof.get("treeSize", 0),
                    hashes=proof.get("hashes", [])
                )

            entry.submitted_at = datetime.utcnow().isoformat() + "Z"
            entry.verified = True

            break

        logger.info(f"Submitted entry {entry.entry_id} to transparency log")
        return entry

    def _verify_online(self, entry: TransparencyEntry) -> Tuple[bool, Optional[str]]:
        """Verify entry against online log."""
        try:
            request = urllib.request.Request(
                f"{self.api_url}/api/v1/log/entries/{entry.entry_id}",
                method="GET"
            )

            with urllib.request.urlopen(request, timeout=10) as response:
                result = json.loads(response.read().decode())

            # Check entry exists and matches
            for _, log_entry in result.items():
                body = log_entry.get("body", "")
                decoded = base64.b64decode(body).decode()
                entry_data = json.loads(decoded)

                # Verify hash matches
                if "spec" in entry_data:
                    stored_hash = entry_data["spec"].get("data", {}).get("hash", {}).get("value", "")
                    if stored_hash == entry.body_hash:
                        return True, None

            return False, "Entry not found or hash mismatch"

        except Exception as e:
            return False, str(e)

    def _fetch_proof_online(self, entry_id: str) -> Optional[InclusionProof]:
        """Fetch inclusion proof from online log."""
        try:
            request = urllib.request.Request(
                f"{self.api_url}/api/v1/log/entries/{entry_id}",
                method="GET"
            )

            with urllib.request.urlopen(request, timeout=10) as response:
                result = json.loads(response.read().decode())

            for _, log_entry in result.items():
                verification = log_entry.get("verification", {})
                if "inclusionProof" in verification:
                    proof = verification["inclusionProof"]
                    return InclusionProof(
                        log_index=proof.get("logIndex", 0),
                        root_hash=proof.get("rootHash", ""),
                        tree_size=proof.get("treeSize", 0),
                        hashes=proof.get("hashes", [])
                    )

            return None

        except:
            return None


class TransparencyLogger:
    """
    High-level interface for logging Guard decisions to transparency log.
    """

    def __init__(self, client: Optional[RekorClient] = None):
        self.client = client or RekorClient()

    def log_decision(
        self,
        car: Dict[str, Any],
        decision: str,
        permit_id: Optional[str] = None,
        reason: str = ""
    ) -> TransparencyEntry:
        """Log a Guard decision."""
        body = {
            "type": "decision",
            "car_hash": car.get("car_hash", ""),
            "tool": car.get("tool", ""),
            "operation": car.get("operation", ""),
            "decision": decision,
            "permit_id": permit_id,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        return self.client.submit_entry(EntryType.DECISION, body)

    def log_policy_change(
        self,
        policy_hash: str,
        change_type: str,
        changed_by: str,
        description: str = ""
    ) -> TransparencyEntry:
        """Log a policy change."""
        body = {
            "type": "policy_change",
            "policy_hash": policy_hash,
            "change_type": change_type,
            "changed_by": changed_by,
            "description": description,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        return self.client.submit_entry(EntryType.POLICY_CHANGE, body)

    def log_permit(
        self,
        permit_id: str,
        car_hash: str,
        caveats: Dict[str, Any],
        expires_at: str
    ) -> TransparencyEntry:
        """Log a permit issuance."""
        body = {
            "type": "permit",
            "permit_id": permit_id,
            "car_hash": car_hash,
            "caveats_hash": hashlib.sha256(
                json.dumps(caveats, sort_keys=True).encode()
            ).hexdigest(),
            "expires_at": expires_at,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        return self.client.submit_entry(EntryType.PERMIT, body)

    def verify_decision(self, entry: TransparencyEntry) -> bool:
        """Verify a decision entry."""
        valid, _ = self.client.verify_entry(entry)
        return valid


# Singleton instances
_rekor_client: Optional[RekorClient] = None
_transparency_logger: Optional[TransparencyLogger] = None


def get_rekor_client() -> RekorClient:
    """Get singleton Rekor client."""
    global _rekor_client
    if _rekor_client is None:
        _rekor_client = RekorClient()
    return _rekor_client


def get_transparency_logger() -> TransparencyLogger:
    """Get singleton transparency logger."""
    global _transparency_logger
    if _transparency_logger is None:
        _transparency_logger = TransparencyLogger(get_rekor_client())
    return _transparency_logger
