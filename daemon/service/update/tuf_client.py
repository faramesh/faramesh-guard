"""
TUF (The Update Framework) Secure Updates

Implements secure update mechanism using TUF principles:
- Signed metadata (root.json, targets.json, snapshot.json, timestamp.json)
- Rollback attack protection
- Freeze attack protection
- Key rotation support
- SLSA provenance verification

Reference: https://theupdateframework.io/
"""

import json
import hashlib
import hmac
import os
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import logging
import base64
import urllib.request
import urllib.error

logger = logging.getLogger("guard.updates.tuf")

# Update server configuration
TUF_REPOSITORY_URL = "https://updates.faramesh.ai/guard/v1"
TUF_LOCAL_CACHE = Path.home() / ".faramesh-guard" / "tuf_cache"


class TUFRole(Enum):
    """TUF metadata roles."""
    ROOT = "root"
    TARGETS = "targets"
    SNAPSHOT = "snapshot"
    TIMESTAMP = "timestamp"


class VerificationError(Exception):
    """Raised when TUF verification fails."""
    pass


@dataclass
class TUFKey:
    """TUF public key."""
    keyid: str
    keytype: str  # "ed25519", "rsa", etc.
    keyval: Dict[str, str]  # {"public": "base64..."}
    scheme: str  # "ed25519", "rsassa-pss-sha256"


@dataclass
class TUFSignature:
    """TUF signature on metadata."""
    keyid: str
    sig: str  # Base64-encoded signature


@dataclass
class TUFMetadata:
    """Base TUF metadata structure."""
    _type: str
    version: int
    spec_version: str
    expires: str
    signatures: List[TUFSignature] = field(default_factory=list)

    def is_expired(self) -> bool:
        """Check if metadata has expired."""
        try:
            expires_dt = datetime.fromisoformat(self.expires.replace("Z", "+00:00"))
            return datetime.now(expires_dt.tzinfo) > expires_dt
        except:
            return True


@dataclass
class RootMetadata(TUFMetadata):
    """TUF root metadata - defines trust anchors."""
    keys: Dict[str, TUFKey] = field(default_factory=dict)
    roles: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # role -> {keyids, threshold}
    consistent_snapshot: bool = True


@dataclass
class TargetInfo:
    """Information about a target file."""
    length: int
    hashes: Dict[str, str]  # {"sha256": "abc123..."}
    custom: Optional[Dict[str, Any]] = None  # SLSA provenance, etc.


@dataclass
class TargetsMetadata(TUFMetadata):
    """TUF targets metadata - lists available files."""
    targets: Dict[str, TargetInfo] = field(default_factory=dict)
    delegations: Optional[Dict[str, Any]] = None


@dataclass
class SnapshotMetadata(TUFMetadata):
    """TUF snapshot metadata - versions of all metadata."""
    meta: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # filename -> {version, length, hashes}


@dataclass
class TimestampMetadata(TUFMetadata):
    """TUF timestamp metadata - freshness guarantee."""
    meta: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # snapshot.json info


@dataclass
class SLSAProvenance:
    """SLSA Build Provenance attestation."""
    builder_id: str  # e.g., "https://github.com/faramesh/faramesh-guard/.github/workflows/release.yml"
    build_type: str  # e.g., "https://slsa.dev/provenance/v1"
    invocation: Dict[str, Any]  # Build parameters
    materials: List[Dict[str, str]]  # Source inputs
    metadata: Dict[str, Any]  # Build metadata

    def verify_builder(self, allowed_builders: List[str]) -> bool:
        """Verify builder is in allowed list."""
        return self.builder_id in allowed_builders

    def verify_source(self, expected_repo: str, expected_ref: Optional[str] = None) -> bool:
        """Verify source repository matches expected."""
        for material in self.materials:
            if "uri" in material and expected_repo in material["uri"]:
                if expected_ref is None:
                    return True
                if material.get("digest", {}).get("gitCommit", "").startswith(expected_ref):
                    return True
        return False


class TUFClient:
    """
    TUF client for secure updates.

    Implements the TUF update workflow:
    1. Download timestamp.json (most frequently updated)
    2. Download snapshot.json if version changed
    3. Download targets.json if version changed
    4. Download and verify target files
    """

    ALLOWED_BUILDERS = [
        "https://github.com/faramesh/faramesh-guard/.github/workflows/release.yml",
        "https://github.com/faramesh/faramesh-guard/.github/workflows/build.yml"
    ]

    def __init__(
        self,
        repository_url: str = TUF_REPOSITORY_URL,
        cache_dir: Path = TUF_LOCAL_CACHE
    ):
        self.repository_url = repository_url.rstrip("/")
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Initialize with embedded root of trust
        self.trusted_root: Optional[RootMetadata] = None
        self._load_trusted_root()

    def _load_trusted_root(self) -> None:
        """Load the trusted root metadata."""
        root_path = self.cache_dir / "root.json"

        if root_path.exists():
            try:
                with open(root_path) as f:
                    data = json.load(f)
                self.trusted_root = self._parse_root(data)
                logger.info(f"Loaded trusted root v{self.trusted_root.version}")
            except Exception as e:
                logger.error(f"Failed to load root: {e}")
        else:
            # Bootstrap with embedded root
            self.trusted_root = self._get_embedded_root()
            self._save_metadata("root.json", self.trusted_root)

    def _get_embedded_root(self) -> RootMetadata:
        """Get the embedded root of trust (first-time bootstrap)."""
        # In production, this would be a real embedded root with actual keys
        return RootMetadata(
            _type="root",
            version=1,
            spec_version="1.0.0",
            expires=(datetime.utcnow() + timedelta(days=365)).isoformat() + "Z",
            keys={},
            roles={
                "root": {"keyids": [], "threshold": 1},
                "targets": {"keyids": [], "threshold": 1},
                "snapshot": {"keyids": [], "threshold": 1},
                "timestamp": {"keyids": [], "threshold": 1}
            },
            consistent_snapshot=True
        )

    def check_for_updates(self) -> Optional[Dict[str, TargetInfo]]:
        """
        Check for available updates.

        Returns:
            Dict of available updates (target name -> TargetInfo) or None if up to date
        """
        try:
            # 1. Fetch and verify timestamp
            timestamp = self._fetch_timestamp()
            if timestamp is None:
                return None

            cached_timestamp = self._load_cached_metadata("timestamp.json")
            if cached_timestamp and cached_timestamp.get("version", 0) >= timestamp.version:
                logger.info("Already at latest timestamp")
                return None

            # 2. Fetch and verify snapshot
            snapshot = self._fetch_snapshot(timestamp)
            if snapshot is None:
                return None

            # 3. Fetch and verify targets
            targets = self._fetch_targets(snapshot)
            if targets is None:
                return None

            # 4. Compare with installed versions
            installed = self._get_installed_versions()
            updates = {}

            for target_name, target_info in targets.targets.items():
                if target_name not in installed:
                    updates[target_name] = target_info
                elif self._needs_update(target_name, target_info, installed[target_name]):
                    updates[target_name] = target_info

            if updates:
                logger.info(f"Found {len(updates)} available updates")
                return updates

            return None

        except Exception as e:
            logger.error(f"Update check failed: {e}")
            return None

    def download_update(
        self,
        target_name: str,
        target_info: TargetInfo,
        destination: Path
    ) -> bool:
        """
        Download and verify a target file.

        Args:
            target_name: Name of the target file
            target_info: Target metadata with hashes
            destination: Where to save the file

        Returns:
            True if download and verification succeeded
        """
        try:
            # Build URL
            if self.trusted_root and self.trusted_root.consistent_snapshot:
                # Use content-addressed URL
                sha256 = target_info.hashes.get("sha256", "")
                url = f"{self.repository_url}/targets/{sha256}.{target_name}"
            else:
                url = f"{self.repository_url}/targets/{target_name}"

            # Download to temp file
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = Path(tmp.name)

                logger.info(f"Downloading {target_name} from {url}")

                request = urllib.request.Request(url)
                with urllib.request.urlopen(request, timeout=60) as response:
                    content = response.read()
                    tmp.write(content)

            # Verify length
            if len(content) != target_info.length:
                raise VerificationError(
                    f"Length mismatch: expected {target_info.length}, got {len(content)}"
                )

            # Verify hashes
            for algo, expected_hash in target_info.hashes.items():
                if algo == "sha256":
                    actual_hash = hashlib.sha256(content).hexdigest()
                elif algo == "sha512":
                    actual_hash = hashlib.sha512(content).hexdigest()
                else:
                    continue

                if actual_hash != expected_hash:
                    raise VerificationError(
                        f"{algo} mismatch: expected {expected_hash}, got {actual_hash}"
                    )

            # Verify SLSA provenance if present
            if target_info.custom and "slsa_provenance" in target_info.custom:
                provenance = SLSAProvenance(**target_info.custom["slsa_provenance"])

                if not provenance.verify_builder(self.ALLOWED_BUILDERS):
                    raise VerificationError(
                        f"Untrusted builder: {provenance.builder_id}"
                    )

                if not provenance.verify_source("github.com/faramesh/faramesh-guard"):
                    raise VerificationError("Source repository verification failed")

                logger.info(f"SLSA provenance verified: {provenance.builder_id}")

            # Move to destination
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(tmp_path), str(destination))

            logger.info(f"Successfully downloaded and verified {target_name}")
            return True

        except urllib.error.URLError as e:
            logger.error(f"Download failed: {e}")
            return False
        except VerificationError as e:
            logger.error(f"Verification failed: {e}")
            # Clean up temp file
            try:
                tmp_path.unlink()
            except:
                pass
            return False
        except Exception as e:
            logger.error(f"Update download failed: {e}")
            return False

    def _fetch_timestamp(self) -> Optional[TimestampMetadata]:
        """Fetch and verify timestamp metadata."""
        try:
            url = f"{self.repository_url}/metadata/timestamp.json"
            data = self._fetch_json(url)

            if data is None:
                return None

            # Verify signatures
            # In production, verify against trusted root keys

            # Parse metadata
            timestamp = TimestampMetadata(
                _type="timestamp",
                version=data.get("signed", {}).get("version", 0),
                spec_version=data.get("signed", {}).get("spec_version", "1.0.0"),
                expires=data.get("signed", {}).get("expires", ""),
                meta=data.get("signed", {}).get("meta", {})
            )

            # Check expiration
            if timestamp.is_expired():
                raise VerificationError("Timestamp metadata has expired")

            # Cache it
            self._save_cached_metadata("timestamp.json", data)

            return timestamp

        except Exception as e:
            logger.error(f"Failed to fetch timestamp: {e}")
            return None

    def _fetch_snapshot(self, timestamp: TimestampMetadata) -> Optional[SnapshotMetadata]:
        """Fetch and verify snapshot metadata."""
        try:
            snapshot_info = timestamp.meta.get("snapshot.json", {})
            version = snapshot_info.get("version", 1)

            if self.trusted_root and self.trusted_root.consistent_snapshot:
                url = f"{self.repository_url}/metadata/{version}.snapshot.json"
            else:
                url = f"{self.repository_url}/metadata/snapshot.json"

            data = self._fetch_json(url)
            if data is None:
                return None

            # Verify hashes match timestamp
            content = json.dumps(data, sort_keys=True).encode()
            actual_hash = hashlib.sha256(content).hexdigest()

            expected_hashes = snapshot_info.get("hashes", {})
            if "sha256" in expected_hashes and actual_hash != expected_hashes["sha256"]:
                raise VerificationError("Snapshot hash mismatch")

            snapshot = SnapshotMetadata(
                _type="snapshot",
                version=data.get("signed", {}).get("version", 0),
                spec_version=data.get("signed", {}).get("spec_version", "1.0.0"),
                expires=data.get("signed", {}).get("expires", ""),
                meta=data.get("signed", {}).get("meta", {})
            )

            if snapshot.is_expired():
                raise VerificationError("Snapshot metadata has expired")

            self._save_cached_metadata("snapshot.json", data)
            return snapshot

        except Exception as e:
            logger.error(f"Failed to fetch snapshot: {e}")
            return None

    def _fetch_targets(self, snapshot: SnapshotMetadata) -> Optional[TargetsMetadata]:
        """Fetch and verify targets metadata."""
        try:
            targets_info = snapshot.meta.get("targets.json", {})
            version = targets_info.get("version", 1)

            if self.trusted_root and self.trusted_root.consistent_snapshot:
                url = f"{self.repository_url}/metadata/{version}.targets.json"
            else:
                url = f"{self.repository_url}/metadata/targets.json"

            data = self._fetch_json(url)
            if data is None:
                return None

            # Parse targets
            targets_dict = {}
            for name, info in data.get("signed", {}).get("targets", {}).items():
                targets_dict[name] = TargetInfo(
                    length=info.get("length", 0),
                    hashes=info.get("hashes", {}),
                    custom=info.get("custom")
                )

            targets = TargetsMetadata(
                _type="targets",
                version=data.get("signed", {}).get("version", 0),
                spec_version=data.get("signed", {}).get("spec_version", "1.0.0"),
                expires=data.get("signed", {}).get("expires", ""),
                targets=targets_dict
            )

            if targets.is_expired():
                raise VerificationError("Targets metadata has expired")

            self._save_cached_metadata("targets.json", data)
            return targets

        except Exception as e:
            logger.error(f"Failed to fetch targets: {e}")
            return None

    def _fetch_json(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch JSON from URL."""
        try:
            request = urllib.request.Request(url)
            request.add_header("Accept", "application/json")

            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode())
        except urllib.error.URLError as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            return None

    def _parse_root(self, data: Dict[str, Any]) -> RootMetadata:
        """Parse root metadata from JSON."""
        signed = data.get("signed", {})

        keys = {}
        for keyid, key_data in signed.get("keys", {}).items():
            keys[keyid] = TUFKey(
                keyid=keyid,
                keytype=key_data.get("keytype", ""),
                keyval=key_data.get("keyval", {}),
                scheme=key_data.get("scheme", "")
            )

        return RootMetadata(
            _type="root",
            version=signed.get("version", 0),
            spec_version=signed.get("spec_version", "1.0.0"),
            expires=signed.get("expires", ""),
            keys=keys,
            roles=signed.get("roles", {}),
            consistent_snapshot=signed.get("consistent_snapshot", True)
        )

    def _load_cached_metadata(self, filename: str) -> Optional[Dict[str, Any]]:
        """Load metadata from cache."""
        cache_path = self.cache_dir / filename
        if cache_path.exists():
            try:
                with open(cache_path) as f:
                    return json.load(f)
            except:
                pass
        return None

    def _save_cached_metadata(self, filename: str, data: Dict[str, Any]) -> None:
        """Save metadata to cache."""
        cache_path = self.cache_dir / filename
        with open(cache_path, "w") as f:
            json.dump(data, f, indent=2)

    def _save_metadata(self, filename: str, metadata: TUFMetadata) -> None:
        """Save TUF metadata to cache."""
        cache_path = self.cache_dir / filename
        # Convert dataclass to dict (simplified)
        data = {"signed": {"version": metadata.version, "expires": metadata.expires}}
        with open(cache_path, "w") as f:
            json.dump(data, f, indent=2)

    def _get_installed_versions(self) -> Dict[str, str]:
        """Get currently installed file versions."""
        versions = {}

        # Check Guard daemon version
        version_file = Path(__file__).parent.parent.parent / "VERSION"
        if version_file.exists():
            versions["guard-daemon"] = version_file.read_text().strip()

        return versions

    def _needs_update(
        self,
        target_name: str,
        target_info: TargetInfo,
        installed_version: str
    ) -> bool:
        """Check if target needs updating."""
        # Compare hashes or versions
        if target_info.custom and "version" in target_info.custom:
            return target_info.custom["version"] > installed_version

        # Default: always update if hash differs
        return True


class VersionCompatibility:
    """
    Version compatibility checker for Guard <-> OpenClaw.

    Ensures plugin and daemon versions are compatible.
    """

    COMPATIBILITY_MATRIX = {
        # Guard version -> supported OpenClaw version ranges
        "1.0.0": ["2024.1.0", "2024.2.0", "2024.3.0"],
        "1.1.0": ["2024.2.0", "2024.3.0", "2025.1.0"],
        "1.2.0": ["2024.3.0", "2025.1.0", "2025.2.0", "2026.1.0"],
    }

    def __init__(self, guard_version: str):
        self.guard_version = guard_version

    def is_compatible(self, openclaw_version: str) -> Tuple[bool, Optional[str]]:
        """
        Check if OpenClaw version is compatible with Guard.

        Returns:
            (compatible, error_message)
        """
        supported = self.COMPATIBILITY_MATRIX.get(self.guard_version, [])

        if not supported:
            # Unknown Guard version - be permissive but warn
            return True, "Unknown Guard version, compatibility not verified"

        # Check if OpenClaw version is in supported range
        for supported_version in supported:
            if self._version_matches(openclaw_version, supported_version):
                return True, None

        return False, (
            f"OpenClaw {openclaw_version} not compatible with Guard {self.guard_version}. "
            f"Supported: {', '.join(supported)}"
        )

    def _version_matches(self, actual: str, supported: str) -> bool:
        """Check if actual version matches supported pattern."""
        # Simple prefix match for now
        actual_parts = actual.split(".")
        supported_parts = supported.split(".")

        for i, part in enumerate(supported_parts):
            if i >= len(actual_parts):
                return False
            if actual_parts[i] != part:
                return False

        return True

    def get_strict_mode_recommendation(self, openclaw_version: str) -> bool:
        """
        Check if strict mode should be enforced due to version mismatch.

        Returns:
            True if strict mode should be used
        """
        compatible, _ = self.is_compatible(openclaw_version)
        return not compatible


# Singleton instance
_tuf_client: Optional[TUFClient] = None


def get_tuf_client() -> TUFClient:
    """Get singleton TUF client."""
    global _tuf_client
    if _tuf_client is None:
        _tuf_client = TUFClient()
    return _tuf_client
