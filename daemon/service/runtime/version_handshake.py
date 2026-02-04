"""
Version Handshake and Compatibility System
==========================================

Implements version negotiation between plugin and daemon.

From guard-plan-v1.md:
- Compatibility matrix between plugin and daemon versions
- /v1/handshake endpoint for version negotiation
- LOCKED mode when versions are incompatible
- Minimum supported version tracking
- Deprecation warnings

Usage:
    from service.runtime.version_handshake import (
        VersionHandshake,
        get_version_handshake,
        CompatibilityResult
    )

    handshake = get_version_handshake()

    # Check compatibility
    result = handshake.check_compatibility(
        plugin_version="1.2.0",
        daemon_version="1.1.0"
    )

    if result.is_compatible:
        print(f"Compatible! Features: {result.available_features}")
    else:
        print(f"Incompatible: {result.reason}")
"""

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class CompatibilityLevel(Enum):
    """Compatibility level between components."""

    FULL = "full"  # All features available
    PARTIAL = "partial"  # Some features unavailable
    DEPRECATED = "deprecated"  # Works but deprecated
    INCOMPATIBLE = "incompatible"  # Cannot work together
    LOCKED = "locked"  # Explicitly locked out


@dataclass
class SemanticVersion:
    """Parsed semantic version."""

    major: int
    minor: int
    patch: int
    prerelease: str = ""
    build: str = ""

    @classmethod
    def parse(cls, version_string: str) -> "SemanticVersion":
        """Parse a version string into a SemanticVersion."""
        # Remove leading 'v' if present
        version_string = version_string.lstrip("v")

        # Pattern: MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
        pattern = r"^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.-]+))?(?:\+([a-zA-Z0-9.-]+))?$"
        match = re.match(pattern, version_string)

        if not match:
            # Fallback: try simple MAJOR.MINOR or MAJOR
            parts = version_string.split(".")
            try:
                major = int(parts[0]) if len(parts) > 0 else 0
                minor = int(parts[1]) if len(parts) > 1 else 0
                patch = (
                    int(parts[2].split("-")[0].split("+")[0]) if len(parts) > 2 else 0
                )
                return cls(major=major, minor=minor, patch=patch)
            except (ValueError, IndexError):
                raise ValueError(f"Invalid version string: {version_string}")

        return cls(
            major=int(match.group(1)),
            minor=int(match.group(2)),
            patch=int(match.group(3)),
            prerelease=match.group(4) or "",
            build=match.group(5) or "",
        )

    def __str__(self) -> str:
        version = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            version += f"-{self.prerelease}"
        if self.build:
            version += f"+{self.build}"
        return version

    def __lt__(self, other: "SemanticVersion") -> bool:
        if (self.major, self.minor, self.patch) != (
            other.major,
            other.minor,
            other.patch,
        ):
            return (self.major, self.minor, self.patch) < (
                other.major,
                other.minor,
                other.patch,
            )
        # Prerelease versions are lower than release versions
        if self.prerelease and not other.prerelease:
            return True
        if not self.prerelease and other.prerelease:
            return False
        return self.prerelease < other.prerelease

    def __le__(self, other: "SemanticVersion") -> bool:
        return self == other or self < other

    def __gt__(self, other: "SemanticVersion") -> bool:
        return other < self

    def __ge__(self, other: "SemanticVersion") -> bool:
        return self == other or self > other

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return False
        return (
            self.major == other.major
            and self.minor == other.minor
            and self.patch == other.patch
            and self.prerelease == other.prerelease
        )

    def __hash__(self) -> int:
        return hash((self.major, self.minor, self.patch, self.prerelease))

    def is_compatible_with(self, other: "SemanticVersion") -> bool:
        """Check if this version is API-compatible with another (same major)."""
        return self.major == other.major

    def to_dict(self) -> Dict[str, Any]:
        return {
            "major": self.major,
            "minor": self.minor,
            "patch": self.patch,
            "prerelease": self.prerelease,
            "build": self.build,
            "string": str(self),
        }


@dataclass
class CompatibilityResult:
    """Result of a compatibility check."""

    level: CompatibilityLevel
    plugin_version: SemanticVersion
    daemon_version: SemanticVersion
    is_compatible: bool
    reason: str = ""
    available_features: Set[str] = field(default_factory=set)
    unavailable_features: Set[str] = field(default_factory=set)
    deprecation_warnings: List[str] = field(default_factory=list)
    recommended_action: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "plugin_version": str(self.plugin_version),
            "daemon_version": str(self.daemon_version),
            "is_compatible": self.is_compatible,
            "reason": self.reason,
            "available_features": list(self.available_features),
            "unavailable_features": list(self.unavailable_features),
            "deprecation_warnings": self.deprecation_warnings,
            "recommended_action": self.recommended_action,
        }


@dataclass
class HandshakeRecord:
    """Record of a handshake attempt."""

    plugin_version: str
    daemon_version: str
    client_id: str
    result: CompatibilityLevel
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin_version": self.plugin_version,
            "daemon_version": self.daemon_version,
            "client_id": self.client_id,
            "result": self.result.value,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


class VersionHandshake:
    """
    Manages version compatibility between plugin and daemon.

    Features:
    - Semantic version parsing
    - Compatibility matrix
    - Feature availability tracking
    - Deprecation warnings
    - Handshake history
    """

    # Current daemon version
    DAEMON_VERSION = "1.0.0"

    # Minimum supported plugin versions
    MIN_PLUGIN_VERSION = "0.9.0"

    # Features introduced in specific versions
    FEATURE_VERSIONS: Dict[str, str] = {
        "basic_interception": "0.9.0",
        "heartbeat": "0.9.0",
        "approval_flow": "0.9.0",
        "policy_modes": "0.9.5",
        "state_tracking": "1.0.0",
        "merkle_audit": "1.0.0",
        "behavioral_anomaly": "1.0.0",
        "adversarial_detection": "1.0.0",
        "sequence_model": "1.1.0",
        "contextual_allowlist": "1.1.0",
        "shadow_mode": "1.2.0",
        "training_data": "1.2.0",
    }

    # Deprecated features and when they'll be removed
    DEPRECATED_FEATURES: Dict[str, Tuple[str, str]] = {
        # "feature_name": ("deprecated_in", "removed_in")
        "legacy_api_v0": ("0.9.0", "2.0.0"),
    }

    # Locked version combinations (plugin -> daemon -> reason)
    LOCKED_COMBINATIONS: List[Tuple[str, str, str]] = [
        # ("plugin_version", "daemon_version", "reason")
        ("0.8.0", "*", "Plugin 0.8.0 has critical security vulnerabilities"),
        ("*", "0.8.0", "Daemon 0.8.0 has critical security vulnerabilities"),
    ]

    def __init__(
        self,
        daemon_version: Optional[str] = None,
        min_plugin_version: Optional[str] = None,
    ):
        """
        Initialize version handshake.

        Args:
            daemon_version: Override daemon version (default: DAEMON_VERSION)
            min_plugin_version: Override minimum plugin version
        """
        self._daemon_version = SemanticVersion.parse(
            daemon_version or self.DAEMON_VERSION
        )
        self._min_plugin_version = SemanticVersion.parse(
            min_plugin_version or self.MIN_PLUGIN_VERSION
        )

        self._handshake_history: List[HandshakeRecord] = []
        self._max_history = 100
        self._start_time = time.time()

        # Statistics
        self._total_handshakes = 0
        self._successful_handshakes = 0
        self._failed_handshakes = 0

        logger.info(
            f"VersionHandshake initialized: daemon={self._daemon_version}, "
            f"min_plugin={self._min_plugin_version}"
        )

    def _is_locked(self, plugin_ver: str, daemon_ver: str) -> Optional[str]:
        """Check if a version combination is locked. Returns reason if locked."""
        for p_ver, d_ver, reason in self.LOCKED_COMBINATIONS:
            # Check plugin match
            p_match = p_ver == "*" or p_ver == plugin_ver
            # Check daemon match
            d_match = d_ver == "*" or d_ver == daemon_ver

            if p_match and d_match:
                return reason
        return None

    def _get_available_features(self, plugin_version: SemanticVersion) -> Set[str]:
        """Get features available for a given plugin version."""
        available = set()
        for feature, min_version_str in self.FEATURE_VERSIONS.items():
            min_version = SemanticVersion.parse(min_version_str)
            if plugin_version >= min_version:
                available.add(feature)
        return available

    def _get_deprecation_warnings(self, plugin_version: SemanticVersion) -> List[str]:
        """Get deprecation warnings for features used by this version."""
        warnings = []
        for feature, (deprecated_in, removed_in) in self.DEPRECATED_FEATURES.items():
            dep_ver = SemanticVersion.parse(deprecated_in)
            rem_ver = SemanticVersion.parse(removed_in)

            if plugin_version >= dep_ver and plugin_version < rem_ver:
                warnings.append(
                    f"Feature '{feature}' is deprecated since {deprecated_in} "
                    f"and will be removed in {removed_in}"
                )
        return warnings

    def check_compatibility(
        self,
        plugin_version: str,
        daemon_version: Optional[str] = None,
    ) -> CompatibilityResult:
        """
        Check compatibility between plugin and daemon versions.

        Args:
            plugin_version: Plugin version string
            daemon_version: Daemon version (default: current daemon version)

        Returns:
            CompatibilityResult with full compatibility info
        """
        plugin_ver = SemanticVersion.parse(plugin_version)
        daemon_ver = (
            SemanticVersion.parse(daemon_version)
            if daemon_version
            else self._daemon_version
        )

        # Check for locked combinations
        lock_reason = self._is_locked(str(plugin_ver), str(daemon_ver))
        if lock_reason:
            return CompatibilityResult(
                level=CompatibilityLevel.LOCKED,
                plugin_version=plugin_ver,
                daemon_version=daemon_ver,
                is_compatible=False,
                reason=lock_reason,
                recommended_action="Update to a non-locked version immediately",
            )

        # Check minimum version
        if plugin_ver < self._min_plugin_version:
            return CompatibilityResult(
                level=CompatibilityLevel.INCOMPATIBLE,
                plugin_version=plugin_ver,
                daemon_version=daemon_ver,
                is_compatible=False,
                reason=f"Plugin version {plugin_ver} is below minimum {self._min_plugin_version}",
                recommended_action=f"Update plugin to {self._min_plugin_version} or higher",
            )

        # Check major version compatibility
        if not plugin_ver.is_compatible_with(daemon_ver):
            return CompatibilityResult(
                level=CompatibilityLevel.INCOMPATIBLE,
                plugin_version=plugin_ver,
                daemon_version=daemon_ver,
                is_compatible=False,
                reason=f"Major version mismatch: plugin {plugin_ver.major} vs daemon {daemon_ver.major}",
                recommended_action="Upgrade both plugin and daemon to matching major versions",
            )

        # Get available features
        available_features = self._get_available_features(plugin_ver)
        all_features = set(self.FEATURE_VERSIONS.keys())
        unavailable_features = all_features - available_features

        # Get deprecation warnings
        deprecation_warnings = self._get_deprecation_warnings(plugin_ver)

        # Determine level
        if unavailable_features:
            level = CompatibilityLevel.PARTIAL
            reason = f"{len(unavailable_features)} features unavailable"
            action = (
                f"Update plugin to enable: {', '.join(list(unavailable_features)[:3])}"
            )
        elif deprecation_warnings:
            level = CompatibilityLevel.DEPRECATED
            reason = "Using deprecated features"
            action = "Update plugin to avoid deprecated features"
        else:
            level = CompatibilityLevel.FULL
            reason = "Full compatibility"
            action = "No action needed"

        return CompatibilityResult(
            level=level,
            plugin_version=plugin_ver,
            daemon_version=daemon_ver,
            is_compatible=True,
            reason=reason,
            available_features=available_features,
            unavailable_features=unavailable_features,
            deprecation_warnings=deprecation_warnings,
            recommended_action=action,
        )

    def perform_handshake(
        self,
        plugin_version: str,
        client_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[CompatibilityResult, HandshakeRecord]:
        """
        Perform a version handshake with a client.

        Args:
            plugin_version: Plugin version
            client_id: Client identifier
            metadata: Additional handshake metadata

        Returns:
            Tuple of (CompatibilityResult, HandshakeRecord)
        """
        self._total_handshakes += 1

        result = self.check_compatibility(plugin_version)

        record = HandshakeRecord(
            plugin_version=plugin_version,
            daemon_version=str(self._daemon_version),
            client_id=client_id,
            result=result.level,
            metadata=metadata or {},
        )

        # Update history
        self._handshake_history.append(record)
        if len(self._handshake_history) > self._max_history:
            self._handshake_history = self._handshake_history[-self._max_history :]

        # Update stats
        if result.is_compatible:
            self._successful_handshakes += 1
        else:
            self._failed_handshakes += 1

        logger.info(
            f"Handshake with {client_id}: plugin={plugin_version}, "
            f"result={result.level.value}"
        )

        return result, record

    def get_daemon_version(self) -> SemanticVersion:
        """Get current daemon version."""
        return self._daemon_version

    def get_min_plugin_version(self) -> SemanticVersion:
        """Get minimum supported plugin version."""
        return self._min_plugin_version

    def get_handshake_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent handshake history."""
        recent = self._handshake_history[-limit:]
        return [r.to_dict() for r in reversed(recent)]

    def get_statistics(self) -> Dict[str, Any]:
        """Get handshake statistics."""
        success_rate = (
            self._successful_handshakes / self._total_handshakes
            if self._total_handshakes > 0
            else 0.0
        )

        return {
            "daemon_version": str(self._daemon_version),
            "min_plugin_version": str(self._min_plugin_version),
            "total_handshakes": self._total_handshakes,
            "successful_handshakes": self._successful_handshakes,
            "failed_handshakes": self._failed_handshakes,
            "success_rate": round(success_rate, 4),
            "all_features": list(self.FEATURE_VERSIONS.keys()),
            "uptime_seconds": time.time() - self._start_time,
        }


# Global singleton instance
_version_handshake: Optional[VersionHandshake] = None


def get_version_handshake() -> VersionHandshake:
    """Get or create the global version handshake instance."""
    global _version_handshake
    if _version_handshake is None:
        _version_handshake = VersionHandshake()
    return _version_handshake


def reset_version_handshake(
    daemon_version: Optional[str] = None,
    min_plugin_version: Optional[str] = None,
) -> VersionHandshake:
    """Reset the global version handshake instance."""
    global _version_handshake
    _version_handshake = VersionHandshake(
        daemon_version=daemon_version,
        min_plugin_version=min_plugin_version,
    )
    return _version_handshake


# FastAPI integration
def create_handshake_routes():
    """Create FastAPI routes for version handshake."""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel

    router = APIRouter(prefix="/api/v1/guard", tags=["handshake"])

    class HandshakeRequest(BaseModel):
        plugin_version: str
        client_id: str
        metadata: Optional[Dict[str, Any]] = None

    class CompatibilityCheckRequest(BaseModel):
        plugin_version: str
        daemon_version: Optional[str] = None

    @router.post("/handshake")
    async def perform_handshake(request: HandshakeRequest):
        """Perform version handshake with a client."""
        handshake = get_version_handshake()

        try:
            result, record = handshake.perform_handshake(
                plugin_version=request.plugin_version,
                client_id=request.client_id,
                metadata=request.metadata,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        return {
            "status": "ok" if result.is_compatible else "incompatible",
            "compatibility": result.to_dict(),
            "handshake": record.to_dict(),
        }

    @router.post("/handshake/check")
    async def check_compatibility(request: CompatibilityCheckRequest):
        """Check version compatibility without recording."""
        handshake = get_version_handshake()

        try:
            result = handshake.check_compatibility(
                plugin_version=request.plugin_version,
                daemon_version=request.daemon_version,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        return result.to_dict()

    @router.get("/handshake/version")
    async def get_version_info():
        """Get daemon version information."""
        handshake = get_version_handshake()
        return {
            "daemon_version": handshake.get_daemon_version().to_dict(),
            "min_plugin_version": handshake.get_min_plugin_version().to_dict(),
            "all_features": list(VersionHandshake.FEATURE_VERSIONS.keys()),
            "deprecated_features": list(VersionHandshake.DEPRECATED_FEATURES.keys()),
        }

    @router.get("/handshake/history")
    async def get_handshake_history(limit: int = 10):
        """Get recent handshake history."""
        handshake = get_version_handshake()
        return {
            "history": handshake.get_handshake_history(limit),
            "count": len(handshake.get_handshake_history(limit)),
        }

    @router.get("/handshake/stats")
    async def get_handshake_stats():
        """Get handshake statistics."""
        handshake = get_version_handshake()
        return handshake.get_statistics()

    return router
