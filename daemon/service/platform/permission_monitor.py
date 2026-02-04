"""
Permission Drift Detection Monitor
===================================

Monitors filesystem and process permissions for unexpected changes.

From guard-plan-v1.md:
- Detect permission drift on critical files
- Monitor binary integrity
- Alert on unauthorized permission changes
- Track permission history

Usage:
    from service.platform.permission_monitor import (
        PermissionMonitor,
        get_permission_monitor
    )

    monitor = get_permission_monitor()
    await monitor.start()

    # Check for drift
    drifts = await monitor.check_all()
    for drift in drifts:
        print(f"Permission drift: {drift.path} - {drift.description}")
"""

import asyncio
import grp
import hashlib
import logging
import os
import pwd
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class PermissionType(Enum):
    """Types of permissions being monitored."""

    FILE_MODE = "file_mode"  # Unix file mode (rwxrwxrwx)
    OWNER = "owner"  # File owner
    GROUP = "group"  # File group
    SUID_SGID = "suid_sgid"  # SetUID/SetGID bits
    IMMUTABLE = "immutable"  # Immutable flag
    ACL = "acl"  # Access Control Lists
    SELINUX = "selinux"  # SELinux context


class DriftSeverity(Enum):
    """Severity level of permission drift."""

    INFO = "info"  # Informational
    WARNING = "warning"  # Potential issue
    CRITICAL = "critical"  # Security concern


@dataclass
class PermissionState:
    """Current permission state of a file/directory."""

    path: str
    exists: bool = True
    mode: int = 0
    mode_string: str = ""
    owner: str = ""
    owner_uid: int = -1
    group: str = ""
    group_gid: int = -1
    size: int = 0
    mtime: float = 0
    checksum: str = ""
    is_suid: bool = False
    is_sgid: bool = False
    is_sticky: bool = False
    is_symlink: bool = False
    link_target: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "exists": self.exists,
            "mode": oct(self.mode),
            "mode_string": self.mode_string,
            "owner": self.owner,
            "owner_uid": self.owner_uid,
            "group": self.group,
            "group_gid": self.group_gid,
            "size": self.size,
            "mtime": self.mtime,
            "checksum": self.checksum,
            "is_suid": self.is_suid,
            "is_sgid": self.is_sgid,
            "is_sticky": self.is_sticky,
            "is_symlink": self.is_symlink,
            "link_target": self.link_target,
        }


@dataclass
class PermissionDrift:
    """A detected permission drift."""

    path: str
    drift_type: PermissionType
    severity: DriftSeverity
    description: str
    expected_value: str
    actual_value: str
    detected_at: datetime = field(default_factory=datetime.utcnow)
    auto_remediated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "drift_type": self.drift_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "detected_at": self.detected_at.isoformat(),
            "auto_remediated": self.auto_remediated,
            "metadata": self.metadata,
        }


@dataclass
class MonitoredPath:
    """A path being monitored for permission drift."""

    path: str
    expected_mode: Optional[int] = None
    expected_owner: Optional[str] = None
    expected_group: Optional[str] = None
    allow_suid: bool = False
    allow_sgid: bool = False
    track_content: bool = False  # Track file content changes
    auto_remediate: bool = False
    baseline_state: Optional[PermissionState] = None


# Type alias for drift callbacks
DriftCallback = Callable[[PermissionDrift], None]


class PermissionMonitor:
    """
    Monitors permissions on critical files and detects drift.

    Features:
    - Baseline permission capture
    - Periodic drift detection
    - SetUID/SetGID monitoring
    - Content integrity checking
    - Auto-remediation option
    - Drift history
    """

    # Default critical paths to monitor
    DEFAULT_CRITICAL_PATHS = [
        "daemon/main.py",
        "daemon/core/permit.py",
        "daemon/core/car_hash.py",
        "daemon/service/adversarial_detector.py",
        "policies/",
        "config/",
    ]

    def __init__(
        self,
        base_dir: Optional[str] = None,
        check_interval: float = 60.0,  # Check every minute
        max_history: int = 1000,
    ):
        """
        Initialize the permission monitor.

        Args:
            base_dir: Base directory for relative paths
            check_interval: Seconds between automatic checks
            max_history: Maximum drift events to keep
        """
        self._base_dir = Path(base_dir or os.getcwd())
        self._check_interval = check_interval
        self._max_history = max_history

        self._monitored_paths: Dict[str, MonitoredPath] = {}
        self._drift_history: List[PermissionDrift] = []
        self._callbacks: List[DriftCallback] = []
        self._lock = asyncio.Lock()
        self._check_task: Optional[asyncio.Task] = None
        self._running = False
        self._start_time = time.time()

        # Statistics
        self._total_checks = 0
        self._total_drifts = 0
        self._auto_remediations = 0

        logger.info(
            f"PermissionMonitor initialized: base_dir={self._base_dir}, "
            f"interval={check_interval}s"
        )

    def _get_permission_state(self, path: Path) -> PermissionState:
        """Get current permission state of a file/directory."""
        state = PermissionState(path=str(path))

        if not path.exists():
            state.exists = False
            return state

        try:
            stat_info = path.lstat()
            state.mode = stat_info.st_mode
            state.mode_string = stat.filemode(stat_info.st_mode)
            state.owner_uid = stat_info.st_uid
            state.group_gid = stat_info.st_gid
            state.size = stat_info.st_size
            state.mtime = stat_info.st_mtime

            # Get owner/group names
            try:
                state.owner = pwd.getpwuid(stat_info.st_uid).pw_name
            except KeyError:
                state.owner = str(stat_info.st_uid)

            try:
                state.group = grp.getgrgid(stat_info.st_gid).gr_name
            except KeyError:
                state.group = str(stat_info.st_gid)

            # Check special bits
            state.is_suid = bool(stat_info.st_mode & stat.S_ISUID)
            state.is_sgid = bool(stat_info.st_mode & stat.S_ISGID)
            state.is_sticky = bool(stat_info.st_mode & stat.S_ISVTX)

            # Check symlink
            if path.is_symlink():
                state.is_symlink = True
                state.link_target = str(path.readlink())

            # Compute checksum for files
            if path.is_file() and state.size < 10 * 1024 * 1024:  # < 10MB
                sha256 = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        sha256.update(chunk)
                state.checksum = sha256.hexdigest()

        except PermissionError as e:
            logger.warning(f"Permission error reading {path}: {e}")
            state.exists = False
        except OSError as e:
            logger.warning(f"OS error reading {path}: {e}")
            state.exists = False

        return state

    def add_path(
        self,
        path: str,
        expected_mode: Optional[int] = None,
        expected_owner: Optional[str] = None,
        expected_group: Optional[str] = None,
        allow_suid: bool = False,
        allow_sgid: bool = False,
        track_content: bool = False,
        auto_remediate: bool = False,
    ) -> None:
        """
        Add a path to monitor.

        Args:
            path: Path to monitor (relative to base_dir or absolute)
            expected_mode: Expected permission mode (e.g., 0o644)
            expected_owner: Expected owner username
            expected_group: Expected group name
            allow_suid: Allow SetUID bit
            allow_sgid: Allow SetGID bit
            track_content: Track file content changes
            auto_remediate: Automatically fix permission drift
        """
        full_path = (
            self._base_dir / path if not Path(path).is_absolute() else Path(path)
        )

        monitored = MonitoredPath(
            path=str(full_path),
            expected_mode=expected_mode,
            expected_owner=expected_owner,
            expected_group=expected_group,
            allow_suid=allow_suid,
            allow_sgid=allow_sgid,
            track_content=track_content,
            auto_remediate=auto_remediate,
        )

        # Capture baseline
        monitored.baseline_state = self._get_permission_state(full_path)

        self._monitored_paths[str(full_path)] = monitored
        logger.debug(f"Added monitored path: {full_path}")

    def remove_path(self, path: str) -> bool:
        """Remove a path from monitoring."""
        full_path = (
            self._base_dir / path if not Path(path).is_absolute() else Path(path)
        )
        if str(full_path) in self._monitored_paths:
            del self._monitored_paths[str(full_path)]
            return True
        return False

    def register_callback(self, callback: DriftCallback) -> None:
        """Register a callback for drift detection."""
        self._callbacks.append(callback)

    def unregister_callback(self, callback: DriftCallback) -> None:
        """Unregister a drift callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    async def _fire_callbacks(self, drift: PermissionDrift) -> None:
        """Fire all registered callbacks."""
        for callback in self._callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(drift)
                else:
                    callback(drift)
            except Exception as e:
                logger.error(f"Drift callback error: {e}")

    async def check_path(self, path: str) -> List[PermissionDrift]:
        """Check a single path for permission drift."""
        drifts: List[PermissionDrift] = []

        if path not in self._monitored_paths:
            return drifts

        monitored = self._monitored_paths[path]
        current_state = self._get_permission_state(Path(path))
        baseline = monitored.baseline_state

        # Check existence
        if not current_state.exists:
            drifts.append(
                PermissionDrift(
                    path=path,
                    drift_type=PermissionType.FILE_MODE,
                    severity=DriftSeverity.CRITICAL,
                    description="File no longer exists",
                    expected_value="exists",
                    actual_value="missing",
                )
            )
            return drifts

        # Check mode
        if monitored.expected_mode is not None:
            # Compare only permission bits (not file type)
            expected_perm = monitored.expected_mode & 0o777
            actual_perm = current_state.mode & 0o777
            if actual_perm != expected_perm:
                drifts.append(
                    PermissionDrift(
                        path=path,
                        drift_type=PermissionType.FILE_MODE,
                        severity=DriftSeverity.WARNING,
                        description="File mode changed",
                        expected_value=oct(expected_perm),
                        actual_value=oct(actual_perm),
                    )
                )
        elif baseline and baseline.mode != current_state.mode:
            drifts.append(
                PermissionDrift(
                    path=path,
                    drift_type=PermissionType.FILE_MODE,
                    severity=DriftSeverity.WARNING,
                    description="File mode changed from baseline",
                    expected_value=oct(baseline.mode),
                    actual_value=oct(current_state.mode),
                )
            )

        # Check owner
        if monitored.expected_owner is not None:
            if current_state.owner != monitored.expected_owner:
                drifts.append(
                    PermissionDrift(
                        path=path,
                        drift_type=PermissionType.OWNER,
                        severity=DriftSeverity.WARNING,
                        description="File owner changed",
                        expected_value=monitored.expected_owner,
                        actual_value=current_state.owner,
                    )
                )
        elif baseline and baseline.owner != current_state.owner:
            drifts.append(
                PermissionDrift(
                    path=path,
                    drift_type=PermissionType.OWNER,
                    severity=DriftSeverity.WARNING,
                    description="File owner changed from baseline",
                    expected_value=baseline.owner,
                    actual_value=current_state.owner,
                )
            )

        # Check group
        if monitored.expected_group is not None:
            if current_state.group != monitored.expected_group:
                drifts.append(
                    PermissionDrift(
                        path=path,
                        drift_type=PermissionType.GROUP,
                        severity=DriftSeverity.WARNING,
                        description="File group changed",
                        expected_value=monitored.expected_group,
                        actual_value=current_state.group,
                    )
                )
        elif baseline and baseline.group != current_state.group:
            drifts.append(
                PermissionDrift(
                    path=path,
                    drift_type=PermissionType.GROUP,
                    severity=DriftSeverity.WARNING,
                    description="File group changed from baseline",
                    expected_value=baseline.group,
                    actual_value=current_state.group,
                )
            )

        # Check SUID/SGID
        if current_state.is_suid and not monitored.allow_suid:
            drifts.append(
                PermissionDrift(
                    path=path,
                    drift_type=PermissionType.SUID_SGID,
                    severity=DriftSeverity.CRITICAL,
                    description="Unexpected SetUID bit detected",
                    expected_value="no suid",
                    actual_value="suid set",
                )
            )

        if current_state.is_sgid and not monitored.allow_sgid:
            drifts.append(
                PermissionDrift(
                    path=path,
                    drift_type=PermissionType.SUID_SGID,
                    severity=DriftSeverity.CRITICAL,
                    description="Unexpected SetGID bit detected",
                    expected_value="no sgid",
                    actual_value="sgid set",
                )
            )

        # Check content (checksum)
        if monitored.track_content and baseline:
            if baseline.checksum and current_state.checksum:
                if baseline.checksum != current_state.checksum:
                    drifts.append(
                        PermissionDrift(
                            path=path,
                            drift_type=PermissionType.FILE_MODE,
                            severity=DriftSeverity.WARNING,
                            description="File content changed",
                            expected_value=baseline.checksum[:16] + "...",
                            actual_value=current_state.checksum[:16] + "...",
                        )
                    )

        return drifts

    async def check_all(self) -> List[PermissionDrift]:
        """Check all monitored paths for drift."""
        self._total_checks += 1
        all_drifts: List[PermissionDrift] = []

        async with self._lock:
            for path in self._monitored_paths:
                drifts = await self.check_path(path)
                all_drifts.extend(drifts)

        # Record drifts
        for drift in all_drifts:
            self._total_drifts += 1
            self._drift_history.append(drift)
            await self._fire_callbacks(drift)

            # Log based on severity
            if drift.severity == DriftSeverity.CRITICAL:
                logger.error(f"CRITICAL drift: {drift.path} - {drift.description}")
            elif drift.severity == DriftSeverity.WARNING:
                logger.warning(f"Permission drift: {drift.path} - {drift.description}")
            else:
                logger.info(f"Permission info: {drift.path} - {drift.description}")

        # Trim history
        if len(self._drift_history) > self._max_history:
            self._drift_history = self._drift_history[-self._max_history :]

        return all_drifts

    async def start(self) -> None:
        """Start periodic permission monitoring."""
        if self._running:
            return

        self._running = True
        self._check_task = asyncio.create_task(self._check_loop())
        logger.info("PermissionMonitor started")

    async def stop(self) -> None:
        """Stop permission monitoring."""
        self._running = False
        if self._check_task:
            self._check_task.cancel()
            try:
                await self._check_task
            except asyncio.CancelledError:
                pass
        logger.info("PermissionMonitor stopped")

    async def _check_loop(self) -> None:
        """Background task for periodic checks."""
        while self._running:
            try:
                await asyncio.sleep(self._check_interval)
                await self.check_all()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in permission check loop: {e}")

    def get_monitored_paths(self) -> List[Dict[str, Any]]:
        """Get list of monitored paths."""
        return [
            {
                "path": m.path,
                "expected_mode": oct(m.expected_mode) if m.expected_mode else None,
                "expected_owner": m.expected_owner,
                "expected_group": m.expected_group,
                "allow_suid": m.allow_suid,
                "allow_sgid": m.allow_sgid,
                "track_content": m.track_content,
                "auto_remediate": m.auto_remediate,
                "has_baseline": m.baseline_state is not None,
            }
            for m in self._monitored_paths.values()
        ]

    def get_drift_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent drift history."""
        recent = self._drift_history[-limit:]
        return [d.to_dict() for d in reversed(recent)]

    def get_statistics(self) -> Dict[str, Any]:
        """Get monitor statistics."""
        return {
            "base_dir": str(self._base_dir),
            "monitored_paths_count": len(self._monitored_paths),
            "check_interval_seconds": self._check_interval,
            "total_checks": self._total_checks,
            "total_drifts": self._total_drifts,
            "auto_remediations": self._auto_remediations,
            "is_running": self._running,
            "uptime_seconds": time.time() - self._start_time,
        }


# Global singleton instance
_permission_monitor: Optional[PermissionMonitor] = None


def get_permission_monitor() -> PermissionMonitor:
    """Get or create the global permission monitor."""
    global _permission_monitor
    if _permission_monitor is None:
        _permission_monitor = PermissionMonitor()
    return _permission_monitor


async def reset_permission_monitor(
    base_dir: Optional[str] = None,
    check_interval: float = 60.0,
) -> PermissionMonitor:
    """Reset the global permission monitor."""
    global _permission_monitor
    if _permission_monitor:
        await _permission_monitor.stop()
    _permission_monitor = PermissionMonitor(
        base_dir=base_dir,
        check_interval=check_interval,
    )
    return _permission_monitor


# FastAPI integration
def create_permission_routes():
    """Create FastAPI routes for permission monitoring."""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel

    router = APIRouter(prefix="/api/v1/guard", tags=["permissions"])

    class AddPathRequest(BaseModel):
        path: str
        expected_mode: Optional[str] = None  # Octal string like "0644"
        expected_owner: Optional[str] = None
        expected_group: Optional[str] = None
        allow_suid: bool = False
        allow_sgid: bool = False
        track_content: bool = False
        auto_remediate: bool = False

    @router.post("/permissions/monitor")
    async def add_monitored_path(request: AddPathRequest):
        """Add a path to permission monitoring."""
        monitor = get_permission_monitor()

        expected_mode = None
        if request.expected_mode:
            try:
                expected_mode = int(request.expected_mode, 8)
            except ValueError:
                raise HTTPException(
                    status_code=400, detail=f"Invalid mode: {request.expected_mode}"
                )

        monitor.add_path(
            path=request.path,
            expected_mode=expected_mode,
            expected_owner=request.expected_owner,
            expected_group=request.expected_group,
            allow_suid=request.allow_suid,
            allow_sgid=request.allow_sgid,
            track_content=request.track_content,
            auto_remediate=request.auto_remediate,
        )

        return {"status": "added", "path": request.path}

    @router.delete("/permissions/monitor/{path:path}")
    async def remove_monitored_path(path: str):
        """Remove a path from monitoring."""
        monitor = get_permission_monitor()
        success = monitor.remove_path(path)

        if not success:
            raise HTTPException(status_code=404, detail="Path not found")

        return {"status": "removed", "path": path}

    @router.get("/permissions/check")
    async def check_permissions():
        """Check all monitored paths for drift."""
        monitor = get_permission_monitor()
        drifts = await monitor.check_all()

        return {
            "drifts": [d.to_dict() for d in drifts],
            "count": len(drifts),
        }

    @router.get("/permissions/paths")
    async def get_monitored_paths():
        """Get list of monitored paths."""
        monitor = get_permission_monitor()
        return {
            "paths": monitor.get_monitored_paths(),
        }

    @router.get("/permissions/history")
    async def get_drift_history(limit: int = 50):
        """Get permission drift history."""
        monitor = get_permission_monitor()
        return {
            "history": monitor.get_drift_history(limit),
        }

    @router.get("/permissions/stats")
    async def get_permission_stats():
        """Get permission monitor statistics."""
        monitor = get_permission_monitor()
        return monitor.get_statistics()

    return router
