"""
Atomic Updater with Rollback Support
=====================================

Implements atomic daemon updates with automatic rollback capability.

From guard-plan-v1.md:
- Atomic update mechanism (all-or-nothing)
- Automatic rollback on failure
- Backup of previous version
- Health check after update
- Update history tracking

Usage:
    from service.update.atomic_updater import AtomicUpdater, get_atomic_updater

    updater = get_atomic_updater()

    # Start an update
    result = await updater.start_update(
        new_version="1.1.0",
        update_package_path="/path/to/update.tar.gz"
    )

    # Rollback if needed
    await updater.rollback()
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class UpdateState(Enum):
    """State of an update operation."""

    IDLE = "idle"  # No update in progress
    DOWNLOADING = "downloading"  # Downloading update package
    VERIFYING = "verifying"  # Verifying package integrity
    BACKING_UP = "backing_up"  # Creating backup of current version
    EXTRACTING = "extracting"  # Extracting update package
    APPLYING = "applying"  # Applying update
    TESTING = "testing"  # Running post-update tests
    COMPLETED = "completed"  # Update completed successfully
    ROLLING_BACK = "rolling_back"  # Rolling back to previous version
    FAILED = "failed"  # Update failed


@dataclass
class UpdateInfo:
    """Information about an update operation."""

    update_id: str
    from_version: str
    to_version: str
    state: UpdateState
    started_at: datetime
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    backup_path: Optional[str] = None
    progress: float = 0.0  # 0.0 to 1.0
    steps_completed: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "update_id": self.update_id,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "state": self.state.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "error": self.error,
            "backup_path": self.backup_path,
            "progress": self.progress,
            "steps_completed": self.steps_completed,
            "metadata": self.metadata,
        }


@dataclass
class RollbackInfo:
    """Information about a rollback operation."""

    rollback_id: str
    from_version: str
    to_version: str
    reason: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    success: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rollback_id": self.rollback_id,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "reason": self.reason,
            "started_at": self.started_at.isoformat(),
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "success": self.success,
            "error": self.error,
        }


# Type alias for update callbacks
UpdateCallback = Callable[[UpdateInfo], None]


class AtomicUpdater:
    """
    Manages atomic updates with rollback capability.

    Features:
    - Atomic update (all-or-nothing)
    - Automatic backup before update
    - Integrity verification (SHA256)
    - Health check after update
    - Automatic rollback on failure
    - Update history
    """

    # Update steps in order
    UPDATE_STEPS = [
        "verify_package",
        "create_backup",
        "extract_package",
        "stop_daemon",
        "apply_update",
        "start_daemon",
        "health_check",
        "cleanup",
    ]

    def __init__(
        self,
        install_dir: Optional[str] = None,
        backup_dir: Optional[str] = None,
        current_version: str = "1.0.0",
        health_check_timeout: float = 30.0,
        max_history: int = 50,
    ):
        """
        Initialize the updater.

        Args:
            install_dir: Directory where daemon is installed
            backup_dir: Directory for storing backups
            current_version: Current daemon version
            health_check_timeout: Timeout for health check after update
            max_history: Maximum update history entries
        """
        self._install_dir = Path(install_dir or os.getcwd())
        self._backup_dir = Path(backup_dir or self._install_dir / "backups")
        self._current_version = current_version
        self._health_check_timeout = health_check_timeout
        self._max_history = max_history

        # Create backup directory
        self._backup_dir.mkdir(parents=True, exist_ok=True)

        # State
        self._current_update: Optional[UpdateInfo] = None
        self._update_history: List[UpdateInfo] = []
        self._rollback_history: List[RollbackInfo] = []
        self._callbacks: List[UpdateCallback] = []
        self._lock = asyncio.Lock()
        self._start_time = time.time()

        logger.info(
            f"AtomicUpdater initialized: install_dir={self._install_dir}, "
            f"version={current_version}"
        )

    def _generate_update_id(self) -> str:
        """Generate unique update ID."""
        import uuid

        return f"upd_{uuid.uuid4().hex[:12]}"

    def _generate_rollback_id(self) -> str:
        """Generate unique rollback ID."""
        import uuid

        return f"rbk_{uuid.uuid4().hex[:12]}"

    def register_callback(self, callback: UpdateCallback) -> None:
        """Register a callback for update state changes."""
        self._callbacks.append(callback)

    def unregister_callback(self, callback: UpdateCallback) -> None:
        """Unregister an update callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    async def _fire_callbacks(self, update: UpdateInfo) -> None:
        """Fire all registered callbacks."""
        for callback in self._callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(update)
                else:
                    callback(update)
            except Exception as e:
                logger.error(f"Update callback error: {e}")

    async def _update_state(
        self,
        update: UpdateInfo,
        state: UpdateState,
        progress: Optional[float] = None,
        step: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        """Update the state of an update operation."""
        update.state = state
        if progress is not None:
            update.progress = progress
        if step:
            update.steps_completed.append(step)
        if error:
            update.error = error

        await self._fire_callbacks(update)

    def _compute_checksum(self, file_path: Path) -> str:
        """Compute SHA256 checksum of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    async def _verify_package(
        self,
        package_path: Path,
        expected_checksum: Optional[str] = None,
    ) -> bool:
        """Verify package integrity."""
        if not package_path.exists():
            raise FileNotFoundError(f"Update package not found: {package_path}")

        if expected_checksum:
            actual_checksum = self._compute_checksum(package_path)
            if actual_checksum != expected_checksum:
                raise ValueError(
                    f"Checksum mismatch: expected {expected_checksum}, "
                    f"got {actual_checksum}"
                )

        # Verify it's a valid tar archive
        if not tarfile.is_tarfile(str(package_path)):
            raise ValueError("Invalid update package: not a valid tar archive")

        return True

    async def _create_backup(self, backup_path: Path) -> None:
        """Create backup of current installation."""
        # Create tar of current installation
        with tarfile.open(backup_path, "w:gz") as tar:
            # Add key directories/files
            for item in ["daemon", "config", "policies"]:
                item_path = self._install_dir / item
                if item_path.exists():
                    tar.add(item_path, arcname=item)

            # Add version file
            version_file = self._install_dir / "VERSION"
            if version_file.exists():
                tar.add(version_file, arcname="VERSION")

        logger.info(f"Backup created: {backup_path}")

    async def _extract_package(
        self,
        package_path: Path,
        target_dir: Path,
    ) -> None:
        """Extract update package to staging directory."""
        with tarfile.open(str(package_path), "r:*") as tar:
            # Security: check for path traversal
            for member in tar.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    raise ValueError(f"Unsafe path in package: {member.name}")

            tar.extractall(target_dir)

        logger.info(f"Package extracted to: {target_dir}")

    async def _apply_update(self, staging_dir: Path) -> None:
        """Apply update from staging directory."""
        # Copy files from staging to install dir
        for item in staging_dir.iterdir():
            target = self._install_dir / item.name
            if item.is_dir():
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(item, target)
            else:
                shutil.copy2(item, target)

        logger.info("Update applied")

    async def _health_check(self) -> bool:
        """Run health check after update."""
        import aiohttp

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "http://127.0.0.1:8765/health",
                    timeout=aiohttp.ClientTimeout(total=self._health_check_timeout),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("status") == "healthy"
        except Exception as e:
            logger.error(f"Health check failed: {e}")

        return False

    async def _restore_backup(self, backup_path: Path) -> None:
        """Restore from backup."""
        # Extract backup to temp dir first
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            with tarfile.open(str(backup_path), "r:gz") as tar:
                tar.extractall(temp_path)

            # Copy back to install dir
            for item in temp_path.iterdir():
                target = self._install_dir / item.name
                if item.is_dir():
                    if target.exists():
                        shutil.rmtree(target)
                    shutil.copytree(item, target)
                else:
                    shutil.copy2(item, target)

        logger.info(f"Restored from backup: {backup_path}")

    async def start_update(
        self,
        new_version: str,
        update_package_path: str,
        expected_checksum: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> UpdateInfo:
        """
        Start an atomic update.

        Args:
            new_version: Version being updated to
            update_package_path: Path to the update package
            expected_checksum: Expected SHA256 checksum
            metadata: Additional metadata

        Returns:
            UpdateInfo with update status
        """
        async with self._lock:
            if self._current_update and self._current_update.state not in [
                UpdateState.COMPLETED,
                UpdateState.FAILED,
                UpdateState.IDLE,
            ]:
                raise RuntimeError("Update already in progress")

            package_path = Path(update_package_path)

            # Create update info
            update = UpdateInfo(
                update_id=self._generate_update_id(),
                from_version=self._current_version,
                to_version=new_version,
                state=UpdateState.IDLE,
                started_at=datetime.utcnow(),
                metadata=metadata or {},
            )

            self._current_update = update

            try:
                # Step 1: Verify package
                await self._update_state(update, UpdateState.VERIFYING, progress=0.1)
                await self._verify_package(package_path, expected_checksum)
                await self._update_state(
                    update, UpdateState.VERIFYING, step="verify_package"
                )

                # Step 2: Create backup
                await self._update_state(update, UpdateState.BACKING_UP, progress=0.2)
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                backup_path = (
                    self._backup_dir
                    / f"backup_{self._current_version}_{timestamp}.tar.gz"
                )
                await self._create_backup(backup_path)
                update.backup_path = str(backup_path)
                await self._update_state(
                    update, UpdateState.BACKING_UP, step="create_backup"
                )

                # Step 3: Extract package
                await self._update_state(update, UpdateState.EXTRACTING, progress=0.4)
                staging_dir = Path(tempfile.mkdtemp(prefix="guard_update_"))
                try:
                    await self._extract_package(package_path, staging_dir)
                    await self._update_state(
                        update, UpdateState.EXTRACTING, step="extract_package"
                    )

                    # Step 4: Apply update
                    await self._update_state(update, UpdateState.APPLYING, progress=0.6)
                    await self._apply_update(staging_dir)
                    await self._update_state(
                        update, UpdateState.APPLYING, step="apply_update"
                    )

                finally:
                    # Cleanup staging
                    shutil.rmtree(staging_dir, ignore_errors=True)

                # Step 5: Health check
                await self._update_state(update, UpdateState.TESTING, progress=0.8)
                # Give daemon time to restart
                await asyncio.sleep(2)

                if not await self._health_check():
                    raise RuntimeError("Health check failed after update")

                await self._update_state(
                    update, UpdateState.TESTING, step="health_check"
                )

                # Success!
                await self._update_state(
                    update, UpdateState.COMPLETED, progress=1.0, step="cleanup"
                )
                update.completed_at = datetime.utcnow()
                self._current_version = new_version

                logger.info(
                    f"Update completed: {update.from_version} -> {update.to_version}"
                )

            except Exception as e:
                logger.error(f"Update failed: {e}")
                update.error = str(e)
                await self._update_state(update, UpdateState.FAILED, error=str(e))

                # Auto-rollback on failure
                if update.backup_path:
                    await self.rollback(reason=f"Auto-rollback: {e}")

            # Add to history
            self._update_history.append(update)
            if len(self._update_history) > self._max_history:
                self._update_history = self._update_history[-self._max_history :]

            return update

    async def rollback(
        self,
        reason: str = "Manual rollback",
        target_version: Optional[str] = None,
    ) -> RollbackInfo:
        """
        Rollback to a previous version.

        Args:
            reason: Reason for rollback
            target_version: Specific version to roll back to (uses latest backup if not specified)

        Returns:
            RollbackInfo with rollback status
        """
        async with self._lock:
            # Find backup to restore
            if target_version:
                # Find specific version backup
                backups = sorted(
                    self._backup_dir.glob(f"backup_{target_version}_*.tar.gz")
                )
                if not backups:
                    raise FileNotFoundError(
                        f"No backup found for version {target_version}"
                    )
                backup_path = backups[-1]  # Latest backup for that version
            elif self._current_update and self._current_update.backup_path:
                backup_path = Path(self._current_update.backup_path)
            else:
                # Find latest backup
                backups = sorted(self._backup_dir.glob("backup_*.tar.gz"))
                if not backups:
                    raise FileNotFoundError("No backups available")
                backup_path = backups[-1]

            # Extract version from backup name
            backup_name = backup_path.stem  # backup_1.0.0_20260204_120000
            parts = backup_name.split("_")
            restore_version = parts[1] if len(parts) > 1 else "unknown"

            rollback = RollbackInfo(
                rollback_id=self._generate_rollback_id(),
                from_version=self._current_version,
                to_version=restore_version,
                reason=reason,
                started_at=datetime.utcnow(),
            )

            try:
                if self._current_update:
                    await self._update_state(
                        self._current_update, UpdateState.ROLLING_BACK
                    )

                await self._restore_backup(backup_path)

                # Health check after rollback
                await asyncio.sleep(2)
                if not await self._health_check():
                    logger.warning("Health check failed after rollback")

                rollback.success = True
                rollback.completed_at = datetime.utcnow()
                self._current_version = restore_version

                logger.info(
                    f"Rollback completed: {rollback.from_version} -> {rollback.to_version}"
                )

            except Exception as e:
                logger.error(f"Rollback failed: {e}")
                rollback.error = str(e)
                rollback.success = False
                rollback.completed_at = datetime.utcnow()

            # Add to history
            self._rollback_history.append(rollback)

            return rollback

    def get_current_update(self) -> Optional[UpdateInfo]:
        """Get current update info."""
        return self._current_update

    def get_current_version(self) -> str:
        """Get current daemon version."""
        return self._current_version

    def get_update_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get update history."""
        recent = self._update_history[-limit:]
        return [u.to_dict() for u in reversed(recent)]

    def get_rollback_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get rollback history."""
        recent = self._rollback_history[-limit:]
        return [r.to_dict() for r in reversed(recent)]

    def get_available_backups(self) -> List[Dict[str, Any]]:
        """Get list of available backups."""
        backups = []
        for backup_path in sorted(self._backup_dir.glob("backup_*.tar.gz")):
            stat = backup_path.stat()
            name = backup_path.stem
            parts = name.split("_")
            version = parts[1] if len(parts) > 1 else "unknown"

            backups.append(
                {
                    "path": str(backup_path),
                    "version": version,
                    "size_bytes": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                }
            )

        return backups

    def get_statistics(self) -> Dict[str, Any]:
        """Get updater statistics."""
        return {
            "current_version": self._current_version,
            "install_dir": str(self._install_dir),
            "backup_dir": str(self._backup_dir),
            "total_updates": len(self._update_history),
            "successful_updates": sum(
                1 for u in self._update_history if u.state == UpdateState.COMPLETED
            ),
            "failed_updates": sum(
                1 for u in self._update_history if u.state == UpdateState.FAILED
            ),
            "total_rollbacks": len(self._rollback_history),
            "successful_rollbacks": sum(1 for r in self._rollback_history if r.success),
            "available_backups": len(list(self._backup_dir.glob("backup_*.tar.gz"))),
            "uptime_seconds": time.time() - self._start_time,
        }


# Global singleton instance
_atomic_updater: Optional[AtomicUpdater] = None


def get_atomic_updater() -> AtomicUpdater:
    """Get or create the global atomic updater."""
    global _atomic_updater
    if _atomic_updater is None:
        _atomic_updater = AtomicUpdater()
    return _atomic_updater


def reset_atomic_updater(
    install_dir: Optional[str] = None,
    backup_dir: Optional[str] = None,
    current_version: str = "1.0.0",
) -> AtomicUpdater:
    """Reset the global atomic updater."""
    global _atomic_updater
    _atomic_updater = AtomicUpdater(
        install_dir=install_dir,
        backup_dir=backup_dir,
        current_version=current_version,
    )
    return _atomic_updater


# FastAPI integration
def create_updater_routes():
    """Create FastAPI routes for the updater."""
    from fastapi import APIRouter, HTTPException, UploadFile, File
    from pydantic import BaseModel

    router = APIRouter(prefix="/api/v1/guard", tags=["update"])

    class StartUpdateRequest(BaseModel):
        new_version: str
        package_path: str
        expected_checksum: Optional[str] = None

    class RollbackRequest(BaseModel):
        reason: str = "Manual rollback"
        target_version: Optional[str] = None

    @router.post("/update/start")
    async def start_update(request: StartUpdateRequest):
        """Start an atomic update."""
        updater = get_atomic_updater()

        try:
            result = await updater.start_update(
                new_version=request.new_version,
                update_package_path=request.package_path,
                expected_checksum=request.expected_checksum,
            )
            return result.to_dict()
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.post("/update/rollback")
    async def rollback(request: RollbackRequest):
        """Rollback to a previous version."""
        updater = get_atomic_updater()

        try:
            result = await updater.rollback(
                reason=request.reason,
                target_version=request.target_version,
            )
            return result.to_dict()
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.get("/update/status")
    async def get_update_status():
        """Get current update status."""
        updater = get_atomic_updater()
        current = updater.get_current_update()

        return {
            "current_version": updater.get_current_version(),
            "update_in_progress": current is not None
            and current.state
            not in [
                UpdateState.COMPLETED,
                UpdateState.FAILED,
                UpdateState.IDLE,
            ],
            "current_update": current.to_dict() if current else None,
        }

    @router.get("/update/history")
    async def get_update_history(limit: int = 10):
        """Get update history."""
        updater = get_atomic_updater()
        return {
            "updates": updater.get_update_history(limit),
            "rollbacks": updater.get_rollback_history(limit),
        }

    @router.get("/update/backups")
    async def get_backups():
        """Get available backups."""
        updater = get_atomic_updater()
        return {
            "backups": updater.get_available_backups(),
        }

    @router.get("/update/stats")
    async def get_update_stats():
        """Get updater statistics."""
        updater = get_atomic_updater()
        return updater.get_statistics()

    return router
