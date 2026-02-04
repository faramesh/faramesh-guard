"""
Configuration Migration System
===============================

Handles configuration schema migrations between versions.

From guard-plan-v1.md:
- Automatic config migration on version upgrade
- Backup of old config
- Schema version tracking
- Rollback support
- Migration validation

Usage:
    from service.config.migrator import ConfigMigrator, get_config_migrator

    migrator = get_config_migrator()

    # Register migrations
    migrator.register_migration(
        from_version="1.0.0",
        to_version="1.1.0",
        migrate_fn=migrate_1_0_to_1_1
    )

    # Run migration
    result = await migrator.migrate(config_path="/path/to/config.yaml")
"""

import asyncio
import copy
import hashlib
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


@dataclass
class MigrationStep:
    """A single migration step between versions."""

    from_version: str
    to_version: str
    description: str = ""
    migrate_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None
    validate_fn: Optional[Callable[[Dict[str, Any]], bool]] = None
    reversible: bool = True
    reverse_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None


@dataclass
class MigrationResult:
    """Result of a migration operation."""

    success: bool
    from_version: str
    to_version: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    steps_applied: List[str] = field(default_factory=list)
    backup_path: Optional[str] = None
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "started_at": self.started_at.isoformat(),
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "steps_applied": self.steps_applied,
            "backup_path": self.backup_path,
            "error": self.error,
            "warnings": self.warnings,
        }


class ConfigMigrator:
    """
    Manages configuration migrations between versions.

    Features:
    - Automatic version detection
    - Sequential migration steps
    - Backup before migration
    - Validation after each step
    - Rollback support
    - Migration history
    """

    SCHEMA_VERSION_KEY = "_schema_version"
    DEFAULT_VERSION = "1.0.0"

    def __init__(
        self,
        config_dir: Optional[str] = None,
        backup_dir: Optional[str] = None,
        current_schema_version: str = "1.0.0",
    ):
        """
        Initialize the migrator.

        Args:
            config_dir: Directory containing config files
            backup_dir: Directory for config backups
            current_schema_version: Current schema version
        """
        self._config_dir = Path(config_dir or os.getcwd())
        self._backup_dir = Path(backup_dir or self._config_dir / "config_backups")
        self._current_schema_version = current_schema_version

        # Create backup directory
        self._backup_dir.mkdir(parents=True, exist_ok=True)

        # Migration registry: (from_version, to_version) -> MigrationStep
        self._migrations: Dict[Tuple[str, str], MigrationStep] = {}

        # Migration history
        self._history: List[MigrationResult] = []
        self._max_history = 50

        self._start_time = time.time()

        # Register built-in migrations
        self._register_builtin_migrations()

        logger.info(
            f"ConfigMigrator initialized: config_dir={self._config_dir}, "
            f"schema_version={current_schema_version}"
        )

    def _register_builtin_migrations(self) -> None:
        """Register built-in migration steps."""

        # 1.0.0 -> 1.1.0: Add new fields
        def migrate_1_0_to_1_1(config: Dict[str, Any]) -> Dict[str, Any]:
            config = copy.deepcopy(config)
            # Add heartbeat settings
            if "heartbeat" not in config:
                config["heartbeat"] = {
                    "enabled": True,
                    "interval_seconds": 5,
                    "timeout_seconds": 15,
                }
            # Add deduplication settings
            if "deduplication" not in config:
                config["deduplication"] = {
                    "enabled": True,
                    "window_seconds": 60,
                }
            return config

        def reverse_1_1_to_1_0(config: Dict[str, Any]) -> Dict[str, Any]:
            config = copy.deepcopy(config)
            config.pop("heartbeat", None)
            config.pop("deduplication", None)
            return config

        self.register_migration(
            from_version="1.0.0",
            to_version="1.1.0",
            description="Add heartbeat and deduplication settings",
            migrate_fn=migrate_1_0_to_1_1,
            reverse_fn=reverse_1_1_to_1_0,
        )

        # 1.1.0 -> 1.2.0: Add shadow mode
        def migrate_1_1_to_1_2(config: Dict[str, Any]) -> Dict[str, Any]:
            config = copy.deepcopy(config)
            if "shadow_mode" not in config:
                config["shadow_mode"] = {
                    "enabled": False,
                    "log_only": True,
                    "rules": [],
                }
            if "training" not in config:
                config["training"] = {
                    "collect_data": False,
                    "max_samples": 10000,
                }
            return config

        def reverse_1_2_to_1_1(config: Dict[str, Any]) -> Dict[str, Any]:
            config = copy.deepcopy(config)
            config.pop("shadow_mode", None)
            config.pop("training", None)
            return config

        self.register_migration(
            from_version="1.1.0",
            to_version="1.2.0",
            description="Add shadow mode and training data settings",
            migrate_fn=migrate_1_1_to_1_2,
            reverse_fn=reverse_1_2_to_1_1,
        )

    def register_migration(
        self,
        from_version: str,
        to_version: str,
        migrate_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
        description: str = "",
        validate_fn: Optional[Callable[[Dict[str, Any]], bool]] = None,
        reverse_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> None:
        """
        Register a migration step.

        Args:
            from_version: Source version
            to_version: Target version
            migrate_fn: Function to transform config
            description: Human-readable description
            validate_fn: Optional validation function
            reverse_fn: Optional reverse migration function
        """
        step = MigrationStep(
            from_version=from_version,
            to_version=to_version,
            description=description,
            migrate_fn=migrate_fn,
            validate_fn=validate_fn,
            reversible=reverse_fn is not None,
            reverse_fn=reverse_fn,
        )
        self._migrations[(from_version, to_version)] = step
        logger.debug(f"Registered migration: {from_version} -> {to_version}")

    def _get_migration_path(
        self, from_version: str, to_version: str
    ) -> List[MigrationStep]:
        """Find the migration path between two versions."""
        # Simple BFS to find path
        from collections import deque

        queue = deque([(from_version, [])])
        visited = {from_version}

        while queue:
            current_version, path = queue.popleft()

            if current_version == to_version:
                return path

            # Find all migrations from current version
            for (fv, tv), step in self._migrations.items():
                if fv == current_version and tv not in visited:
                    visited.add(tv)
                    queue.append((tv, path + [step]))

        return []  # No path found

    def _compute_checksum(self, config: Dict[str, Any]) -> str:
        """Compute checksum of config."""
        canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    async def _backup_config(self, config_path: Path) -> Path:
        """Create backup of config file."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{config_path.stem}_{timestamp}{config_path.suffix}"
        backup_path = self._backup_dir / backup_name

        shutil.copy2(config_path, backup_path)
        logger.info(f"Config backed up to: {backup_path}")
        return backup_path

    def _load_config(self, config_path: Path) -> Dict[str, Any]:
        """Load config from file."""
        with open(config_path) as f:
            if config_path.suffix in [".yaml", ".yml"]:
                return yaml.safe_load(f) or {}
            else:
                return json.load(f)

    def _save_config(self, config: Dict[str, Any], config_path: Path) -> None:
        """Save config to file."""
        with open(config_path, "w") as f:
            if config_path.suffix in [".yaml", ".yml"]:
                yaml.safe_dump(config, f, default_flow_style=False)
            else:
                json.dump(config, f, indent=2)

    def _get_config_version(self, config: Dict[str, Any]) -> str:
        """Extract version from config."""
        return config.get(self.SCHEMA_VERSION_KEY, self.DEFAULT_VERSION)

    def _set_config_version(
        self, config: Dict[str, Any], version: str
    ) -> Dict[str, Any]:
        """Set version in config."""
        config = copy.deepcopy(config)
        config[self.SCHEMA_VERSION_KEY] = version
        return config

    async def migrate(
        self,
        config_path: str,
        target_version: Optional[str] = None,
        dry_run: bool = False,
    ) -> MigrationResult:
        """
        Migrate config to target version.

        Args:
            config_path: Path to config file
            target_version: Target version (default: current schema version)
            dry_run: If True, don't actually modify files

        Returns:
            MigrationResult with migration details
        """
        config_file = Path(config_path)
        target = target_version or self._current_schema_version

        result = MigrationResult(
            success=False,
            from_version="",
            to_version=target,
            started_at=datetime.utcnow(),
        )

        try:
            # Load config
            config = self._load_config(config_file)
            from_version = self._get_config_version(config)
            result.from_version = from_version

            # Check if migration needed
            if from_version == target:
                result.success = True
                result.completed_at = datetime.utcnow()
                result.warnings.append("Already at target version, no migration needed")
                return result

            # Find migration path
            path = self._get_migration_path(from_version, target)
            if not path:
                raise ValueError(f"No migration path from {from_version} to {target}")

            # Backup config
            if not dry_run:
                backup_path = await self._backup_config(config_file)
                result.backup_path = str(backup_path)

            # Apply migrations
            current_config = config
            for step in path:
                logger.info(
                    f"Applying migration: {step.from_version} -> {step.to_version}"
                )

                if step.migrate_fn:
                    current_config = step.migrate_fn(current_config)

                # Validate if validator provided
                if step.validate_fn:
                    if not step.validate_fn(current_config):
                        raise ValueError(
                            f"Validation failed after migration to {step.to_version}"
                        )

                # Update version
                current_config = self._set_config_version(
                    current_config, step.to_version
                )

                result.steps_applied.append(
                    f"{step.from_version} -> {step.to_version}: {step.description}"
                )

            # Save migrated config
            if not dry_run:
                self._save_config(current_config, config_file)

            result.success = True
            result.completed_at = datetime.utcnow()

            logger.info(
                f"Migration completed: {from_version} -> {target} "
                f"({len(path)} steps)"
            )

        except Exception as e:
            logger.error(f"Migration failed: {e}")
            result.error = str(e)
            result.completed_at = datetime.utcnow()

        # Add to history
        self._history.append(result)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]

        return result

    async def rollback(
        self,
        config_path: str,
        backup_path: str,
    ) -> MigrationResult:
        """
        Rollback config to a backup.

        Args:
            config_path: Path to current config
            backup_path: Path to backup to restore

        Returns:
            MigrationResult with rollback details
        """
        result = MigrationResult(
            success=False,
            from_version="current",
            to_version="backup",
            started_at=datetime.utcnow(),
        )

        try:
            backup_file = Path(backup_path)
            config_file = Path(config_path)

            if not backup_file.exists():
                raise FileNotFoundError(f"Backup not found: {backup_path}")

            # Load backup to get version
            backup_config = self._load_config(backup_file)
            result.to_version = self._get_config_version(backup_config)

            # Load current to get version
            if config_file.exists():
                current_config = self._load_config(config_file)
                result.from_version = self._get_config_version(current_config)

            # Restore backup
            shutil.copy2(backup_file, config_file)

            result.success = True
            result.completed_at = datetime.utcnow()
            result.steps_applied.append(f"Restored from: {backup_path}")

            logger.info(f"Config rolled back from: {backup_path}")

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            result.error = str(e)
            result.completed_at = datetime.utcnow()

        return result

    def get_available_migrations(self) -> List[Dict[str, Any]]:
        """Get list of available migrations."""
        return [
            {
                "from_version": step.from_version,
                "to_version": step.to_version,
                "description": step.description,
                "reversible": step.reversible,
            }
            for step in self._migrations.values()
        ]

    def get_migration_path(
        self, from_version: str, to_version: str
    ) -> List[Dict[str, Any]]:
        """Get migration path between versions."""
        path = self._get_migration_path(from_version, to_version)
        return [
            {
                "from_version": step.from_version,
                "to_version": step.to_version,
                "description": step.description,
            }
            for step in path
        ]

    def get_available_backups(self) -> List[Dict[str, Any]]:
        """Get list of available config backups."""
        backups = []
        for backup_path in sorted(self._backup_dir.glob("*")):
            if backup_path.is_file():
                stat = backup_path.stat()
                try:
                    config = self._load_config(backup_path)
                    version = self._get_config_version(config)
                except Exception:
                    version = "unknown"

                backups.append(
                    {
                        "path": str(backup_path),
                        "name": backup_path.name,
                        "version": version,
                        "size_bytes": stat.st_size,
                        "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    }
                )
        return backups

    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get migration history."""
        recent = self._history[-limit:]
        return [r.to_dict() for r in reversed(recent)]

    def get_statistics(self) -> Dict[str, Any]:
        """Get migrator statistics."""
        return {
            "config_dir": str(self._config_dir),
            "backup_dir": str(self._backup_dir),
            "current_schema_version": self._current_schema_version,
            "registered_migrations": len(self._migrations),
            "total_migrations_run": len(self._history),
            "successful_migrations": sum(1 for r in self._history if r.success),
            "failed_migrations": sum(1 for r in self._history if not r.success),
            "available_backups": len(list(self._backup_dir.glob("*"))),
            "uptime_seconds": time.time() - self._start_time,
        }


# Global singleton instance
_config_migrator: Optional[ConfigMigrator] = None


def get_config_migrator() -> ConfigMigrator:
    """Get or create the global config migrator."""
    global _config_migrator
    if _config_migrator is None:
        _config_migrator = ConfigMigrator()
    return _config_migrator


def reset_config_migrator(
    config_dir: Optional[str] = None,
    backup_dir: Optional[str] = None,
    current_schema_version: str = "1.0.0",
) -> ConfigMigrator:
    """Reset the global config migrator."""
    global _config_migrator
    _config_migrator = ConfigMigrator(
        config_dir=config_dir,
        backup_dir=backup_dir,
        current_schema_version=current_schema_version,
    )
    return _config_migrator


# FastAPI integration
def create_migrator_routes():
    """Create FastAPI routes for config migration."""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel

    router = APIRouter(prefix="/api/v1/guard", tags=["config"])

    class MigrateRequest(BaseModel):
        config_path: str
        target_version: Optional[str] = None
        dry_run: bool = False

    class RollbackRequest(BaseModel):
        config_path: str
        backup_path: str

    @router.post("/config/migrate")
    async def migrate_config(request: MigrateRequest):
        """Migrate config to target version."""
        migrator = get_config_migrator()

        try:
            result = await migrator.migrate(
                config_path=request.config_path,
                target_version=request.target_version,
                dry_run=request.dry_run,
            )
            return result.to_dict()
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.post("/config/rollback")
    async def rollback_config(request: RollbackRequest):
        """Rollback config to a backup."""
        migrator = get_config_migrator()

        try:
            result = await migrator.rollback(
                config_path=request.config_path,
                backup_path=request.backup_path,
            )
            return result.to_dict()
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.get("/config/migrations")
    async def get_migrations():
        """Get available migrations."""
        migrator = get_config_migrator()
        return {
            "migrations": migrator.get_available_migrations(),
        }

    @router.get("/config/migration-path")
    async def get_migration_path(from_version: str, to_version: str):
        """Get migration path between versions."""
        migrator = get_config_migrator()
        path = migrator.get_migration_path(from_version, to_version)
        return {
            "from_version": from_version,
            "to_version": to_version,
            "path": path,
            "steps": len(path),
        }

    @router.get("/config/backups")
    async def get_backups():
        """Get available config backups."""
        migrator = get_config_migrator()
        return {
            "backups": migrator.get_available_backups(),
        }

    @router.get("/config/history")
    async def get_history(limit: int = 10):
        """Get migration history."""
        migrator = get_config_migrator()
        return {
            "history": migrator.get_history(limit),
        }

    @router.get("/config/stats")
    async def get_stats():
        """Get migrator statistics."""
        migrator = get_config_migrator()
        return migrator.get_statistics()

    return router
