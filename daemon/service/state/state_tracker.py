"""
State Tracker - Workspace State Management

Provides workspace state snapshots, Merkle hashing, and drift detection.
Enables state-aware decisions: "What's the current workspace state?"

Key Features:
- Compute workspace state hash (Merkle root)
- Track file modifications
- Detect drift (unexpected state changes)
- State-based policy rules

Following guard-plan-v1.md Section 3: State-Aware Context Model
"""

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class WorkspaceState:
    """Immutable workspace state snapshot."""

    workspace_id: str
    state_hash: str  # Merkle root of all tracked files
    tracked_files: Dict[str, str]  # path → file_hash
    last_action_id: str
    timestamp: datetime
    file_count: int


@dataclass
class StateDrift:
    """Detected state drift (unexpected changes)."""

    workspace_id: str
    changed_files: List[str]
    message: str
    severity: str  # "low", "medium", "high"


class StateTracker:
    """
    Track workspace state changes and detect drift.

    Provides:
    - State snapshots with Merkle hashing
    - Drift detection (files changed outside expected sequence)
    - State history tracking
    """

    def __init__(self, state_dir: Path = Path.home() / ".faramesh-guard" / "state"):
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_store = {}  # workspace_id → WorkspaceState
        logger.info(f"StateTracker initialized with state_dir={state_dir}")

    def snapshot(self, workspace_id: str, workspace_path: Path) -> WorkspaceState:
        """
        Create state snapshot of workspace.

        Args:
            workspace_id: Unique workspace identifier
            workspace_path: Absolute path to workspace directory

        Returns:
            WorkspaceState with Merkle hash of all tracked files
        """
        tracked_files = self._get_tracked_files(workspace_path)

        file_hashes = {}
        for path in tracked_files:
            try:
                content_hash = self._hash_file(path)
                rel_path = str(path.relative_to(workspace_path))
                file_hashes[rel_path] = content_hash
            except Exception as e:
                logger.warning(f"Failed to hash file {path}: {e}")

        # Compute Merkle root (simple: hash of sorted file hashes)
        state_hash = hashlib.sha256(
            json.dumps(file_hashes, sort_keys=True).encode()
        ).hexdigest()

        state = WorkspaceState(
            workspace_id=workspace_id,
            state_hash=state_hash,
            tracked_files=file_hashes,
            last_action_id="",
            timestamp=datetime.utcnow(),
            file_count=len(file_hashes),
        )

        # Store for drift detection
        self.state_store[workspace_id] = state

        logger.info(
            f"Snapshot created for workspace {workspace_id}: "
            f"{len(file_hashes)} files, hash={state_hash[:12]}"
        )

        return state

    def detect_drift(
        self, workspace_id: str, workspace_path: Path
    ) -> Optional[StateDrift]:
        """
        Detect unexpected state changes.

        Compares current workspace state with expected state.
        Returns StateDrift if files changed outside Guard execution.
        """
        expected = self.state_store.get(workspace_id)
        if not expected:
            logger.debug(f"No expected state for workspace {workspace_id}")
            return None

        current = self.snapshot(workspace_id, workspace_path)

        if current.state_hash == expected.state_hash:
            return None  # No drift

        # Find changed files
        changed_files = []
        for path, current_hash in current.tracked_files.items():
            expected_hash = expected.tracked_files.get(path)
            if expected_hash != current_hash:
                changed_files.append(path)

        # Check for deleted files
        for path in expected.tracked_files:
            if path not in current.tracked_files:
                changed_files.append(f"{path} (deleted)")

        # Check for new files
        for path in current.tracked_files:
            if path not in expected.tracked_files:
                changed_files.append(f"{path} (new)")

        severity = self._assess_drift_severity(changed_files)

        drift = StateDrift(
            workspace_id=workspace_id,
            changed_files=changed_files,
            message=f"State changed outside Guard execution: {len(changed_files)} files",
            severity=severity,
        )

        logger.warning(
            f"Drift detected in workspace {workspace_id}: "
            f"{len(changed_files)} files changed (severity={severity})"
        )

        return drift

    def update_expected_state(
        self, workspace_id: str, new_state: WorkspaceState
    ) -> None:
        """Update expected state after Guard-authorized action."""
        self.state_store[workspace_id] = new_state
        logger.debug(f"Updated expected state for workspace {workspace_id}")

    def _get_tracked_files(self, workspace_path: Path) -> List[Path]:
        """
        Get list of files to track in workspace.

        Tracks:
        - Source code files (.py, .ts, .js, .java, etc.)
        - Configuration files (.yaml, .json, .toml, etc.)
        - Documentation (.md, .rst)

        Excludes:
        - node_modules/, .git/, __pycache__/, venv/
        - Binary files
        - Large files (>10MB)
        """
        tracked = []
        exclude_dirs = {
            "node_modules",
            ".git",
            "__pycache__",
            "venv",
            ".venv",
            "dist",
            "build",
            ".next",
            ".cache",
        }
        include_exts = {
            ".py",
            ".ts",
            ".js",
            ".jsx",
            ".tsx",
            ".java",
            ".go",
            ".rs",
            ".yaml",
            ".yml",
            ".json",
            ".toml",
            ".md",
            ".rst",
            ".txt",
            ".sh",
            ".env",
            ".gitignore",
        }

        max_file_size = 10 * 1024 * 1024  # 10MB

        try:
            for path in workspace_path.rglob("*"):
                # Skip directories
                if path.is_dir():
                    continue

                # Skip excluded directories
                if any(excluded in path.parts for excluded in exclude_dirs):
                    continue

                # Check extension
                if path.suffix not in include_exts:
                    continue

                # Check file size
                try:
                    if path.stat().st_size > max_file_size:
                        continue
                except:
                    continue

                tracked.append(path)

        except Exception as e:
            logger.error(f"Error scanning workspace {workspace_path}: {e}")

        return tracked

    def _hash_file(self, path: Path) -> str:
        """Compute SHA256 hash of file contents."""
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                # Read in chunks for large files
                while chunk := f.read(8192):
                    hasher.update(chunk)
        except Exception as e:
            logger.warning(f"Failed to hash {path}: {e}")
            return "ERROR"

        return hasher.hexdigest()

    def _assess_drift_severity(self, changed_files: List[str]) -> str:
        """
        Assess severity of drift based on changed files.

        Rules:
        - High: >10 files or sensitive files (.env, config)
        - Medium: 3-10 files
        - Low: 1-2 files
        """
        sensitive_patterns = [".env", "config", "secret", "key", "password"]

        # Check for sensitive files
        for file in changed_files:
            if any(pattern in file.lower() for pattern in sensitive_patterns):
                return "high"

        # Check count
        if len(changed_files) > 10:
            return "high"
        elif len(changed_files) > 3:
            return "medium"
        else:
            return "low"


# Singleton instance
_state_tracker: Optional[StateTracker] = None


def get_state_tracker() -> StateTracker:
    """Get or create singleton StateTracker instance."""
    global _state_tracker
    if _state_tracker is None:
        _state_tracker = StateTracker()
    return _state_tracker
