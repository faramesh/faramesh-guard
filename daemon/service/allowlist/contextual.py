"""
Contextual Allowlists for Faramesh Guard.

Context-aware allowlists that can be scoped by time, session,
workflow, agent, or other conditions.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
import aiofiles

logger = logging.getLogger(__name__)


class AllowlistScope(str, Enum):
    """Scope of allowlist."""

    GLOBAL = "global"  # Applies everywhere
    SESSION = "session"  # Applies to specific session
    WORKFLOW = "workflow"  # Applies within workflow
    TIME_WINDOW = "time_window"  # Applies during time window
    AGENT = "agent"  # Applies to specific agent
    RESOURCE = "resource"  # Applies to resource pattern


@dataclass
class AllowlistEntry:
    """A single allowlist entry."""

    entry_id: str
    name: str
    description: str

    # Matching criteria
    action_types: List[str] = field(default_factory=list)  # Empty = all
    resource_patterns: List[str] = field(default_factory=list)
    agent_ids: List[str] = field(default_factory=list)

    # Scope
    scope: str = AllowlistScope.GLOBAL.value
    scope_value: Optional[str] = None  # session_id, workflow_id, etc.

    # Time window
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    time_of_day_start: Optional[str] = None  # "09:00"
    time_of_day_end: Optional[str] = None  # "17:00"
    days_of_week: List[int] = field(default_factory=list)  # 0=Mon, 6=Sun

    # Status
    enabled: bool = True
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    created_by: Optional[str] = None

    # Tracking
    hit_count: int = 0
    last_hit: Optional[str] = None


@dataclass
class AllowlistMatch:
    """Result of checking against allowlists."""

    allowed: bool
    entry: Optional[AllowlistEntry] = None
    reason: str = ""


class ContextualAllowlist:
    """
    Manages context-aware allowlists.

    Features:
    - Multiple scopes (global, session, workflow, time, agent, resource)
    - Time-windowed entries
    - Pattern matching
    - Hit tracking
    - Priority ordering
    """

    def __init__(self, data_dir: str = "/var/lib/faramesh-guard/allowlists"):
        self.data_dir = Path(data_dir)
        self._entries: Dict[str, AllowlistEntry] = {}
        self._lock = asyncio.Lock()

        logger.info("ContextualAllowlist initialized")

    async def start(self):
        """Start and load entries."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        await self._load_entries()

    async def stop(self):
        """Save entries."""
        await self._save_entries()

    async def add_entry(
        self,
        name: str,
        description: str,
        action_types: Optional[List[str]] = None,
        resource_patterns: Optional[List[str]] = None,
        agent_ids: Optional[List[str]] = None,
        scope: AllowlistScope = AllowlistScope.GLOBAL,
        scope_value: Optional[str] = None,
        valid_from: Optional[str] = None,
        valid_until: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> AllowlistEntry:
        """Add an allowlist entry."""
        import hashlib

        entry_id = hashlib.sha256(
            f"{name}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:12]

        entry = AllowlistEntry(
            entry_id=entry_id,
            name=name,
            description=description,
            action_types=action_types or [],
            resource_patterns=resource_patterns or [],
            agent_ids=agent_ids or [],
            scope=scope.value,
            scope_value=scope_value,
            valid_from=valid_from,
            valid_until=valid_until,
            created_by=created_by,
        )

        async with self._lock:
            self._entries[entry_id] = entry

        await self._save_entries()
        logger.info(f"Added allowlist entry: {entry_id} ({name})")

        return entry

    async def remove_entry(self, entry_id: str) -> bool:
        """Remove an allowlist entry."""
        async with self._lock:
            if entry_id in self._entries:
                del self._entries[entry_id]
                await self._save_entries()
                return True
        return False

    async def check(
        self,
        action_type: str,
        resource: str,
        agent_id: str,
        session_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
    ) -> AllowlistMatch:
        """
        Check if action is allowlisted.

        Returns AllowlistMatch with result.
        """
        import fnmatch

        now = datetime.now(timezone.utc)

        async with self._lock:
            for entry in self._entries.values():
                if not entry.enabled:
                    continue

                # Check time validity
                if entry.valid_from:
                    valid_from = datetime.fromisoformat(
                        entry.valid_from.replace("Z", "+00:00")
                    )
                    if now < valid_from:
                        continue

                if entry.valid_until:
                    valid_until = datetime.fromisoformat(
                        entry.valid_until.replace("Z", "+00:00")
                    )
                    if now > valid_until:
                        continue

                # Check time of day
                if entry.time_of_day_start and entry.time_of_day_end:
                    current_time = now.strftime("%H:%M")
                    if not (
                        entry.time_of_day_start <= current_time <= entry.time_of_day_end
                    ):
                        continue

                # Check day of week
                if entry.days_of_week and now.weekday() not in entry.days_of_week:
                    continue

                # Check scope
                if entry.scope == AllowlistScope.SESSION.value:
                    if entry.scope_value != session_id:
                        continue
                elif entry.scope == AllowlistScope.WORKFLOW.value:
                    if entry.scope_value != workflow_id:
                        continue
                elif entry.scope == AllowlistScope.AGENT.value:
                    if entry.scope_value != agent_id:
                        continue

                # Check action type
                if entry.action_types and action_type not in entry.action_types:
                    continue

                # Check agent
                if entry.agent_ids and agent_id not in entry.agent_ids:
                    continue

                # Check resource pattern
                if entry.resource_patterns:
                    matched = False
                    for pattern in entry.resource_patterns:
                        if fnmatch.fnmatch(resource, pattern):
                            matched = True
                            break
                    if not matched:
                        continue

                # Match found
                entry.hit_count += 1
                entry.last_hit = now.isoformat()

                return AllowlistMatch(
                    allowed=True,
                    entry=entry,
                    reason=f"Matched allowlist: {entry.name}",
                )

        return AllowlistMatch(
            allowed=False,
            reason="No matching allowlist entry",
        )

    def list_entries(
        self,
        scope: Optional[AllowlistScope] = None,
        enabled_only: bool = False,
    ) -> List[AllowlistEntry]:
        """List all allowlist entries."""
        entries = list(self._entries.values())

        if scope:
            entries = [e for e in entries if e.scope == scope.value]

        if enabled_only:
            entries = [e for e in entries if e.enabled]

        return entries

    async def _load_entries(self):
        """Load entries from disk."""
        entries_file = self.data_dir / "allowlists.json"

        if entries_file.exists():
            try:
                async with aiofiles.open(entries_file, "r") as f:
                    content = await f.read()

                data = json.loads(content)

                for entry_data in data.get("entries", []):
                    entry = AllowlistEntry(**entry_data)
                    self._entries[entry.entry_id] = entry

                logger.info(f"Loaded {len(self._entries)} allowlist entries")

            except Exception as e:
                logger.error(f"Error loading allowlist entries: {e}")

    async def _save_entries(self):
        """Save entries to disk."""
        entries_file = self.data_dir / "allowlists.json"

        try:
            from dataclasses import asdict

            data = {
                "entries": [asdict(e) for e in self._entries.values()],
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }

            async with aiofiles.open(entries_file, "w") as f:
                await f.write(json.dumps(data, indent=2))

        except Exception as e:
            logger.error(f"Error saving allowlist entries: {e}")


# Singleton
_allowlist: Optional[ContextualAllowlist] = None


def get_contextual_allowlist() -> ContextualAllowlist:
    global _allowlist
    if _allowlist is None:
        _allowlist = ContextualAllowlist()
    return _allowlist


def create_allowlist_routes():
    """Create FastAPI routes for allowlists."""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
    from typing import Optional, List

    router = APIRouter(prefix="/api/v1/guard/allowlist", tags=["allowlist"])

    class AddEntryRequest(BaseModel):
        name: str
        description: str
        action_types: Optional[List[str]] = None
        resource_patterns: Optional[List[str]] = None
        agent_ids: Optional[List[str]] = None
        scope: str = "global"
        scope_value: Optional[str] = None
        valid_from: Optional[str] = None
        valid_until: Optional[str] = None

    class CheckRequest(BaseModel):
        action_type: str
        resource: str
        agent_id: str
        session_id: Optional[str] = None
        workflow_id: Optional[str] = None

    @router.post("/entries")
    async def add_entry(request: AddEntryRequest):
        """Add an allowlist entry."""
        allowlist = get_contextual_allowlist()

        try:
            scope = AllowlistScope(request.scope)
        except ValueError:
            raise HTTPException(400, f"Invalid scope: {request.scope}")

        entry = await allowlist.add_entry(
            name=request.name,
            description=request.description,
            action_types=request.action_types,
            resource_patterns=request.resource_patterns,
            agent_ids=request.agent_ids,
            scope=scope,
            scope_value=request.scope_value,
            valid_from=request.valid_from,
            valid_until=request.valid_until,
        )

        return {"entry_id": entry.entry_id, "created": True}

    @router.get("/entries")
    async def list_entries(scope: Optional[str] = None, enabled_only: bool = False):
        """List allowlist entries."""
        allowlist = get_contextual_allowlist()

        scope_enum = None
        if scope:
            try:
                scope_enum = AllowlistScope(scope)
            except ValueError:
                raise HTTPException(400, f"Invalid scope: {scope}")

        entries = allowlist.list_entries(scope=scope_enum, enabled_only=enabled_only)

        return {
            "entries": [
                {
                    "entry_id": e.entry_id,
                    "name": e.name,
                    "scope": e.scope,
                    "enabled": e.enabled,
                    "hit_count": e.hit_count,
                }
                for e in entries
            ]
        }

    @router.delete("/entries/{entry_id}")
    async def remove_entry(entry_id: str):
        """Remove an allowlist entry."""
        allowlist = get_contextual_allowlist()
        success = await allowlist.remove_entry(entry_id)

        if not success:
            raise HTTPException(404, f"Entry not found: {entry_id}")

        return {"entry_id": entry_id, "deleted": True}

    @router.post("/check")
    async def check_allowlist(request: CheckRequest):
        """Check if action is allowlisted."""
        allowlist = get_contextual_allowlist()

        match = await allowlist.check(
            action_type=request.action_type,
            resource=request.resource,
            agent_id=request.agent_id,
            session_id=request.session_id,
            workflow_id=request.workflow_id,
        )

        return {
            "allowed": match.allowed,
            "entry_id": match.entry.entry_id if match.entry else None,
            "entry_name": match.entry.name if match.entry else None,
            "reason": match.reason,
        }

    return router
