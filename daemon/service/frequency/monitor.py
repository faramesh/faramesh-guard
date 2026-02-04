"""
Frequency Monitor for Faramesh Guard.

Tracks approval/denial patterns and provides "approval memory" - automatically
suggesting or auto-approving actions that have been consistently approved.

Features:
- Tracks approval frequency per action pattern
- Learns from human decisions
- Suggests auto-approvals after threshold
- Time-based decay of learned patterns
- Context-aware pattern matching
"""

import asyncio
import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import aiofiles

logger = logging.getLogger(__name__)


class ApprovalSuggestionLevel(str, Enum):
    """Suggestion confidence levels."""

    HIGH = "high"  # Strong pattern, recommend auto-approve
    MEDIUM = "medium"  # Good pattern, suggest approve
    LOW = "low"  # Weak pattern, no suggestion
    NONE = "none"  # Insufficient data


class PatternType(str, Enum):
    """Types of tracked patterns."""

    ACTION_RESOURCE = "action_resource"  # Action type + resource
    ACTION_AGENT = "action_agent"  # Action type + agent
    FULL_CONTEXT = "full_context"  # Action + resource + agent
    COMMAND_PREFIX = "command_prefix"  # Command with same prefix
    PATH_PREFIX = "path_prefix"  # File path with same prefix


@dataclass
class ApprovalRecord:
    """Single approval/denial record."""

    pattern_hash: str
    action_type: str
    resource: str
    agent_id: str
    decision: str  # "allow" or "deny"
    decided_by: str  # "human" or "policy"
    timestamp: str
    session_id: Optional[str] = None
    context_hash: Optional[str] = None


@dataclass
class FrequencyPattern:
    """A tracked frequency pattern."""

    pattern_hash: str
    pattern_type: str

    # Pattern details
    action_type: str
    resource_pattern: Optional[str] = None
    agent_id: Optional[str] = None
    command_prefix: Optional[str] = None
    path_prefix: Optional[str] = None

    # Counters
    total_decisions: int = 0
    allow_count: int = 0
    deny_count: int = 0
    human_decisions: int = 0

    # Timestamps
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_allowed: Optional[str] = None
    last_denied: Optional[str] = None

    # Calculated metrics
    approval_rate: float = 0.0
    consistency_score: float = 0.0  # How consistent the decisions are

    # Auto-approval status
    auto_approve_eligible: bool = False
    auto_approve_enabled: bool = False
    auto_approve_until: Optional[str] = None


@dataclass
class ApprovalMemory:
    """Memory of approvals for a specific pattern."""

    pattern_hash: str
    approvals: List[ApprovalRecord] = field(default_factory=list)
    denials: List[ApprovalRecord] = field(default_factory=list)

    # Recent window
    recent_approvals: int = 0  # Last 24 hours
    recent_denials: int = 0

    # Streak tracking
    consecutive_approvals: int = 0
    consecutive_denials: int = 0

    def add_decision(self, record: ApprovalRecord, is_allow: bool):
        """Add a decision to memory."""
        if is_allow:
            self.approvals.append(record)
            self.consecutive_approvals += 1
            self.consecutive_denials = 0
        else:
            self.denials.append(record)
            self.consecutive_denials += 1
            self.consecutive_approvals = 0


@dataclass
class ApprovalSuggestion:
    """Suggestion based on approval history."""

    pattern_hash: str
    suggestion_level: str
    confidence: float

    # Recommendation
    recommend_auto_approve: bool
    recommend_auto_deny: bool

    # Evidence
    total_decisions: int
    approval_rate: float
    consecutive_approvals: int
    human_decision_count: int

    # Context
    similar_patterns: List[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class FrequencyStats:
    """Statistics for frequency monitoring."""

    total_patterns: int = 0
    active_patterns: int = 0  # Seen in last 24h

    auto_approve_eligible: int = 0
    auto_approve_enabled: int = 0

    total_decisions_tracked: int = 0
    human_decisions_tracked: int = 0

    avg_approval_rate: float = 0.0
    avg_consistency_score: float = 0.0

    auto_approved_count: int = 0
    suggested_approvals: int = 0


class FrequencyMonitor:
    """
    Monitors approval frequency and provides approval memory.

    Configuration thresholds:
    - auto_approve_threshold: Consecutive approvals needed for auto-approve eligibility
    - min_human_decisions: Minimum human decisions before suggestions
    - approval_rate_threshold: Minimum approval rate for suggestions
    - pattern_decay_days: Days after which patterns decay
    """

    def __init__(
        self,
        data_dir: str = "/var/lib/faramesh-guard/frequency",
        auto_approve_threshold: int = 5,
        min_human_decisions: int = 3,
        approval_rate_threshold: float = 0.95,
        pattern_decay_days: int = 30,
        auto_approve_duration_hours: int = 24,
        max_patterns: int = 10000,
    ):
        self.data_dir = Path(data_dir)
        self.auto_approve_threshold = auto_approve_threshold
        self.min_human_decisions = min_human_decisions
        self.approval_rate_threshold = approval_rate_threshold
        self.pattern_decay_days = pattern_decay_days
        self.auto_approve_duration_hours = auto_approve_duration_hours
        self.max_patterns = max_patterns

        # Pattern storage
        self._patterns: Dict[str, FrequencyPattern] = {}
        self._memory: Dict[str, ApprovalMemory] = {}
        self._patterns_lock = asyncio.Lock()

        # Statistics
        self._stats = FrequencyStats()

        # Running state
        self._running = False
        self._decay_task: Optional[asyncio.Task] = None
        self._save_task: Optional[asyncio.Task] = None

        logger.info(f"FrequencyMonitor initialized: threshold={auto_approve_threshold}")

    async def start(self):
        """Start the frequency monitor."""
        if self._running:
            return

        self._running = True
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Load saved patterns
        await self._load_patterns()

        # Start background tasks
        self._decay_task = asyncio.create_task(self._periodic_decay())
        self._save_task = asyncio.create_task(self._periodic_save())

        logger.info("FrequencyMonitor started")

    async def stop(self):
        """Stop the monitor."""
        self._running = False

        for task in [self._decay_task, self._save_task]:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Final save
        await self._save_patterns()

        logger.info("FrequencyMonitor stopped")

    def _generate_pattern_hash(
        self,
        pattern_type: PatternType,
        action_type: str,
        resource: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> str:
        """Generate a unique hash for a pattern."""
        components = [pattern_type.value, action_type]

        if resource:
            components.append(resource)
        if agent_id:
            components.append(agent_id)

        return hashlib.sha256(":".join(components).encode()).hexdigest()[:16]

    def _extract_patterns(
        self,
        action_type: str,
        resource: str,
        agent_id: str,
    ) -> List[Tuple[str, PatternType, Dict[str, Any]]]:
        """Extract all patterns from a request."""
        patterns = []

        # Full context pattern
        full_hash = self._generate_pattern_hash(
            PatternType.FULL_CONTEXT, action_type, resource, agent_id
        )
        patterns.append(
            (
                full_hash,
                PatternType.FULL_CONTEXT,
                {
                    "action_type": action_type,
                    "resource_pattern": resource,
                    "agent_id": agent_id,
                },
            )
        )

        # Action + resource pattern
        ar_hash = self._generate_pattern_hash(
            PatternType.ACTION_RESOURCE, action_type, resource
        )
        patterns.append(
            (
                ar_hash,
                PatternType.ACTION_RESOURCE,
                {
                    "action_type": action_type,
                    "resource_pattern": resource,
                },
            )
        )

        # Action + agent pattern
        aa_hash = self._generate_pattern_hash(
            PatternType.ACTION_AGENT, action_type, agent_id=agent_id
        )
        patterns.append(
            (
                aa_hash,
                PatternType.ACTION_AGENT,
                {
                    "action_type": action_type,
                    "agent_id": agent_id,
                },
            )
        )

        # Path prefix pattern (for file operations)
        if action_type in ["read_file", "write_file", "delete_file"]:
            # Extract directory prefix
            parts = resource.rsplit("/", 1)
            if len(parts) > 1:
                prefix = parts[0]
                pp_hash = self._generate_pattern_hash(
                    PatternType.PATH_PREFIX, action_type, prefix
                )
                patterns.append(
                    (
                        pp_hash,
                        PatternType.PATH_PREFIX,
                        {
                            "action_type": action_type,
                            "path_prefix": prefix,
                        },
                    )
                )

        # Command prefix pattern (for shell commands)
        if action_type == "exec_command":
            # Extract command prefix (first word)
            cmd_prefix = resource.split()[0] if resource else ""
            if cmd_prefix:
                cp_hash = self._generate_pattern_hash(
                    PatternType.COMMAND_PREFIX, action_type, cmd_prefix
                )
                patterns.append(
                    (
                        cp_hash,
                        PatternType.COMMAND_PREFIX,
                        {
                            "action_type": action_type,
                            "command_prefix": cmd_prefix,
                        },
                    )
                )

        return patterns

    async def record_decision(
        self,
        action_type: str,
        resource: str,
        agent_id: str,
        decision: str,
        decided_by: str,
        session_id: Optional[str] = None,
    ) -> List[FrequencyPattern]:
        """
        Record a decision for frequency tracking.

        Args:
            action_type: Type of action
            resource: Resource being accessed
            agent_id: Agent making the request
            decision: "allow" or "deny"
            decided_by: "human" or "policy"
            session_id: Optional session identifier

        Returns:
            Updated patterns
        """
        is_allow = decision == "allow"
        is_human = decided_by == "human"
        timestamp = datetime.now(timezone.utc).isoformat()

        patterns = self._extract_patterns(action_type, resource, agent_id)
        updated_patterns = []

        async with self._patterns_lock:
            for pattern_hash, pattern_type, pattern_details in patterns:
                # Get or create pattern
                if pattern_hash not in self._patterns:
                    self._patterns[pattern_hash] = FrequencyPattern(
                        pattern_hash=pattern_hash,
                        pattern_type=pattern_type.value,
                        **pattern_details,
                    )
                    self._memory[pattern_hash] = ApprovalMemory(
                        pattern_hash=pattern_hash
                    )

                pattern = self._patterns[pattern_hash]
                memory = self._memory[pattern_hash]

                # Create record
                record = ApprovalRecord(
                    pattern_hash=pattern_hash,
                    action_type=action_type,
                    resource=resource,
                    agent_id=agent_id,
                    decision=decision,
                    decided_by=decided_by,
                    timestamp=timestamp,
                    session_id=session_id,
                )

                # Update counters
                pattern.total_decisions += 1
                if is_allow:
                    pattern.allow_count += 1
                    pattern.last_allowed = timestamp
                else:
                    pattern.deny_count += 1
                    pattern.last_denied = timestamp

                if is_human:
                    pattern.human_decisions += 1

                pattern.last_seen = timestamp

                # Update memory
                memory.add_decision(record, is_allow)

                # Calculate metrics
                self._update_pattern_metrics(pattern, memory)

                updated_patterns.append(pattern)

        # Update stats
        self._stats.total_decisions_tracked += 1
        if is_human:
            self._stats.human_decisions_tracked += 1

        return updated_patterns

    def _update_pattern_metrics(
        self, pattern: FrequencyPattern, memory: ApprovalMemory
    ):
        """Update calculated metrics for a pattern."""
        if pattern.total_decisions > 0:
            pattern.approval_rate = pattern.allow_count / pattern.total_decisions

        # Consistency score: How consistently is one decision made?
        if pattern.total_decisions >= 2:
            max_streak = max(memory.consecutive_approvals, memory.consecutive_denials)
            pattern.consistency_score = max_streak / pattern.total_decisions

        # Auto-approve eligibility
        pattern.auto_approve_eligible = (
            pattern.human_decisions >= self.min_human_decisions
            and pattern.approval_rate >= self.approval_rate_threshold
            and memory.consecutive_approvals >= self.auto_approve_threshold
        )

    async def get_suggestion(
        self,
        action_type: str,
        resource: str,
        agent_id: str,
    ) -> ApprovalSuggestion:
        """
        Get approval suggestion based on history.

        Args:
            action_type: Type of action
            resource: Resource being accessed
            agent_id: Agent making the request

        Returns:
            ApprovalSuggestion with recommendation
        """
        patterns = self._extract_patterns(action_type, resource, agent_id)

        best_suggestion = None
        best_confidence = 0.0
        similar_patterns = []

        async with self._patterns_lock:
            for pattern_hash, pattern_type, _ in patterns:
                if pattern_hash not in self._patterns:
                    continue

                pattern = self._patterns[pattern_hash]
                memory = self._memory[pattern_hash]

                similar_patterns.append(pattern_hash)

                # Calculate confidence
                confidence = self._calculate_confidence(pattern, memory)

                if confidence > best_confidence:
                    best_confidence = confidence
                    best_suggestion = self._create_suggestion(
                        pattern, memory, confidence, similar_patterns
                    )

        if not best_suggestion:
            return ApprovalSuggestion(
                pattern_hash="none",
                suggestion_level=ApprovalSuggestionLevel.NONE.value,
                confidence=0.0,
                recommend_auto_approve=False,
                recommend_auto_deny=False,
                total_decisions=0,
                approval_rate=0.0,
                consecutive_approvals=0,
                human_decision_count=0,
                reason="No matching patterns found",
            )

        return best_suggestion

    def _calculate_confidence(
        self,
        pattern: FrequencyPattern,
        memory: ApprovalMemory,
    ) -> float:
        """Calculate confidence score for a pattern."""
        if pattern.total_decisions == 0:
            return 0.0

        # Base confidence from approval rate
        base_confidence = pattern.approval_rate

        # Boost from human decisions
        human_boost = min(pattern.human_decisions / 10, 0.3)

        # Boost from consistency
        consistency_boost = pattern.consistency_score * 0.2

        # Boost from consecutive approvals
        streak_boost = min(
            memory.consecutive_approvals / self.auto_approve_threshold, 0.2
        )

        # Penalty for recency (if not seen recently)
        try:
            last_seen = datetime.fromisoformat(pattern.last_seen.replace("Z", "+00:00"))
            days_since = (datetime.now(timezone.utc) - last_seen).days
            recency_penalty = min(days_since / self.pattern_decay_days, 0.3)
        except Exception:
            recency_penalty = 0.0

        confidence = (
            base_confidence
            + human_boost
            + consistency_boost
            + streak_boost
            - recency_penalty
        )

        return max(0.0, min(1.0, confidence))

    def _create_suggestion(
        self,
        pattern: FrequencyPattern,
        memory: ApprovalMemory,
        confidence: float,
        similar_patterns: List[str],
    ) -> ApprovalSuggestion:
        """Create an approval suggestion."""
        # Determine level
        if confidence >= 0.9 and pattern.auto_approve_eligible:
            level = ApprovalSuggestionLevel.HIGH
            recommend_approve = True
            reason = f"High confidence ({confidence:.0%}) with {memory.consecutive_approvals} consecutive approvals"
        elif confidence >= 0.7:
            level = ApprovalSuggestionLevel.MEDIUM
            recommend_approve = pattern.approval_rate >= 0.8
            reason = f"Medium confidence ({confidence:.0%}) based on {pattern.total_decisions} decisions"
        elif confidence >= 0.5:
            level = ApprovalSuggestionLevel.LOW
            recommend_approve = False
            reason = f"Low confidence ({confidence:.0%}), more data needed"
        else:
            level = ApprovalSuggestionLevel.NONE
            recommend_approve = False
            reason = "Insufficient pattern data"

        # Check for deny pattern
        recommend_deny = (
            pattern.total_decisions >= self.min_human_decisions
            and pattern.approval_rate <= 0.1
            and memory.consecutive_denials >= 3
        )

        if recommend_deny:
            reason = f"Consistently denied ({pattern.deny_count} denials)"

        return ApprovalSuggestion(
            pattern_hash=pattern.pattern_hash,
            suggestion_level=level.value,
            confidence=confidence,
            recommend_auto_approve=recommend_approve and not recommend_deny,
            recommend_auto_deny=recommend_deny,
            total_decisions=pattern.total_decisions,
            approval_rate=pattern.approval_rate,
            consecutive_approvals=memory.consecutive_approvals,
            human_decision_count=pattern.human_decisions,
            similar_patterns=similar_patterns,
            reason=reason,
        )

    async def enable_auto_approve(
        self,
        pattern_hash: str,
        duration_hours: Optional[int] = None,
    ) -> bool:
        """
        Enable auto-approve for a pattern.

        Args:
            pattern_hash: Pattern to enable
            duration_hours: How long to enable (None = use default)

        Returns:
            True if enabled
        """
        duration = duration_hours or self.auto_approve_duration_hours

        async with self._patterns_lock:
            if pattern_hash not in self._patterns:
                return False

            pattern = self._patterns[pattern_hash]

            if not pattern.auto_approve_eligible:
                logger.warning(f"Pattern {pattern_hash} not eligible for auto-approve")
                return False

            pattern.auto_approve_enabled = True
            pattern.auto_approve_until = (
                datetime.now(timezone.utc) + timedelta(hours=duration)
            ).isoformat()

            logger.info(
                f"Auto-approve enabled for pattern {pattern_hash} for {duration}h"
            )

            self._stats.auto_approve_enabled += 1

        return True

    async def disable_auto_approve(self, pattern_hash: str) -> bool:
        """Disable auto-approve for a pattern."""
        async with self._patterns_lock:
            if pattern_hash not in self._patterns:
                return False

            pattern = self._patterns[pattern_hash]
            pattern.auto_approve_enabled = False
            pattern.auto_approve_until = None

            logger.info(f"Auto-approve disabled for pattern {pattern_hash}")

            self._stats.auto_approve_enabled -= 1

        return True

    async def should_auto_approve(
        self,
        action_type: str,
        resource: str,
        agent_id: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a request should be auto-approved.

        Returns:
            (should_auto_approve, pattern_hash that matched)
        """
        patterns = self._extract_patterns(action_type, resource, agent_id)
        now = datetime.now(timezone.utc)

        async with self._patterns_lock:
            for pattern_hash, _, _ in patterns:
                if pattern_hash not in self._patterns:
                    continue

                pattern = self._patterns[pattern_hash]

                if not pattern.auto_approve_enabled:
                    continue

                # Check expiration
                if pattern.auto_approve_until:
                    try:
                        until = datetime.fromisoformat(
                            pattern.auto_approve_until.replace("Z", "+00:00")
                        )
                        if now > until:
                            pattern.auto_approve_enabled = False
                            pattern.auto_approve_until = None
                            continue
                    except Exception:
                        continue

                self._stats.auto_approved_count += 1
                return True, pattern_hash

        return False, None

    def get_stats(self) -> FrequencyStats:
        """Get frequency monitoring statistics."""
        # Update counts
        self._stats.total_patterns = len(self._patterns)

        # Count active and eligible
        now = datetime.now(timezone.utc)
        active = 0
        eligible = 0
        enabled = 0
        total_rate = 0.0
        total_consistency = 0.0

        for pattern in self._patterns.values():
            try:
                last_seen = datetime.fromisoformat(
                    pattern.last_seen.replace("Z", "+00:00")
                )
                if (now - last_seen).days <= 1:
                    active += 1
            except Exception:
                pass

            if pattern.auto_approve_eligible:
                eligible += 1
            if pattern.auto_approve_enabled:
                enabled += 1

            total_rate += pattern.approval_rate
            total_consistency += pattern.consistency_score

        self._stats.active_patterns = active
        self._stats.auto_approve_eligible = eligible
        self._stats.auto_approve_enabled = enabled

        if self._stats.total_patterns > 0:
            self._stats.avg_approval_rate = total_rate / self._stats.total_patterns
            self._stats.avg_consistency_score = (
                total_consistency / self._stats.total_patterns
            )

        return self._stats

    def get_patterns(
        self,
        eligible_only: bool = False,
        enabled_only: bool = False,
        limit: int = 100,
    ) -> List[FrequencyPattern]:
        """Get tracked patterns."""
        patterns = list(self._patterns.values())

        if eligible_only:
            patterns = [p for p in patterns if p.auto_approve_eligible]
        if enabled_only:
            patterns = [p for p in patterns if p.auto_approve_enabled]

        # Sort by total decisions (most frequent first)
        patterns.sort(key=lambda p: p.total_decisions, reverse=True)

        return patterns[:limit]

    async def _periodic_decay(self):
        """Periodically decay old patterns."""
        while self._running:
            try:
                await asyncio.sleep(86400)  # Daily

                cutoff = datetime.now(timezone.utc) - timedelta(
                    days=self.pattern_decay_days
                )
                cutoff_str = cutoff.isoformat()

                to_remove = []

                async with self._patterns_lock:
                    for pattern_hash, pattern in self._patterns.items():
                        if pattern.last_seen < cutoff_str:
                            to_remove.append(pattern_hash)

                    for pattern_hash in to_remove:
                        del self._patterns[pattern_hash]
                        if pattern_hash in self._memory:
                            del self._memory[pattern_hash]

                if to_remove:
                    logger.info(f"Decayed {len(to_remove)} old patterns")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Pattern decay error: {e}")

    async def _periodic_save(self):
        """Periodically save patterns to disk."""
        while self._running:
            try:
                await asyncio.sleep(300)  # Every 5 minutes
                await self._save_patterns()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Pattern save error: {e}")

    async def _load_patterns(self):
        """Load patterns from disk."""
        patterns_file = self.data_dir / "patterns.json"

        if patterns_file.exists():
            try:
                async with aiofiles.open(patterns_file, "r") as f:
                    content = await f.read()

                data = json.loads(content)

                for pattern_data in data.get("patterns", []):
                    pattern = FrequencyPattern(**pattern_data)
                    self._patterns[pattern.pattern_hash] = pattern
                    self._memory[pattern.pattern_hash] = ApprovalMemory(
                        pattern_hash=pattern.pattern_hash
                    )

                logger.info(f"Loaded {len(self._patterns)} patterns")

            except Exception as e:
                logger.error(f"Error loading patterns: {e}")

    async def _save_patterns(self):
        """Save patterns to disk."""
        patterns_file = self.data_dir / "patterns.json"

        try:
            from dataclasses import asdict

            async with self._patterns_lock:
                data = {
                    "patterns": [asdict(p) for p in self._patterns.values()],
                    "saved_at": datetime.now(timezone.utc).isoformat(),
                }

            async with aiofiles.open(patterns_file, "w") as f:
                await f.write(json.dumps(data, indent=2))

        except Exception as e:
            logger.error(f"Error saving patterns: {e}")


# =============================================================================
# Singleton instance
# =============================================================================

_frequency_monitor: Optional[FrequencyMonitor] = None


def get_frequency_monitor() -> FrequencyMonitor:
    """Get the singleton frequency monitor instance."""
    global _frequency_monitor
    if _frequency_monitor is None:
        _frequency_monitor = FrequencyMonitor()
    return _frequency_monitor


# =============================================================================
# FastAPI Routes
# =============================================================================


def create_frequency_routes():
    """Create FastAPI routes for frequency monitoring."""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
    from typing import Optional

    router = APIRouter(prefix="/api/v1/guard/frequency", tags=["frequency"])

    class RecordDecisionRequest(BaseModel):
        action_type: str
        resource: str
        agent_id: str
        decision: str
        decided_by: str
        session_id: Optional[str] = None

    class GetSuggestionRequest(BaseModel):
        action_type: str
        resource: str
        agent_id: str

    class AutoApproveRequest(BaseModel):
        pattern_hash: str
        duration_hours: Optional[int] = None

    @router.post("/record")
    async def record_decision(request: RecordDecisionRequest):
        """Record a decision for frequency tracking."""
        monitor = get_frequency_monitor()
        patterns = await monitor.record_decision(
            action_type=request.action_type,
            resource=request.resource,
            agent_id=request.agent_id,
            decision=request.decision,
            decided_by=request.decided_by,
            session_id=request.session_id,
        )
        return {
            "recorded": True,
            "patterns_updated": len(patterns),
        }

    @router.post("/suggestion")
    async def get_suggestion(request: GetSuggestionRequest):
        """Get approval suggestion based on history."""
        monitor = get_frequency_monitor()
        suggestion = await monitor.get_suggestion(
            action_type=request.action_type,
            resource=request.resource,
            agent_id=request.agent_id,
        )
        return {
            "pattern_hash": suggestion.pattern_hash,
            "level": suggestion.suggestion_level,
            "confidence": suggestion.confidence,
            "recommend_auto_approve": suggestion.recommend_auto_approve,
            "recommend_auto_deny": suggestion.recommend_auto_deny,
            "total_decisions": suggestion.total_decisions,
            "approval_rate": suggestion.approval_rate,
            "reason": suggestion.reason,
        }

    @router.post("/check-auto-approve")
    async def check_auto_approve(request: GetSuggestionRequest):
        """Check if a request should be auto-approved."""
        monitor = get_frequency_monitor()
        should_approve, pattern_hash = await monitor.should_auto_approve(
            action_type=request.action_type,
            resource=request.resource,
            agent_id=request.agent_id,
        )
        return {
            "auto_approve": should_approve,
            "pattern_hash": pattern_hash,
        }

    @router.post("/auto-approve/enable")
    async def enable_auto_approve(request: AutoApproveRequest):
        """Enable auto-approve for a pattern."""
        monitor = get_frequency_monitor()
        success = await monitor.enable_auto_approve(
            pattern_hash=request.pattern_hash,
            duration_hours=request.duration_hours,
        )
        if not success:
            raise HTTPException(400, "Pattern not found or not eligible")
        return {"enabled": True, "pattern_hash": request.pattern_hash}

    @router.post("/auto-approve/disable")
    async def disable_auto_approve(pattern_hash: str):
        """Disable auto-approve for a pattern."""
        monitor = get_frequency_monitor()
        success = await monitor.disable_auto_approve(pattern_hash)
        if not success:
            raise HTTPException(404, f"Pattern not found: {pattern_hash}")
        return {"disabled": True, "pattern_hash": pattern_hash}

    @router.get("/stats")
    async def get_stats():
        """Get frequency monitoring statistics."""
        monitor = get_frequency_monitor()
        stats = monitor.get_stats()
        return {
            "total_patterns": stats.total_patterns,
            "active_patterns": stats.active_patterns,
            "auto_approve_eligible": stats.auto_approve_eligible,
            "auto_approve_enabled": stats.auto_approve_enabled,
            "total_decisions_tracked": stats.total_decisions_tracked,
            "auto_approved_count": stats.auto_approved_count,
            "avg_approval_rate": stats.avg_approval_rate,
        }

    @router.get("/patterns")
    async def get_patterns(
        eligible_only: bool = False,
        enabled_only: bool = False,
        limit: int = 100,
    ):
        """Get tracked patterns."""
        monitor = get_frequency_monitor()
        patterns = monitor.get_patterns(
            eligible_only=eligible_only,
            enabled_only=enabled_only,
            limit=limit,
        )
        return {
            "patterns": [
                {
                    "pattern_hash": p.pattern_hash,
                    "pattern_type": p.pattern_type,
                    "action_type": p.action_type,
                    "total_decisions": p.total_decisions,
                    "approval_rate": p.approval_rate,
                    "auto_approve_eligible": p.auto_approve_eligible,
                    "auto_approve_enabled": p.auto_approve_enabled,
                }
                for p in patterns
            ]
        }

    return router
