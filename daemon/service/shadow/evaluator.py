"""
Shadow Mode Evaluator for Faramesh Guard.

Evaluates requests against shadow policies without affecting production
decisions. Useful for:
- Testing new policies before deployment
- A/B testing policy changes
- Comparing policy versions
- Evaluating policy model updates

Shadow mode records what WOULD have happened, enabling safe experimentation.
"""

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Tuple
import aiofiles

logger = logging.getLogger(__name__)


class ShadowDecision(str, Enum):
    """Shadow evaluation decisions."""

    ALLOW = "allow"
    DENY = "deny"
    PROMPT = "prompt"
    ERROR = "error"


class ComparisonResult(str, Enum):
    """Result of comparing shadow to production."""

    MATCH = "match"  # Same decision
    FALSE_POSITIVE = "fp"  # Shadow blocked, prod allowed
    FALSE_NEGATIVE = "fn"  # Shadow allowed, prod blocked
    DIFFERENT_PROMPT = "dp"  # Different prompt behavior
    ERROR = "error"


@dataclass
class ShadowResult:
    """Result from shadow policy evaluation."""

    request_id: str
    shadow_policy_id: str
    shadow_decision: str
    shadow_reason: Optional[str]
    evaluation_time_ms: float

    # Matched rules
    matched_rules: List[str] = field(default_factory=list)
    rule_scores: Dict[str, float] = field(default_factory=dict)

    # Context
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    error: Optional[str] = None


@dataclass
class ShadowComparison:
    """Comparison between shadow and production decisions."""

    request_id: str

    # Production
    prod_decision: str
    prod_policy_id: str
    prod_reason: Optional[str]

    # Shadow
    shadow_decision: str
    shadow_policy_id: str
    shadow_reason: Optional[str]

    # Comparison
    comparison_result: str
    difference_severity: str  # low, medium, high, critical

    # Context
    action_type: str
    resource: str
    agent_id: str

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class ShadowStats:
    """Statistics for shadow mode evaluation."""

    total_evaluations: int = 0

    # By comparison result
    matches: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    different_prompts: int = 0
    errors: int = 0

    # Rates
    match_rate: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0

    # By shadow policy
    by_policy: Dict[str, Dict[str, int]] = field(default_factory=dict)

    # Timing
    avg_evaluation_time_ms: float = 0.0
    total_evaluation_time_ms: float = 0.0

    # Time range
    oldest_evaluation: Optional[str] = None
    newest_evaluation: Optional[str] = None


@dataclass
class ShadowPolicy:
    """A shadow policy configuration."""

    policy_id: str
    name: str
    description: str

    # Policy rules (simplified - in production would load from policy engine)
    rules: List[Dict[str, Any]] = field(default_factory=list)

    # Sampling
    sample_rate: float = 1.0  # 0.0 - 1.0

    # Targeting
    target_actions: Optional[List[str]] = None  # None = all
    target_agents: Optional[List[str]] = None

    # Status
    enabled: bool = True
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Comparison settings
    compare_to_prod: bool = True
    alert_on_difference: bool = False


class ShadowModeEvaluator:
    """
    Evaluates requests against shadow policies without affecting production.

    Features:
    - Multiple shadow policies can run simultaneously
    - Configurable sampling rates
    - Action/agent targeting
    - Detailed comparison with production decisions
    - False positive/negative tracking
    - Alert on significant differences
    """

    def __init__(
        self,
        data_dir: str = "/var/lib/faramesh-guard/shadow",
        max_history: int = 10000,
        retention_hours: int = 168,  # 1 week
    ):
        self.data_dir = Path(data_dir)
        self.max_history = max_history
        self.retention_hours = retention_hours

        # Shadow policies
        self._policies: Dict[str, ShadowPolicy] = {}
        self._policies_lock = asyncio.Lock()

        # Results history
        self._results: List[ShadowResult] = []
        self._comparisons: List[ShadowComparison] = []
        self._history_lock = asyncio.Lock()

        # Statistics
        self._stats = ShadowStats()
        self._stats_by_policy: Dict[str, ShadowStats] = {}

        # Callbacks
        self._on_difference_callbacks: List[Callable[[ShadowComparison], None]] = []

        # Running state
        self._running = False
        self._cleanup_task: Optional[asyncio.Task] = None

        logger.info(f"ShadowModeEvaluator initialized: dir={data_dir}")

    async def start(self):
        """Start the shadow mode evaluator."""
        if self._running:
            return

        self._running = True
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Load saved policies
        await self._load_policies()

        # Start cleanup task
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())

        logger.info("ShadowModeEvaluator started")

    async def stop(self):
        """Stop the evaluator."""
        self._running = False

        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Save policies
        await self._save_policies()

        logger.info("ShadowModeEvaluator stopped")

    async def add_shadow_policy(
        self,
        policy_id: str,
        name: str,
        description: str,
        rules: List[Dict[str, Any]],
        sample_rate: float = 1.0,
        target_actions: Optional[List[str]] = None,
        target_agents: Optional[List[str]] = None,
    ) -> ShadowPolicy:
        """
        Add a shadow policy for evaluation.

        Args:
            policy_id: Unique identifier for the policy
            name: Human-readable name
            description: Policy description
            rules: List of policy rules
            sample_rate: Fraction of requests to evaluate (0.0-1.0)
            target_actions: Specific action types to target (None = all)
            target_agents: Specific agents to target (None = all)

        Returns:
            The created ShadowPolicy
        """
        policy = ShadowPolicy(
            policy_id=policy_id,
            name=name,
            description=description,
            rules=rules,
            sample_rate=sample_rate,
            target_actions=target_actions,
            target_agents=target_agents,
        )

        async with self._policies_lock:
            self._policies[policy_id] = policy

        # Initialize stats for this policy
        self._stats_by_policy[policy_id] = ShadowStats()

        logger.info(f"Added shadow policy: {policy_id} ({name})")

        await self._save_policies()

        return policy

    async def remove_shadow_policy(self, policy_id: str) -> bool:
        """Remove a shadow policy."""
        async with self._policies_lock:
            if policy_id in self._policies:
                del self._policies[policy_id]
                logger.info(f"Removed shadow policy: {policy_id}")
                await self._save_policies()
                return True
        return False

    async def enable_policy(self, policy_id: str, enabled: bool = True) -> bool:
        """Enable or disable a shadow policy."""
        async with self._policies_lock:
            if policy_id in self._policies:
                self._policies[policy_id].enabled = enabled
                logger.info(f"Shadow policy {policy_id} enabled={enabled}")
                return True
        return False

    def get_policies(self) -> List[ShadowPolicy]:
        """Get all shadow policies."""
        return list(self._policies.values())

    async def evaluate(
        self,
        request_id: str,
        action_type: str,
        resource: str,
        agent_id: str,
        context: Dict[str, Any],
        prod_decision: Optional[str] = None,
        prod_policy_id: Optional[str] = None,
        prod_reason: Optional[str] = None,
    ) -> List[ShadowResult]:
        """
        Evaluate a request against all applicable shadow policies.

        Args:
            request_id: Unique request identifier
            action_type: Type of action (write_file, exec_command, etc.)
            resource: Resource being accessed
            agent_id: ID of the agent
            context: Additional context for evaluation
            prod_decision: Production decision (for comparison)
            prod_policy_id: Production policy ID
            prod_reason: Production decision reason

        Returns:
            List of ShadowResult from each applicable policy
        """
        import random

        results = []

        async with self._policies_lock:
            policies = [p for p in self._policies.values() if p.enabled]

        for policy in policies:
            # Check targeting
            if policy.target_actions and action_type not in policy.target_actions:
                continue
            if policy.target_agents and agent_id not in policy.target_agents:
                continue

            # Check sampling
            if random.random() > policy.sample_rate:
                continue

            # Evaluate against this policy
            start_time = datetime.now(timezone.utc)

            try:
                decision, reason, matched_rules, scores = await self._evaluate_policy(
                    policy, action_type, resource, agent_id, context
                )

                eval_time = (
                    datetime.now(timezone.utc) - start_time
                ).total_seconds() * 1000

                result = ShadowResult(
                    request_id=request_id,
                    shadow_policy_id=policy.policy_id,
                    shadow_decision=decision,
                    shadow_reason=reason,
                    evaluation_time_ms=eval_time,
                    matched_rules=matched_rules,
                    rule_scores=scores,
                )

            except Exception as e:
                logger.error(
                    f"Shadow evaluation error for policy {policy.policy_id}: {e}"
                )
                result = ShadowResult(
                    request_id=request_id,
                    shadow_policy_id=policy.policy_id,
                    shadow_decision=ShadowDecision.ERROR.value,
                    shadow_reason=None,
                    evaluation_time_ms=0,
                    error=str(e),
                )

            results.append(result)

            # Compare with production if available
            if policy.compare_to_prod and prod_decision:
                comparison = self._compare_decisions(
                    request_id=request_id,
                    action_type=action_type,
                    resource=resource,
                    agent_id=agent_id,
                    prod_decision=prod_decision,
                    prod_policy_id=prod_policy_id or "unknown",
                    prod_reason=prod_reason,
                    shadow_decision=result.shadow_decision,
                    shadow_policy_id=policy.policy_id,
                    shadow_reason=result.shadow_reason,
                )

                # Update stats
                await self._record_comparison(comparison, policy.policy_id)

                # Alert on difference if configured
                if (
                    policy.alert_on_difference
                    and comparison.comparison_result != ComparisonResult.MATCH.value
                ):
                    for callback in self._on_difference_callbacks:
                        try:
                            callback(comparison)
                        except Exception as e:
                            logger.warning(f"Difference callback error: {e}")

            # Update result stats
            await self._record_result(result, policy.policy_id)

        return results

    async def _evaluate_policy(
        self,
        policy: ShadowPolicy,
        action_type: str,
        resource: str,
        agent_id: str,
        context: Dict[str, Any],
    ) -> Tuple[str, Optional[str], List[str], Dict[str, float]]:
        """
        Evaluate a single shadow policy.

        Returns:
            (decision, reason, matched_rules, rule_scores)
        """
        matched_rules = []
        rule_scores = {}

        # Evaluate each rule
        for rule in policy.rules:
            rule_id = rule.get("id", "unknown")

            # Check if rule matches
            matches, score = self._evaluate_rule(
                rule, action_type, resource, agent_id, context
            )

            if matches:
                matched_rules.append(rule_id)
                rule_scores[rule_id] = score

        # Determine decision based on matched rules
        if not matched_rules:
            return ShadowDecision.ALLOW.value, "No rules matched", [], {}

        # Find highest priority matched rule
        highest_priority_rule = None
        highest_priority = -1

        for rule in policy.rules:
            if rule.get("id") in matched_rules:
                priority = rule.get("priority", 0)
                if priority > highest_priority:
                    highest_priority = priority
                    highest_priority_rule = rule

        if highest_priority_rule:
            decision = highest_priority_rule.get(
                "decision", ShadowDecision.PROMPT.value
            )
            reason = highest_priority_rule.get(
                "reason", f"Rule {highest_priority_rule.get('id')} matched"
            )
            return decision, reason, matched_rules, rule_scores

        return (
            ShadowDecision.PROMPT.value,
            "Default decision",
            matched_rules,
            rule_scores,
        )

    def _evaluate_rule(
        self,
        rule: Dict[str, Any],
        action_type: str,
        resource: str,
        agent_id: str,
        context: Dict[str, Any],
    ) -> Tuple[bool, float]:
        """
        Evaluate a single rule against the request.

        Returns:
            (matches, confidence_score)
        """
        import re

        conditions = rule.get("conditions", {})
        score = 1.0

        # Check action type
        if "action_type" in conditions:
            pattern = conditions["action_type"]
            if isinstance(pattern, str):
                if pattern != "*" and not re.match(pattern, action_type):
                    return False, 0.0
            elif isinstance(pattern, list):
                if action_type not in pattern:
                    return False, 0.0

        # Check resource pattern
        if "resource" in conditions:
            pattern = conditions["resource"]
            if isinstance(pattern, str):
                if pattern != "*" and not re.search(pattern, resource):
                    return False, 0.0

        # Check agent
        if "agent" in conditions:
            pattern = conditions["agent"]
            if isinstance(pattern, str):
                if pattern != "*" and pattern != agent_id:
                    return False, 0.0
            elif isinstance(pattern, list):
                if agent_id not in pattern:
                    return False, 0.0

        # Check context conditions
        for key, expected in conditions.items():
            if key in ["action_type", "resource", "agent"]:
                continue

            actual = context.get(key)
            if actual is None:
                score *= 0.8  # Reduce confidence if context missing
                continue

            if actual != expected:
                return False, 0.0

        return True, score

    def _compare_decisions(
        self,
        request_id: str,
        action_type: str,
        resource: str,
        agent_id: str,
        prod_decision: str,
        prod_policy_id: str,
        prod_reason: Optional[str],
        shadow_decision: str,
        shadow_policy_id: str,
        shadow_reason: Optional[str],
    ) -> ShadowComparison:
        """Compare shadow and production decisions."""
        # Determine comparison result
        if shadow_decision == prod_decision:
            result = ComparisonResult.MATCH
            severity = "low"
        elif shadow_decision == ShadowDecision.DENY.value and prod_decision in [
            "allow",
            "prompt",
        ]:
            result = ComparisonResult.FALSE_POSITIVE
            severity = "medium"
        elif shadow_decision in ["allow", "prompt"] and prod_decision == "deny":
            result = ComparisonResult.FALSE_NEGATIVE
            severity = "high"
        elif (
            shadow_decision == ShadowDecision.PROMPT.value or prod_decision == "prompt"
        ):
            result = ComparisonResult.DIFFERENT_PROMPT
            severity = "low"
        else:
            result = ComparisonResult.ERROR
            severity = "medium"

        # Adjust severity based on action type
        sensitive_actions = ["exec_command", "delete_file", "api_call", "write_file"]
        if action_type in sensitive_actions and result != ComparisonResult.MATCH:
            if severity == "medium":
                severity = "high"
            elif severity == "low":
                severity = "medium"

        return ShadowComparison(
            request_id=request_id,
            prod_decision=prod_decision,
            prod_policy_id=prod_policy_id,
            prod_reason=prod_reason,
            shadow_decision=shadow_decision,
            shadow_policy_id=shadow_policy_id,
            shadow_reason=shadow_reason,
            comparison_result=result.value,
            difference_severity=severity,
            action_type=action_type,
            resource=resource,
            agent_id=agent_id,
        )

    async def _record_result(self, result: ShadowResult, policy_id: str):
        """Record a shadow evaluation result."""
        async with self._history_lock:
            self._results.append(result)

            # Trim history
            if len(self._results) > self.max_history:
                self._results = self._results[-self.max_history :]

        # Update stats
        self._stats.total_evaluations += 1
        self._stats.total_evaluation_time_ms += result.evaluation_time_ms
        self._stats.avg_evaluation_time_ms = (
            self._stats.total_evaluation_time_ms / self._stats.total_evaluations
        )

        if not self._stats.oldest_evaluation:
            self._stats.oldest_evaluation = result.timestamp
        self._stats.newest_evaluation = result.timestamp

        # Policy-specific stats
        if policy_id not in self._stats_by_policy:
            self._stats_by_policy[policy_id] = ShadowStats()

        policy_stats = self._stats_by_policy[policy_id]
        policy_stats.total_evaluations += 1

    async def _record_comparison(self, comparison: ShadowComparison, policy_id: str):
        """Record a comparison result."""
        async with self._history_lock:
            self._comparisons.append(comparison)

            # Trim history
            if len(self._comparisons) > self.max_history:
                self._comparisons = self._comparisons[-self.max_history :]

        # Update stats
        result = comparison.comparison_result

        if result == ComparisonResult.MATCH.value:
            self._stats.matches += 1
        elif result == ComparisonResult.FALSE_POSITIVE.value:
            self._stats.false_positives += 1
        elif result == ComparisonResult.FALSE_NEGATIVE.value:
            self._stats.false_negatives += 1
        elif result == ComparisonResult.DIFFERENT_PROMPT.value:
            self._stats.different_prompts += 1
        else:
            self._stats.errors += 1

        # Calculate rates
        total = self._stats.total_evaluations
        if total > 0:
            self._stats.match_rate = self._stats.matches / total
            self._stats.false_positive_rate = self._stats.false_positives / total
            self._stats.false_negative_rate = self._stats.false_negatives / total

        # Update policy-specific stats
        if policy_id in self._stats_by_policy:
            policy_stats = self._stats_by_policy[policy_id]

            if result == ComparisonResult.MATCH.value:
                policy_stats.matches += 1
            elif result == ComparisonResult.FALSE_POSITIVE.value:
                policy_stats.false_positives += 1
            elif result == ComparisonResult.FALSE_NEGATIVE.value:
                policy_stats.false_negatives += 1

    def get_stats(self, policy_id: Optional[str] = None) -> ShadowStats:
        """Get evaluation statistics."""
        if policy_id:
            return self._stats_by_policy.get(policy_id, ShadowStats())
        return self._stats

    def get_comparisons(
        self,
        policy_id: Optional[str] = None,
        result_filter: Optional[str] = None,
        limit: int = 100,
    ) -> List[ShadowComparison]:
        """Get comparison history."""
        comparisons = self._comparisons.copy()

        if policy_id:
            comparisons = [c for c in comparisons if c.shadow_policy_id == policy_id]

        if result_filter:
            comparisons = [
                c for c in comparisons if c.comparison_result == result_filter
            ]

        return comparisons[-limit:]

    def add_difference_callback(self, callback: Callable[[ShadowComparison], None]):
        """Add callback for when shadow differs from production."""
        self._on_difference_callbacks.append(callback)

    async def _periodic_cleanup(self):
        """Periodically clean up old data."""
        while self._running:
            try:
                await asyncio.sleep(3600)  # Every hour

                cutoff = datetime.now(timezone.utc) - timedelta(
                    hours=self.retention_hours
                )
                cutoff_str = cutoff.isoformat()

                async with self._history_lock:
                    self._results = [
                        r for r in self._results if r.timestamp > cutoff_str
                    ]
                    self._comparisons = [
                        c for c in self._comparisons if c.timestamp > cutoff_str
                    ]

                logger.debug(f"Cleaned up shadow data older than {cutoff_str}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Shadow cleanup error: {e}")

    async def _load_policies(self):
        """Load saved shadow policies."""
        policy_file = self.data_dir / "policies.json"

        if policy_file.exists():
            try:
                async with aiofiles.open(policy_file, "r") as f:
                    content = await f.read()

                data = json.loads(content)

                for policy_data in data.get("policies", []):
                    policy = ShadowPolicy(**policy_data)
                    self._policies[policy.policy_id] = policy
                    self._stats_by_policy[policy.policy_id] = ShadowStats()

                logger.info(f"Loaded {len(self._policies)} shadow policies")

            except Exception as e:
                logger.error(f"Error loading shadow policies: {e}")

    async def _save_policies(self):
        """Save shadow policies to disk."""
        policy_file = self.data_dir / "policies.json"

        try:
            from dataclasses import asdict

            data = {
                "policies": [asdict(p) for p in self._policies.values()],
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }

            async with aiofiles.open(policy_file, "w") as f:
                await f.write(json.dumps(data, indent=2))

        except Exception as e:
            logger.error(f"Error saving shadow policies: {e}")


# =============================================================================
# Singleton instance
# =============================================================================

_shadow_evaluator: Optional[ShadowModeEvaluator] = None


def get_shadow_evaluator() -> ShadowModeEvaluator:
    """Get the singleton shadow mode evaluator instance."""
    global _shadow_evaluator
    if _shadow_evaluator is None:
        _shadow_evaluator = ShadowModeEvaluator()
    return _shadow_evaluator


# =============================================================================
# FastAPI Routes
# =============================================================================


def create_shadow_routes():
    """Create FastAPI routes for shadow mode."""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
    from typing import Optional, Dict, Any, List

    router = APIRouter(prefix="/api/v1/guard/shadow", tags=["shadow"])

    class AddPolicyRequest(BaseModel):
        policy_id: str
        name: str
        description: str
        rules: List[Dict[str, Any]]
        sample_rate: float = 1.0
        target_actions: Optional[List[str]] = None
        target_agents: Optional[List[str]] = None

    class EvaluateRequest(BaseModel):
        request_id: str
        action_type: str
        resource: str
        agent_id: str
        context: Dict[str, Any] = {}
        prod_decision: Optional[str] = None
        prod_policy_id: Optional[str] = None
        prod_reason: Optional[str] = None

    @router.post("/policies")
    async def add_policy(request: AddPolicyRequest):
        """Add a shadow policy."""
        evaluator = get_shadow_evaluator()
        policy = await evaluator.add_shadow_policy(
            policy_id=request.policy_id,
            name=request.name,
            description=request.description,
            rules=request.rules,
            sample_rate=request.sample_rate,
            target_actions=request.target_actions,
            target_agents=request.target_agents,
        )
        return {"policy_id": policy.policy_id, "created": True}

    @router.get("/policies")
    async def list_policies():
        """List all shadow policies."""
        evaluator = get_shadow_evaluator()
        policies = evaluator.get_policies()
        return {
            "policies": [
                {
                    "policy_id": p.policy_id,
                    "name": p.name,
                    "enabled": p.enabled,
                    "sample_rate": p.sample_rate,
                    "rules_count": len(p.rules),
                }
                for p in policies
            ]
        }

    @router.delete("/policies/{policy_id}")
    async def delete_policy(policy_id: str):
        """Delete a shadow policy."""
        evaluator = get_shadow_evaluator()
        success = await evaluator.remove_shadow_policy(policy_id)
        if not success:
            raise HTTPException(404, f"Policy not found: {policy_id}")
        return {"policy_id": policy_id, "deleted": True}

    @router.post("/policies/{policy_id}/enable")
    async def enable_policy(policy_id: str, enabled: bool = True):
        """Enable or disable a shadow policy."""
        evaluator = get_shadow_evaluator()
        success = await evaluator.enable_policy(policy_id, enabled)
        if not success:
            raise HTTPException(404, f"Policy not found: {policy_id}")
        return {"policy_id": policy_id, "enabled": enabled}

    @router.post("/evaluate")
    async def evaluate(request: EvaluateRequest):
        """Evaluate a request against shadow policies."""
        evaluator = get_shadow_evaluator()
        results = await evaluator.evaluate(
            request_id=request.request_id,
            action_type=request.action_type,
            resource=request.resource,
            agent_id=request.agent_id,
            context=request.context,
            prod_decision=request.prod_decision,
            prod_policy_id=request.prod_policy_id,
            prod_reason=request.prod_reason,
        )
        return {
            "request_id": request.request_id,
            "results": [
                {
                    "policy_id": r.shadow_policy_id,
                    "decision": r.shadow_decision,
                    "reason": r.shadow_reason,
                    "matched_rules": r.matched_rules,
                    "evaluation_time_ms": r.evaluation_time_ms,
                }
                for r in results
            ],
        }

    @router.get("/stats")
    async def get_stats(policy_id: Optional[str] = None):
        """Get shadow evaluation statistics."""
        evaluator = get_shadow_evaluator()
        stats = evaluator.get_stats(policy_id)
        return {
            "total_evaluations": stats.total_evaluations,
            "matches": stats.matches,
            "false_positives": stats.false_positives,
            "false_negatives": stats.false_negatives,
            "match_rate": stats.match_rate,
            "false_positive_rate": stats.false_positive_rate,
            "false_negative_rate": stats.false_negative_rate,
            "avg_evaluation_time_ms": stats.avg_evaluation_time_ms,
        }

    @router.get("/comparisons")
    async def get_comparisons(
        policy_id: Optional[str] = None,
        result: Optional[str] = None,
        limit: int = 100,
    ):
        """Get comparison history."""
        evaluator = get_shadow_evaluator()
        comparisons = evaluator.get_comparisons(
            policy_id=policy_id,
            result_filter=result,
            limit=limit,
        )
        return {
            "comparisons": [
                {
                    "request_id": c.request_id,
                    "prod_decision": c.prod_decision,
                    "shadow_decision": c.shadow_decision,
                    "comparison_result": c.comparison_result,
                    "severity": c.difference_severity,
                    "action_type": c.action_type,
                    "timestamp": c.timestamp,
                }
                for c in comparisons
            ]
        }

    return router
