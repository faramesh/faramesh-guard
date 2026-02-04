"""
Fail-Closed Handler - Safety First Error Handling

When Guard daemon is unreachable or errors occur, fail-closed ensures:
1. HIGH/CRITICAL risk actions are blocked
2. LOW risk may use cached policies (optional)
3. Audit trail records all failures
4. Clear error messages for debugging

Following plan-farameshGuardV1Enhanced.prompt.md:
- Fail-closed by default
- Risk-based fallback policies
- Comprehensive error categorization
- Audit trail integration
"""

import logging
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class FailureMode(Enum):
    """Categories of failures"""

    DAEMON_UNREACHABLE = "daemon_unreachable"
    DAEMON_TIMEOUT = "daemon_timeout"
    DAEMON_ERROR = "daemon_error"
    INVALID_RESPONSE = "invalid_response"
    PERMIT_VALIDATION_FAILED = "permit_validation_failed"
    NETWORK_ERROR = "network_error"
    UNKNOWN_ERROR = "unknown_error"


class RiskLevel(Enum):
    """Risk levels for actions"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class FailureContext:
    """Context about a failure"""

    mode: FailureMode
    error_message: str
    risk_level: RiskLevel
    agent_id: str
    tool_name: str
    parameters: Dict[str, Any]
    timestamp: datetime
    stack_trace: Optional[str] = None


@dataclass
class FailClosedDecision:
    """Decision made by fail-closed handler"""

    allowed: bool
    reason: str
    reason_code: str
    fallback_used: bool = False
    cached_policy_used: bool = False
    audit_record_id: Optional[str] = None


class FailClosedHandler:
    """
    Handles failures with fail-closed semantics.

    Default behavior: DENY all actions when Guard unavailable
    Optional: Allow LOW risk actions with cached policies
    """

    def __init__(
        self, allow_low_risk_fallback: bool = False, allow_cached_policies: bool = False
    ):
        self.allow_low_risk_fallback = allow_low_risk_fallback
        self.allow_cached_policies = allow_cached_policies
        self._failure_count = 0
        self._last_failure: Optional[datetime] = None
        self._cached_policies: Dict[str, Any] = {}

    def handle_failure(self, failure_context: FailureContext) -> FailClosedDecision:
        """
        Handle a failure with fail-closed logic.

        Args:
            failure_context: Information about the failure

        Returns:
            Decision on whether to allow or block the action
        """
        self._failure_count += 1
        self._last_failure = datetime.utcnow()

        # Log the failure
        logger.error(
            f"Guard failure ({failure_context.mode.value}): "
            f"{failure_context.error_message} | "
            f"Tool: {failure_context.tool_name} | "
            f"Agent: {failure_context.agent_id} | "
            f"Risk: {failure_context.risk_level.value}"
        )

        # Audit the failure
        audit_id = self._audit_failure(failure_context)

        # Apply fail-closed logic
        decision = self._make_decision(failure_context)
        decision.audit_record_id = audit_id

        return decision

    def _make_decision(self, context: FailureContext) -> FailClosedDecision:
        """Make the fail-closed decision"""

        # CRITICAL and HIGH risk: ALWAYS block
        if context.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            return FailClosedDecision(
                allowed=False,
                reason=(
                    f"Guard daemon unavailable and action is {context.risk_level.value} risk. "
                    "Fail-closed safety measure activated."
                ),
                reason_code="FAIL_CLOSED_HIGH_RISK",
                fallback_used=False,
            )

        # MEDIUM risk: Block unless cached policy exists
        if context.risk_level == RiskLevel.MEDIUM:
            if self.allow_cached_policies:
                cached = self._check_cached_policy(context)
                if cached:
                    return FailClosedDecision(
                        allowed=True,
                        reason=(
                            f"Guard daemon unavailable but cached policy allows "
                            f"{context.tool_name} for medium risk actions."
                        ),
                        reason_code="CACHED_POLICY_ALLOW",
                        cached_policy_used=True,
                    )

            return FailClosedDecision(
                allowed=False,
                reason=(
                    "Guard daemon unavailable and no cached policy for medium risk action. "
                    "Fail-closed safety measure activated."
                ),
                reason_code="FAIL_CLOSED_MEDIUM_RISK",
            )

        # LOW risk: Optional fallback
        if context.risk_level == RiskLevel.LOW:
            if self.allow_low_risk_fallback:
                return FailClosedDecision(
                    allowed=True,
                    reason=(
                        "Guard daemon unavailable but action is low risk. "
                        "Fallback policy allows execution."
                    ),
                    reason_code="FALLBACK_ALLOW_LOW_RISK",
                    fallback_used=True,
                )
            else:
                return FailClosedDecision(
                    allowed=False,
                    reason=(
                        "Guard daemon unavailable. Fail-closed policy blocks all actions "
                        "regardless of risk level."
                    ),
                    reason_code="FAIL_CLOSED_ALL_RISK",
                )

        # UNKNOWN risk: Always block (conservative)
        return FailClosedDecision(
            allowed=False,
            reason=(
                "Guard daemon unavailable and action risk level unknown. "
                "Conservative fail-closed policy activated."
            ),
            reason_code="FAIL_CLOSED_UNKNOWN_RISK",
        )

    def _check_cached_policy(self, context: FailureContext) -> bool:
        """Check if cached policy allows this action"""
        # Simple implementation - check if tool is in cached allow list
        cache_key = f"{context.tool_name}:{context.risk_level.value}"
        return cache_key in self._cached_policies

    def _audit_failure(self, context: FailureContext) -> str:
        """
        Record failure in audit trail.

        Returns:
            Audit record ID
        """
        # TODO: Integrate with audit system
        # For now, just log
        audit_id = f"failure-{datetime.utcnow().isoformat()}"

        logger.warning(
            f"AUDIT [{audit_id}]: Guard failure | "
            f"Mode: {context.mode.value} | "
            f"Tool: {context.tool_name} | "
            f"Agent: {context.agent_id} | "
            f"Risk: {context.risk_level.value} | "
            f"Error: {context.error_message}"
        )

        return audit_id

    def add_cached_policy(
        self, tool_name: str, risk_level: RiskLevel, allow: bool, ttl_seconds: int = 300
    ):
        """Add a cached policy for a tool"""
        cache_key = f"{tool_name}:{risk_level.value}"
        self._cached_policies[cache_key] = {
            "allow": allow,
            "cached_at": datetime.utcnow(),
            "ttl": ttl_seconds,
        }
        logger.info(
            f"Cached policy added: {cache_key} -> {'ALLOW' if allow else 'DENY'}"
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get failure statistics"""
        return {
            "failure_count": self._failure_count,
            "last_failure": (
                self._last_failure.isoformat() if self._last_failure else None
            ),
            "cached_policies": len(self._cached_policies),
            "allow_low_risk_fallback": self.allow_low_risk_fallback,
            "allow_cached_policies": self.allow_cached_policies,
        }


def assess_risk_level(tool_name: str, parameters: Dict[str, Any]) -> RiskLevel:
    """
    Assess risk level of an action.

    Uses heuristics based on tool name and parameters.
    """
    tool_lower = tool_name.lower()
    params_str = str(parameters).lower()

    # Critical risk patterns
    critical_patterns = [
        "rm",
        "delete",
        "drop",
        "truncate",
        "destroy",
        "kill",
        "shutdown",
        "reboot",
        "format",
        "wipe",
        "rm -rf",
        "del /f",
        "DROP TABLE",
        "DROP DATABASE",
    ]

    if any(
        pattern in tool_lower or pattern in params_str for pattern in critical_patterns
    ):
        return RiskLevel.CRITICAL

    # High risk patterns
    high_patterns = [
        "exec",
        "eval",
        "system",
        "shell",
        "run",
        "sudo",
        "admin",
        "root",
        "chmod 777",
        "chown",
    ]

    if any(pattern in tool_lower or pattern in params_str for pattern in high_patterns):
        return RiskLevel.HIGH

    # Medium risk patterns
    medium_patterns = [
        "write",
        "modify",
        "update",
        "create",
        "insert",
        "post",
        "put",
        "patch",
        "send",
        "publish",
    ]

    if any(
        pattern in tool_lower or pattern in params_str for pattern in medium_patterns
    ):
        return RiskLevel.MEDIUM

    # Low risk patterns
    low_patterns = [
        "read",
        "get",
        "list",
        "search",
        "query",
        "view",
        "show",
        "display",
        "print",
        "fetch",
    ]

    if any(pattern in tool_lower or pattern in params_str for pattern in low_patterns):
        return RiskLevel.LOW

    return RiskLevel.UNKNOWN


def create_failure_context(
    mode: FailureMode,
    error: Exception,
    agent_id: str,
    tool_name: str,
    parameters: Dict[str, Any],
) -> FailureContext:
    """Helper to create FailureContext from an exception"""

    risk_level = assess_risk_level(tool_name, parameters)

    return FailureContext(
        mode=mode,
        error_message=str(error),
        risk_level=risk_level,
        agent_id=agent_id,
        tool_name=tool_name,
        parameters=parameters,
        timestamp=datetime.utcnow(),
        stack_trace=None,  # Could add traceback.format_exc()
    )


# Global fail-closed handler (singleton)
_global_handler: Optional[FailClosedHandler] = None


def get_fail_closed_handler(
    allow_low_risk_fallback: bool = False, allow_cached_policies: bool = False
) -> FailClosedHandler:
    """Get or create the global fail-closed handler"""
    global _global_handler
    if _global_handler is None:
        _global_handler = FailClosedHandler(
            allow_low_risk_fallback=allow_low_risk_fallback,
            allow_cached_policies=allow_cached_policies,
        )
    return _global_handler
