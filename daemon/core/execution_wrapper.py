"""
Execution Wrapper - Final enforcement boundary

This module wraps tool execution and validates permits BEFORE allowing
any system effect. This is the NON-BYPASSABLE layer.

Enforcement Invariants:
1. Tool cannot execute without valid permit
2. Permit must be signed by Guard daemon
3. Permit must not be expired
4. Permit CAR hash must match current action
5. Daemon down = HIGH/CRITICAL risk blocked
6. Plugin missing = execution fails
7. Permit absent = execution fails

This is the CRITICAL difference between "plugin integration" and "enforcement proof".
"""

import os
import json
import hashlib
import hmac
from typing import Dict, Any, Optional, Tuple, Callable
from datetime import datetime
from dataclasses import dataclass


# Configuration
GUARD_DAEMON_URL = os.getenv("GUARD_DAEMON_URL", "http://127.0.0.1:9472")
GUARD_API_TOKEN = os.getenv("GUARD_API_TOKEN", "dev-token-CHANGE-IN-PRODUCTION")
PERMIT_SECRET_KEY = os.getenv(
    "GUARD_PERMIT_SECRET", "guard-v1-permit-signing-key-CHANGE-IN-PRODUCTION"
).encode()


@dataclass
class ExecutionContext:
    """Context passed to tool execution"""

    agent_id: str
    tool_name: str
    parameters: Dict[str, Any]
    workspace_id: Optional[str] = None
    session_key: Optional[str] = None


@dataclass
class ExecutionResult:
    """Result of attempted tool execution"""

    allowed: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    permit_id: Optional[str] = None
    decision_id: Optional[str] = None


class PermitValidationError(Exception):
    """Raised when permit validation fails"""

    pass


class GuardEnforcementError(Exception):
    """Raised when Guard enforcement fails"""

    pass


def validate_permit(
    permit: Dict[str, Any], current_car_hash: str
) -> Tuple[bool, Optional[str]]:
    """
    Validate cryptographically signed permit.

    CRITICAL CHECKS:
    1. Signature verification (HMAC-SHA256)
    2. Expiry check (with clock skew tolerance)
    3. CAR hash match (prevents replay attacks)

    Args:
        permit: Signed permit from daemon
        current_car_hash: Hash of current action being executed

    Returns:
        (valid, error_reason) tuple
    """
    try:
        # Extract signature
        signature = permit.get("signature")
        if not signature:
            return False, "No signature in permit"

        # Reconstruct permit (without signature)
        permit_data = {k: v for k, v in permit.items() if k != "signature"}

        # 1. Verify HMAC signature
        canonical = json.dumps(permit_data, sort_keys=True, separators=(",", ":"))
        expected_signature = hmac.new(
            PERMIT_SECRET_KEY, canonical.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            return False, "Invalid signature - permit may be forged"

        # 2. Check expiry (with 5s clock skew tolerance)
        expires_at = datetime.fromisoformat(
            permit_data["expires_at"].replace("Z", "+00:00")
        )
        now = datetime.utcnow()

        if now.timestamp() > expires_at.timestamp() + 5:
            return False, "Permit expired"

        # 3. CRITICAL: Check CAR hash match (prevents replay attacks)
        if permit_data["car_hash"] != current_car_hash:
            return False, "CAR hash mismatch - permit bound to different action"

        return True, None

    except Exception as e:
        return False, f"Permit validation error: {str(e)}"


def compute_car_hash(context: ExecutionContext) -> str:
    """
    Compute deterministic hash of action for permit binding.

    Must match daemon's car_hash.py implementation.
    """
    canonical = {
        "tool": context.tool_name.lower(),
        "operation": context.tool_name.lower(),
        "target_kind": "generic",
        "target": json.dumps(context.parameters, sort_keys=True),
    }

    canonical_json = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


async def call_guard_daemon(context: ExecutionContext) -> Dict[str, Any]:
    """
    Call Guard daemon for authorization decision.

    Returns decision with signed permit (if authorized).
    """
    import aiohttp

    request = {
        "agent_id": context.agent_id,
        "tool": context.tool_name,
        "operation": context.tool_name,
        "params": context.parameters,
        "context": {
            "workspace_id": context.workspace_id,
            "session_key": context.session_key,
        },
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{GUARD_DAEMON_URL}/v1/actions",
                json=request,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {GUARD_API_TOKEN}",
                },
                timeout=aiohttp.ClientTimeout(total=5),
            ) as response:
                if response.status != 200:
                    text = await response.text()
                    raise GuardEnforcementError(
                        f"Guard daemon returned {response.status}: {text}"
                    )

                return await response.json()

    except aiohttp.ClientError as e:
        raise GuardEnforcementError(f"Failed to reach Guard daemon: {e}")


async def execute_with_guard(
    context: ExecutionContext, tool_executor: Callable
) -> ExecutionResult:
    """
    Execute tool with Guard enforcement.

    ENFORCEMENT FLOW:
    1. Compute CAR hash for current action
    2. Call Guard daemon for decision + permit
    3. Validate permit signature
    4. Execute tool ONLY if permit valid
    5. Report result to Guard

    Args:
        context: Execution context
        tool_executor: Async function that executes the tool

    Returns:
        ExecutionResult with success/failure and permit info
    """
    try:
        # 1. Compute CAR hash
        car_hash = compute_car_hash(context)

        # 2. Call Guard daemon
        try:
            decision = await call_guard_daemon(context)
        except GuardEnforcementError as e:
            # Daemon unreachable - FAIL CLOSED
            return ExecutionResult(
                allowed=False,
                error=f"Guard daemon unreachable: {e}. Blocking execution for safety.",
            )

        # 3. Check decision outcome
        outcome = decision.get("outcome")

        if outcome == "HALT":
            return ExecutionResult(
                allowed=False,
                error=f"Guard blocked: {decision.get('reason')}",
                decision_id=decision.get("id"),
            )

        if outcome == "ABSTAIN":
            # Phase 2: Will poll for approval
            return ExecutionResult(
                allowed=False,
                error="Requires approval (not yet implemented in Phase 1)",
                decision_id=decision.get("id"),
            )

        # 4. CRITICAL: Validate permit
        permit = decision.get("permit")
        if not permit:
            return ExecutionResult(
                allowed=False,
                error="Guard returned EXECUTE but no permit - security violation",
                decision_id=decision.get("id"),
            )

        valid, error_reason = validate_permit(permit, car_hash)
        if not valid:
            return ExecutionResult(
                allowed=False,
                error=f"Invalid permit: {error_reason}",
                decision_id=decision.get("id"),
            )

        # 5. Execute tool with valid permit
        try:
            result = await tool_executor(context.parameters)

            return ExecutionResult(
                allowed=True,
                result=result,
                permit_id=permit.get("permit_id"),
                decision_id=decision.get("id"),
            )

        except Exception as e:
            return ExecutionResult(
                allowed=False,
                error=f"Tool execution failed: {e}",
                permit_id=permit.get("permit_id"),
                decision_id=decision.get("id"),
            )

    except Exception as e:
        # ANY unexpected error - FAIL CLOSED
        return ExecutionResult(allowed=False, error=f"Guard enforcement error: {e}")


class GuardedToolWrapper:
    """
    Wrapper that enforces Guard authorization on tool execution.

    Usage:
        async def my_tool(params):
            # Tool logic here
            return result

        guarded = GuardedToolWrapper("my_tool", my_tool)
        result = await guarded.execute(agent_id, params)
    """

    def __init__(self, tool_name: str, tool_executor: Callable):
        self.tool_name = tool_name
        self.tool_executor = tool_executor

    async def execute(
        self,
        agent_id: str,
        parameters: Dict[str, Any],
        workspace_id: Optional[str] = None,
        session_key: Optional[str] = None,
    ) -> ExecutionResult:
        """
        Execute tool with Guard enforcement.

        This is the NON-BYPASSABLE execution boundary.
        """
        context = ExecutionContext(
            agent_id=agent_id,
            tool_name=self.tool_name,
            parameters=parameters,
            workspace_id=workspace_id,
            session_key=session_key,
        )

        return await execute_with_guard(context, self.tool_executor)
