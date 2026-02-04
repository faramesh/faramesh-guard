"""
/v1/actions - Faramesh-compatible action authorization endpoint

Matches Faramesh Cloud API exactly so OpenClaw integration works.
Phase 1: Log + basic risk evaluation with permit minting
Phase 2: Approval flow with polling
"""

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Dict, Any, Optional, Literal
import logging
from datetime import datetime
import uuid

# Use relative imports for consolidated structure
from core.car import CAR, AuthorityDomain, validate_params, ValidationError
from core.car_hash import compute_car_hash
from core.permit import PermitMinter

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize permit minter
permit_minter = PermitMinter()


class ActionRequest(BaseModel):
    """Faramesh-compatible action request (from OpenClaw)."""

    agent_id: str
    tool: str
    operation: str
    params: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None
    tenant_id: Optional[str] = None
    project_id: Optional[str] = None
    runtime_id: Optional[str] = None


class ActionResponse(BaseModel):
    """Faramesh-compatible action response with permit."""

    id: str  # action_id
    decision: Literal["allow", "deny", "pending"]
    outcome: Literal["EXECUTE", "HALT", "ABSTAIN"]
    status: Literal["allowed", "denied", "pending_approval"]
    reason: str
    reason_code: str
    request_hash: str
    approval_token: Optional[str] = None
    policy_version: Optional[str] = None
    risk_level: Optional[str] = None
    permit: Optional[Dict[str, Any]] = None  # NEW: Cryptographically signed permit


@router.post("/v1/actions", response_model=ActionResponse)
async def create_action(
    request: ActionRequest, authorization: Optional[str] = Header(None)
):
    """
    Evaluate action and return authorization decision.

    MATCHES FARAMESH CLOUD API EXACTLY.

    Phase 1: Log + basic risk evaluation
    Phase 2: Approval flow for medium/high risk

    OpenClaw timeout: 5 seconds (must respond quickly)
    """

    # Validate Bearer token
    if authorization:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid authorization format")
        token = authorization[7:]  # Remove "Bearer "
        # Phase 2: Validate token against configured RUNTIME_TOKEN
        # For now, just log it
        logger.debug(f"Received token: {token[:8]}...")
    try:
        # 1. Validate parameters
        try:
            validate_params(request.params)
        except ValidationError as e:
            logger.warning(f"Parameter validation failed: {e}")

        # 2. Build CAR from OpenClaw request
        action_id = str(uuid.uuid4())

        # Map tool to authority domain
        authority_domain = infer_authority_domain(request.tool)

        car = CAR(
            car_id=action_id,
            car_hash="",  # Will compute below
            tool=request.tool,
            operation=request.operation,
            authority_domain=authority_domain,
            args=request.params,
            normalized_args=request.params,  # TODO: Normalize paths/URLs
            agent_id=request.agent_id,
            agent_name=request.agent_id,  # OpenClaw uses agent_id
            session_id=(
                request.context.get("sessionKey", "unknown")
                if request.context
                else "unknown"
            ),
            provenance={},
            workflow_stage=None,
            target_kind=infer_target_kind(request.tool, request.params),
            sensitivity={},
            blast_radius=infer_blast_radius(request.tool, request.params),
            timestamp=datetime.utcnow().isoformat(),
            runtime_version=request.runtime_id or "openclaw",
            guard_version="0.1.0",
        )

        # 3. Compute CAR hash (deterministic identity)
        car_dict = car.to_dict()
        car.car_hash = compute_car_hash(car_dict)

        # 4. Evaluate risk
        risk_level = evaluate_risk(car)

        # 5. Log action
        logger.info(
            f"Action {action_id}: {car.tool}.{car.operation} "
            f"[{car.authority_domain.value}] "
            f"risk={risk_level} hash={car.car_hash[:8]}..."
        )
        logger.debug(f"CAR: {car.to_dict()}")

        # 6. Make decision based on risk
        if risk_level == "low":
            # LOW RISK: Mint permit and allow execution
            signed_permit = permit_minter.mint(
                car_hash=car.car_hash,
                agent_id=request.agent_id,
                tool=request.tool,
                operation=request.operation,
                caveats={
                    "tool": request.tool,
                    "operation": request.operation,
                    "max_uses": 1,
                },
                metadata={
                    "reason": "Low risk - auto-allowed",
                    "decision_id": action_id,
                    "risk_level": risk_level,
                },
            )

            return ActionResponse(
                id=action_id,
                decision="allow",
                outcome="EXECUTE",
                status="allowed",
                reason="Low risk - auto-allowed",
                reason_code="AUTO_ALLOW_LOW_RISK",
                request_hash=car.car_hash,
                risk_level=risk_level,
                permit=signed_permit.to_dict(),  # Include signed permit
            )

        elif risk_level in ["critical", "high"]:
            # Phase 1: Block critical/high risk
            # Phase 2: Will require approval
            logger.warning(f"Action {action_id} BLOCKED: {risk_level} risk")
            return ActionResponse(
                id=action_id,
                decision="deny",
                outcome="HALT",
                status="denied",
                reason=f"{risk_level.capitalize()} risk action blocked",
                reason_code=f"BLOCKED_{risk_level.upper()}_RISK",
                request_hash=car.car_hash,
                risk_level=risk_level,
            )

        else:  # medium
            # Phase 1: Allow medium risk
            # Phase 2: Will trigger approval flow (ABSTAIN)
            return ActionResponse(
                id=action_id,
                decision="allow",
                outcome="EXECUTE",
                status="allowed",
                reason="Medium risk - allowed in Phase 1",
                reason_code="AUTO_ALLOW_PHASE1",
                request_hash=car.car_hash,
                risk_level=risk_level,
            )

    except ValueError as e:
        logger.error(f"Invalid action: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    except Exception as e:
        logger.error(f"Action evaluation error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error")


def infer_authority_domain(tool: str) -> AuthorityDomain:
    """Map OpenClaw tool name to authority domain."""
    if tool in ["exec", "bash", "shell", "command"]:
        return AuthorityDomain.EXEC
    elif tool in ["read", "write", "edit", "list", "filesystem"]:
        return AuthorityDomain.FILESYSTEM
    elif tool in ["browser", "navigate", "screenshot"]:
        return AuthorityDomain.BROWSER
    else:
        return AuthorityDomain.NETWORK  # http, api calls, etc


def infer_target_kind(tool: str, params: Dict[str, Any]) -> str:
    """Infer what kind of resource is targeted."""
    # Check for financial operations
    if tool in ["stripe", "paypal", "payment"]:
        return "financial"

    # Check for config files
    if "path" in params:
        path = str(params["path"]).lower()
        if any(x in path for x in [".env", "config", "credentials", ".ssh"]):
            return "config"

    # Check for user data
    if tool == "database" or "user" in str(params).lower():
        return "user_data"

    return "general"


def infer_blast_radius(tool: str, params: Dict[str, Any]) -> str:
    """Estimate impact scope of action."""
    # System-wide operations
    if "sudo" in str(params).get("cmd", ""):
        return "system"

    if "path" in params:
        path = str(params["path"])
        if path.startswith("/etc/") or path.startswith("/sys/"):
            return "system"

    # Cloud operations
    if tool in ["aws", "gcp", "azure", "terraform"]:
        return "account"

    return "user"


def evaluate_risk(car: CAR) -> str:
    """
    Evaluate risk level of action.

    Returns: "low", "medium", "high", "critical"
    """
    risk_score = 0

    # Authority domain risks
    if car.authority_domain == AuthorityDomain.EXEC:
        risk_score += 30

        # Check for dangerous shell patterns
        cmd = car.args.get("cmd", "")
        if isinstance(cmd, str):
            dangerous_patterns = [
                "rm -rf",
                "sudo",
                "chmod 777",
                "dd if=",
                "> /dev/",
                "mkfs",
                "format",
                "shutdown",
                "reboot",
            ]
            if any(pattern in cmd for pattern in dangerous_patterns):
                risk_score += 50

    elif car.authority_domain == AuthorityDomain.FILESYSTEM:
        risk_score += 10

        if car.operation in ["delete", "remove", "unlink"]:
            risk_score += 20

        # Check target kind
        if car.target_kind in ["config", "user_data"]:
            risk_score += 15

    elif car.authority_domain == AuthorityDomain.BROWSER:
        risk_score += 5

    else:  # NETWORK
        risk_score += 5

    # Blast radius multiplier
    if car.blast_radius == "system":
        risk_score += 40
    elif car.blast_radius == "account":
        risk_score += 20

    # Target kind multiplier
    if car.target_kind == "financial":
        risk_score += 30
    elif car.target_kind in ["config", "user_data"]:
        risk_score += 15

    # Map score to risk level
    if risk_score >= 70:
        return "critical"
    elif risk_score >= 40:
        return "high"
    elif risk_score >= 20:
        return "medium"
    else:
        return "low"
