"""
Approval lifecycle endpoints for Guard.

Implements polling mechanism for pending actions.
Phase 2: Full approval flow with UI integration.
"""

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Literal, Optional
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


class ApprovalStatusResponse(BaseModel):
    """Status of an action approval."""

    action_id: str
    status: Literal["pending", "approved", "denied", "expired"]
    approved_at: Optional[str] = None
    denied_at: Optional[str] = None
    reason: Optional[str] = None


class ApprovalUpdateRequest(BaseModel):
    """Request to approve or deny an action."""

    reason: Optional[str] = None


@router.get("/v1/actions/{action_id}")
async def get_action_status(
    action_id: str, authorization: Optional[str] = Header(None)
):
    """
    Get current status of an action (for OpenClaw polling).

    OpenClaw polls this endpoint every 5 seconds for ABSTAIN actions.
    Must return FarameshActionResponse format (same as POST /v1/actions).

    Phase 1: Always returns EXECUTE (no actual approvals yet)
    Phase 2: Query from SQLite pending_actions table
    """

    # Validate Bearer token
    if authorization:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid authorization format")

    # Phase 1: Fake approval (everything auto-approved)
    logger.debug(f"Status check for action {action_id}")

    return ApprovalStatusResponse(
        action_id=action_id,
        status="approved",
        approved_at=None,
        reason="Phase 1: Auto-approved",
    )


@router.post("/v1/actions/{action_id}/approve")
async def approve_action(action_id: str, request: ApprovalUpdateRequest = None):
    """
    Approve a pending action.

    Phase 2: Update SQLite, notify OpenClaw via polling
    """

    logger.info(f"Action {action_id} approved")

    return {
        "action_id": action_id,
        "status": "approved",
        "message": "Action approved successfully",
    }


@router.post("/v1/actions/{action_id}/deny")
async def deny_action(action_id: str, request: ApprovalUpdateRequest):
    """
    Deny a pending action.

    Phase 2: Update SQLite, notify OpenClaw via polling
    """

    logger.info(
        f"Action {action_id} denied: {request.reason if request else 'no reason'}"
    )

    return {
        "action_id": action_id,
        "status": "denied",
        "message": "Action denied",
        "reason": request.reason if request else None,
    }
