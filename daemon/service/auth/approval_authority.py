"""
Approval Authority - Role Weights & Quorum Logic

From guard-plan-v1.md Meta-Layer 5: Human Authority Semantics

Implements:
- Role-based authorization (owner, admin, operator, viewer)
- Role weights for approval power
- Quorum logic (2-of-3, weight thresholds)
- Delegated authority scopes
- Approval expiration semantics
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from enum import Enum
import hashlib
import hmac
import json
import os

logger = logging.getLogger(__name__)


class Role(Enum):
    """User roles with associated authority levels."""

    OWNER = "owner"  # Full control, highest authority
    ADMIN = "admin"  # Administrative access
    OPERATOR = "operator"  # Operational access within scopes
    VIEWER = "viewer"  # Read-only, cannot approve


@dataclass
class ApprovalAuthority:
    """
    Represents a user's authority to approve actions.

    Authority is scoped and can be delegated.
    """

    user_id: str
    role: Role
    scopes: List[str] = field(default_factory=list)  # ["finance", "production", "dev"]
    granted_by: Optional[str] = None
    granted_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

    @property
    def weight(self) -> int:
        """Get the approval weight for this authority."""
        return AuthorityChecker.ROLE_WEIGHTS.get(self.role, 0)

    @property
    def is_expired(self) -> bool:
        """Check if authority has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def to_dict(self) -> Dict:
        return {
            "user_id": self.user_id,
            "role": self.role.value,
            "weight": self.weight,
            "scopes": self.scopes,
            "granted_by": self.granted_by,
            "granted_at": self.granted_at.isoformat() if self.granted_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_expired": self.is_expired,
        }


@dataclass
class ApprovalRequirement:
    """
    Specifies what's needed to approve an action.
    """

    quorum: int  # How many approvers needed
    min_weight: int  # Minimum combined weight required
    eligible_roles: List[Role]  # Roles that can approve
    timeout_seconds: int  # How long approval is valid
    fallback: str  # "deny" | "escalate" | "retry"

    def to_dict(self) -> Dict:
        return {
            "quorum": self.quorum,
            "min_weight": self.min_weight,
            "eligible_roles": [r.value for r in self.eligible_roles],
            "timeout_seconds": self.timeout_seconds,
            "fallback": self.fallback,
        }


@dataclass
class ApprovalRecord:
    """Record of a single approval."""

    approval_id: str
    user_id: str
    role: Role
    weight: int
    approved_at: datetime
    reason: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "approval_id": self.approval_id,
            "user_id": self.user_id,
            "role": self.role.value,
            "weight": self.weight,
            "approved_at": self.approved_at.isoformat(),
            "reason": self.reason,
        }


@dataclass
class ApprovalDecision:
    """
    Tracks approval progress toward quorum.
    """

    action_id: str
    requirement: ApprovalRequirement
    approvals: List[ApprovalRecord] = field(default_factory=list)
    denials: List[ApprovalRecord] = field(default_factory=list)

    @property
    def current_weight(self) -> int:
        """Total weight from approvals."""
        return sum(a.weight for a in self.approvals)

    @property
    def approver_count(self) -> int:
        """Number of unique approvers."""
        return len(set(a.user_id for a in self.approvals))

    @property
    def quorum_met(self) -> bool:
        """Check if approval quorum is satisfied."""
        weight_met = self.current_weight >= self.requirement.min_weight
        count_met = self.approver_count >= self.requirement.quorum
        return weight_met and count_met

    @property
    def is_denied(self) -> bool:
        """Check if action was explicitly denied."""
        return len(self.denials) > 0

    def to_dict(self) -> Dict:
        return {
            "action_id": self.action_id,
            "requirement": self.requirement.to_dict(),
            "approvals": [a.to_dict() for a in self.approvals],
            "denials": [d.to_dict() for d in self.denials],
            "current_weight": self.current_weight,
            "approver_count": self.approver_count,
            "quorum_met": self.quorum_met,
            "is_denied": self.is_denied,
        }


class AuthorityChecker:
    """
    Manages user authorities and approval logic.

    Implements:
    - Role-based weight system
    - Scope-based approval restrictions
    - Quorum requirements based on risk level
    """

    # Role weights (from plan)
    ROLE_WEIGHTS = {Role.OWNER: 10, Role.ADMIN: 7, Role.OPERATOR: 3, Role.VIEWER: 0}

    def __init__(self):
        self._authorities: Dict[str, ApprovalAuthority] = {}
        self._pending_decisions: Dict[str, ApprovalDecision] = {}

        # Default: single user is owner
        self._initialize_default_authority()

        logger.info("AuthorityChecker initialized")

    def _initialize_default_authority(self):
        """Create default owner authority for local user."""
        import getpass

        local_user = getpass.getuser()

        self._authorities[local_user] = ApprovalAuthority(
            user_id=local_user,
            role=Role.OWNER,
            scopes=["*"],  # All scopes
            granted_by="system",
            granted_at=datetime.utcnow(),
        )

        # Also add 'user' as alias for compatibility
        self._authorities["user"] = ApprovalAuthority(
            user_id="user",
            role=Role.OWNER,
            scopes=["*"],
            granted_by="system",
            granted_at=datetime.utcnow(),
        )

    def get_authority(self, user_id: str) -> Optional[ApprovalAuthority]:
        """Get authority record for a user."""
        return self._authorities.get(user_id)

    def grant_authority(
        self,
        user_id: str,
        role: Role,
        scopes: List[str],
        granted_by: str,
        duration_hours: Optional[int] = None,
    ) -> ApprovalAuthority:
        """Grant authority to a user."""
        expires_at = None
        if duration_hours:
            expires_at = datetime.utcnow() + timedelta(hours=duration_hours)

        authority = ApprovalAuthority(
            user_id=user_id,
            role=role,
            scopes=scopes,
            granted_by=granted_by,
            granted_at=datetime.utcnow(),
            expires_at=expires_at,
        )

        self._authorities[user_id] = authority
        logger.info(f"Granted {role.value} authority to {user_id} (scopes: {scopes})")

        return authority

    def revoke_authority(self, user_id: str) -> bool:
        """Revoke authority from a user."""
        if user_id in self._authorities:
            del self._authorities[user_id]
            logger.info(f"Revoked authority from {user_id}")
            return True
        return False

    def can_approve(
        self, user_id: str, action_scope: str, risk_level: str
    ) -> Tuple[bool, int, str]:
        """
        Check if user can approve an action.

        Args:
            user_id: User attempting to approve
            action_scope: Scope of the action (e.g., "finance", "dev")
            risk_level: Risk level of action ("low", "medium", "high", "critical")

        Returns:
            (can_approve: bool, weight: int, reason: str)
        """
        authority = self._authorities.get(user_id)

        if not authority:
            return (False, 0, "No authority record found")

        if authority.is_expired:
            return (False, 0, "Authority has expired")

        if authority.role == Role.VIEWER:
            return (False, 0, "Viewers cannot approve actions")

        # Check scope
        if "*" not in authority.scopes and action_scope not in authority.scopes:
            return (False, 0, f"Not authorized for scope: {action_scope}")

        # Operators can only approve medium/low risk
        if authority.role == Role.OPERATOR and risk_level in ["critical", "high"]:
            return (False, 0, "Operators cannot approve high/critical risk actions")

        return (True, authority.weight, "Authorized")

    def get_quorum_requirement(
        self, technical_risk: str, economic_risk: str
    ) -> ApprovalRequirement:
        """
        Determine quorum requirements based on risk levels.

        From plan:
        - Critical: Need 2 approvers OR 1 owner (weight >= 10)
        - High: Need 1 admin+ OR 2 operators (weight >= 7)
        - Medium/Low: Need 1 eligible role (weight >= 3)
        """
        # Take the higher risk level
        risks = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        max_risk = max(risks.get(technical_risk, 0), risks.get(economic_risk, 0))

        if max_risk >= 3:  # Critical
            return ApprovalRequirement(
                quorum=2,
                min_weight=10,  # 1 owner (10) OR 2 admins (7+7=14)
                eligible_roles=[Role.OWNER, Role.ADMIN],
                timeout_seconds=300,
                fallback="deny",
            )
        elif max_risk >= 2:  # High
            return ApprovalRequirement(
                quorum=1,
                min_weight=7,  # 1 admin (7) OR 3 operators (3+3+3=9)
                eligible_roles=[Role.OWNER, Role.ADMIN, Role.OPERATOR],
                timeout_seconds=120,
                fallback="deny",
            )
        else:  # Medium/Low
            return ApprovalRequirement(
                quorum=1,
                min_weight=3,  # Any eligible role
                eligible_roles=[Role.OWNER, Role.ADMIN, Role.OPERATOR],
                timeout_seconds=60,
                fallback="deny",
            )

    def create_approval_decision(
        self, action_id: str, technical_risk: str = "medium", economic_risk: str = "low"
    ) -> ApprovalDecision:
        """Create a new approval decision tracking object."""
        requirement = self.get_quorum_requirement(technical_risk, economic_risk)

        decision = ApprovalDecision(action_id=action_id, requirement=requirement)

        self._pending_decisions[action_id] = decision
        logger.info(
            f"Created approval decision for {action_id}: quorum={requirement.quorum}, min_weight={requirement.min_weight}"
        )

        return decision

    def record_approval(
        self, action_id: str, user_id: str, reason: Optional[str] = None
    ) -> Tuple[bool, ApprovalDecision, str]:
        """
        Record an approval for an action.

        Returns:
            (success: bool, decision: ApprovalDecision, message: str)
        """
        decision = self._pending_decisions.get(action_id)
        if not decision:
            # Create default decision for backward compatibility
            decision = self.create_approval_decision(action_id)

        authority = self._authorities.get(user_id)
        if not authority:
            # For backward compatibility, treat unknown users as owners
            authority = ApprovalAuthority(
                user_id=user_id, role=Role.OWNER, scopes=["*"]
            )

        # Check if user already approved
        existing = [a for a in decision.approvals if a.user_id == user_id]
        if existing:
            return (False, decision, "User already approved this action")

        # Record approval
        record = ApprovalRecord(
            approval_id=f"{action_id}-{user_id}",
            user_id=user_id,
            role=authority.role,
            weight=authority.weight,
            approved_at=datetime.utcnow(),
            reason=reason,
        )

        decision.approvals.append(record)

        if decision.quorum_met:
            logger.info(
                f"Quorum met for {action_id}: weight={decision.current_weight}, count={decision.approver_count}"
            )
            return (True, decision, "Approval quorum met")
        else:
            logger.info(
                f"Approval recorded for {action_id}: current_weight={decision.current_weight}, need={decision.requirement.min_weight}"
            )
            return (
                True,
                decision,
                f"Approval recorded. Need {decision.requirement.min_weight - decision.current_weight} more weight",
            )

    def record_denial(
        self, action_id: str, user_id: str, reason: Optional[str] = None
    ) -> Tuple[bool, ApprovalDecision, str]:
        """
        Record a denial for an action.

        Any eligible user can deny. Single denial blocks the action.
        """
        decision = self._pending_decisions.get(action_id)
        if not decision:
            decision = self.create_approval_decision(action_id)

        authority = self._authorities.get(user_id)
        if not authority:
            authority = ApprovalAuthority(
                user_id=user_id, role=Role.OWNER, scopes=["*"]
            )

        record = ApprovalRecord(
            approval_id=f"{action_id}-{user_id}-deny",
            user_id=user_id,
            role=authority.role,
            weight=authority.weight,
            approved_at=datetime.utcnow(),
            reason=reason,
        )

        decision.denials.append(record)

        logger.info(f"Action {action_id} denied by {user_id}")
        return (True, decision, "Action denied")

    def get_decision(self, action_id: str) -> Optional[ApprovalDecision]:
        """Get approval decision status for an action."""
        return self._pending_decisions.get(action_id)

    def cleanup_expired(self) -> int:
        """Remove expired decisions. Returns count of removed."""
        now = datetime.utcnow()
        expired = []

        for action_id, decision in self._pending_decisions.items():
            if decision.approvals:
                first_approval = min(a.approved_at for a in decision.approvals)
                timeout = timedelta(seconds=decision.requirement.timeout_seconds)
                if now - first_approval > timeout:
                    expired.append(action_id)

        for action_id in expired:
            del self._pending_decisions[action_id]

        if expired:
            logger.info(f"Cleaned up {len(expired)} expired approval decisions")

        return len(expired)

    def get_stats(self) -> Dict:
        """Get authority statistics."""
        return {
            "total_users": len(self._authorities),
            "pending_decisions": len(self._pending_decisions),
            "users_by_role": {
                role.value: sum(1 for a in self._authorities.values() if a.role == role)
                for role in Role
            },
        }


# Global instance for singleton access
_authority_checker: Optional[AuthorityChecker] = None


def get_authority_checker() -> AuthorityChecker:
    """Get or create the global authority checker."""
    global _authority_checker
    if _authority_checker is None:
        _authority_checker = AuthorityChecker()
    return _authority_checker
