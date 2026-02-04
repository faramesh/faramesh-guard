"""
Permit System - Cryptographically signed execution permits.

Implements the permit-based enforcement model:
1. Guard mints signed permits on EXECUTE/APPROVE decisions
2. Permits are bound to CAR hash (prevents replay attacks)
3. Tool execution requires valid permit
4. Permits expire after 2 minutes
"""

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


# Secret key for HMAC signing (in production, load from secure storage)
PERMIT_SECRET_KEY = b"guard-v1-permit-signing-key-CHANGE-IN-PRODUCTION"
PERMIT_VALIDITY_SECONDS = 120  # 2 minutes


@dataclass
class Permit:
    """Cryptographically signed execution permit."""

    permit_id: str
    issued_at: str
    expires_at: str
    issuer: str
    subject: str  # agent_id

    car_hash: str  # Binds permit to specific action

    caveats: Dict[str, Any]  # Action constraints

    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for signing/serialization."""
        return asdict(self)


@dataclass
class SignedPermit:
    """Permit with cryptographic signature."""

    permit: Permit
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for transmission."""
        return {**self.permit.to_dict(), "signature": self.signature}


class PermitMinter:
    """Mints cryptographically signed permits for approved actions."""

    def __init__(self, secret_key: bytes = PERMIT_SECRET_KEY):
        self.secret_key = secret_key

    def mint(
        self,
        car_hash: str,
        agent_id: str,
        tool: str,
        operation: str,
        caveats: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SignedPermit:
        """
        Mint a signed permit for an approved action.

        Args:
            car_hash: SHA256 hash of canonical CAR (binds permit to action)
            agent_id: Agent requesting execution
            tool: Tool name
            operation: Operation name
            caveats: Additional constraints (max_uses, path restrictions, etc.)
            metadata: Decision context (reason, approval_id, etc.)

        Returns:
            SignedPermit with HMAC signature
        """
        now = datetime.utcnow()
        expires = now + timedelta(seconds=PERMIT_VALIDITY_SECONDS)

        permit = Permit(
            permit_id=str(uuid.uuid4()),
            issued_at=now.isoformat() + "Z",
            expires_at=expires.isoformat() + "Z",
            issuer="guard-daemon@localhost",
            subject=agent_id,
            car_hash=car_hash,
            caveats=caveats or {"tool": tool, "operation": operation, "max_uses": 1},
            metadata=metadata or {},
        )

        signature = self._sign(permit)

        return SignedPermit(permit=permit, signature=signature)

    def _sign(self, permit: Permit) -> str:
        """
        Sign permit with HMAC-SHA256.

        Uses canonical JSON serialization (sorted keys, no whitespace)
        to ensure signature stability.
        """
        canonical = json.dumps(permit.to_dict(), sort_keys=True, separators=(",", ":"))

        signature = hmac.new(
            self.secret_key, canonical.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        return signature


class PermitValidator:
    """Validates permits before tool execution."""

    def __init__(self, secret_key: bytes = PERMIT_SECRET_KEY):
        self.secret_key = secret_key

    def validate(
        self, signed_permit: Dict[str, Any], current_car_hash: str
    ) -> tuple[bool, Optional[str]]:
        """
        Validate permit signature and constraints.

        Args:
            signed_permit: Permit with signature from daemon
            current_car_hash: Hash of current action being executed

        Returns:
            (valid, error_reason) tuple
        """
        try:
            # Extract signature
            signature = signed_permit.get("signature")
            if not signature:
                return False, "No signature in permit"

            # Reconstruct permit (without signature)
            permit_data = {k: v for k, v in signed_permit.items() if k != "signature"}

            # 1. Verify HMAC signature
            canonical = json.dumps(permit_data, sort_keys=True, separators=(",", ":"))
            expected_signature = hmac.new(
                self.secret_key, canonical.encode("utf-8"), hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(signature, expected_signature):
                return False, "Invalid signature"

            # 2. Check expiry (with 5s clock skew tolerance)
            expires_at = datetime.fromisoformat(
                permit_data["expires_at"].replace("Z", "+00:00")
            )
            now = datetime.utcnow()

            if now > expires_at + timedelta(seconds=5):
                return False, "Permit expired"

            # 3. CRITICAL: Check CAR hash match (prevents replay attacks)
            if permit_data["car_hash"] != current_car_hash:
                return False, "CAR hash mismatch - permit bound to different action"

            # 4. Check use count (if tracked)
            # TODO: Track permit uses in database

            return True, None

        except Exception as e:
            return False, f"Permit validation error: {str(e)}"
