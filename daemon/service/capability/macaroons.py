"""
Macaroons-Style Capability Permits with Caveats

Implements capability-based authorization using macaroon-inspired permits.
Unlike simple boolean approve/deny, permits carry structured caveats that
constrain exactly what was authorized.

Key Features:
- Chained caveats that can be attenuated (never expanded)
- HMAC signature verification
- TTL and use-count limits
- Delegation support with caveat restriction
- Bound to specific CAR hash (replay protection)

Reference: Google Research - Macaroons: Cookies with Contextual Caveats
"""

import hmac
import hashlib
import json
import uuid
import base64
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging

logger = logging.getLogger("guard.capability.macaroons")

# Secret key for HMAC signing (in production, load from secure key storage)
MACAROON_ROOT_KEY = b"guard-v1-macaroon-root-key-CHANGE-IN-PRODUCTION"


class CaveatType(Enum):
    """Types of caveats that can constrain permits."""
    FIRST_PARTY = "first_party"  # Verified by Guard itself
    THIRD_PARTY = "third_party"  # Requires external verification


class CaveatOperator(Enum):
    """Operators for caveat conditions."""
    EQUALS = "eq"
    NOT_EQUALS = "neq"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUAL = "lte"
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    MATCHES = "matches"  # Regex match
    GLOB = "glob"  # Glob pattern match
    IN = "in"  # In list
    NOT_IN = "not_in"


@dataclass
class Caveat:
    """
    A caveat is a condition that must be satisfied for the permit to be valid.
    Caveats can only restrict (attenuate) permissions, never expand them.
    """
    caveat_id: str
    field: str  # Field in CAR to check (e.g., "tool", "destination", "args.path")
    operator: CaveatOperator
    value: Any  # Expected value
    reason: str = ""  # Human-readable explanation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "caveat_id": self.caveat_id,
            "field": self.field,
            "operator": self.operator.value,
            "value": self.value,
            "reason": self.reason
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Caveat":
        return cls(
            caveat_id=data["caveat_id"],
            field=data["field"],
            operator=CaveatOperator(data["operator"]),
            value=data["value"],
            reason=data.get("reason", "")
        )


@dataclass
class MacaroonPermit:
    """
    Macaroon-style permit with chained caveats.

    Structure:
    - identifier: Unique permit ID
    - location: Issuing authority (Guard daemon)
    - caveats: Chain of restrictions
    - signature: HMAC chain of (secret, identifier, caveats...)
    """
    identifier: str
    location: str
    car_hash: str  # Bound to specific action
    issued_at: str
    expires_at: str
    caveats: List[Caveat] = field(default_factory=list)
    signature: str = ""

    # Metadata
    issuer: str = "guard-daemon"
    subject: str = ""  # agent_id
    use_count: int = 0
    max_uses: int = 1
    delegated_from: Optional[str] = None  # Parent permit if delegated

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for transmission."""
        return {
            "identifier": self.identifier,
            "location": self.location,
            "car_hash": self.car_hash,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "caveats": [c.to_dict() for c in self.caveats],
            "signature": self.signature,
            "issuer": self.issuer,
            "subject": self.subject,
            "use_count": self.use_count,
            "max_uses": self.max_uses,
            "delegated_from": self.delegated_from
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MacaroonPermit":
        """Deserialize from dictionary."""
        caveats = [Caveat.from_dict(c) for c in data.get("caveats", [])]
        return cls(
            identifier=data["identifier"],
            location=data["location"],
            car_hash=data["car_hash"],
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            caveats=caveats,
            signature=data.get("signature", ""),
            issuer=data.get("issuer", "guard-daemon"),
            subject=data.get("subject", ""),
            use_count=data.get("use_count", 0),
            max_uses=data.get("max_uses", 1),
            delegated_from=data.get("delegated_from")
        )

    def add_caveat(self, caveat: Caveat) -> "MacaroonPermit":
        """
        Add a caveat to restrict the permit further.
        Returns a new permit with the caveat added and signature updated.
        """
        # Clone current permit
        new_permit = MacaroonPermit(
            identifier=self.identifier,
            location=self.location,
            car_hash=self.car_hash,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            caveats=self.caveats + [caveat],
            signature="",  # Will be recomputed
            issuer=self.issuer,
            subject=self.subject,
            use_count=self.use_count,
            max_uses=self.max_uses,
            delegated_from=self.delegated_from
        )
        return new_permit


class MacaroonMinter:
    """
    Mints macaroon-style permits with chained HMAC signatures.

    Signature chain:
    sig_0 = HMAC(root_key, identifier)
    sig_i = HMAC(sig_{i-1}, caveat_i)
    final_signature = sig_n (last in chain)
    """

    def __init__(self, root_key: bytes = MACAROON_ROOT_KEY):
        self.root_key = root_key
        self.location = "guard-daemon@localhost"

    def mint(
        self,
        car_hash: str,
        agent_id: str,
        tool: str,
        operation: str,
        ttl_seconds: int = 120,
        max_uses: int = 1,
        additional_caveats: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> MacaroonPermit:
        """
        Mint a new macaroon permit.

        Args:
            car_hash: SHA-256 hash of the CAR (binds permit to specific action)
            agent_id: Agent requesting the action
            tool: Tool being authorized
            operation: Operation being authorized
            ttl_seconds: Time-to-live in seconds
            max_uses: Maximum number of times permit can be used
            additional_caveats: Extra caveats to add
            metadata: Additional metadata for audit

        Returns:
            Signed MacaroonPermit
        """
        now = datetime.utcnow()
        expires = now + timedelta(seconds=ttl_seconds)
        identifier = str(uuid.uuid4())

        # Create base permit
        permit = MacaroonPermit(
            identifier=identifier,
            location=self.location,
            car_hash=car_hash,
            issued_at=now.isoformat() + "Z",
            expires_at=expires.isoformat() + "Z",
            caveats=[],
            issuer=self.location,
            subject=agent_id,
            max_uses=max_uses
        )

        # Add standard caveats
        standard_caveats = [
            Caveat(
                caveat_id=f"caveat_{uuid.uuid4().hex[:8]}",
                field="tool",
                operator=CaveatOperator.EQUALS,
                value=tool,
                reason=f"Permit only valid for tool: {tool}"
            ),
            Caveat(
                caveat_id=f"caveat_{uuid.uuid4().hex[:8]}",
                field="operation",
                operator=CaveatOperator.EQUALS,
                value=operation,
                reason=f"Permit only valid for operation: {operation}"
            ),
            Caveat(
                caveat_id=f"caveat_{uuid.uuid4().hex[:8]}",
                field="expires_at",
                operator=CaveatOperator.LESS_THAN,
                value=permit.expires_at,
                reason=f"Permit expires at {permit.expires_at}"
            ),
            Caveat(
                caveat_id=f"caveat_{uuid.uuid4().hex[:8]}",
                field="car_hash",
                operator=CaveatOperator.EQUALS,
                value=car_hash,
                reason="Permit bound to specific action (replay protection)"
            )
        ]
        permit.caveats.extend(standard_caveats)

        # Add any additional caveats
        if additional_caveats:
            for caveat_data in additional_caveats:
                caveat = Caveat(
                    caveat_id=f"caveat_{uuid.uuid4().hex[:8]}",
                    field=caveat_data["field"],
                    operator=CaveatOperator(caveat_data.get("operator", "eq")),
                    value=caveat_data["value"],
                    reason=caveat_data.get("reason", "")
                )
                permit.caveats.append(caveat)

        # Compute chained signature
        permit.signature = self._compute_signature(permit)

        logger.info(f"Minted permit {identifier[:8]} for {tool}.{operation} with {len(permit.caveats)} caveats")

        return permit

    def mint_delegated(
        self,
        parent_permit: MacaroonPermit,
        additional_caveats: List[Caveat],
        delegator: str
    ) -> MacaroonPermit:
        """
        Create a delegated permit by adding caveats to an existing permit.
        The delegated permit can only be MORE restrictive, never less.

        Args:
            parent_permit: The original permit being delegated
            additional_caveats: Caveats to add (must be more restrictive)
            delegator: Who is delegating

        Returns:
            New permit with additional caveats
        """
        # Create delegated permit
        delegated = MacaroonPermit(
            identifier=str(uuid.uuid4()),
            location=parent_permit.location,
            car_hash=parent_permit.car_hash,
            issued_at=datetime.utcnow().isoformat() + "Z",
            expires_at=parent_permit.expires_at,  # Cannot extend TTL
            caveats=parent_permit.caveats + additional_caveats,
            issuer=delegator,
            subject=parent_permit.subject,
            use_count=0,
            max_uses=min(1, parent_permit.max_uses - parent_permit.use_count),  # Cannot exceed remaining uses
            delegated_from=parent_permit.identifier
        )

        # Recompute signature with new caveats
        delegated.signature = self._compute_signature(delegated)

        logger.info(f"Created delegated permit from {parent_permit.identifier[:8]} with {len(additional_caveats)} additional caveats")

        return delegated

    def _compute_signature(self, permit: MacaroonPermit) -> str:
        """
        Compute HMAC signature chain.

        sig_0 = HMAC(root_key, identifier || location || car_hash)
        sig_i = HMAC(sig_{i-1}, caveat_i_canonical)
        final = base64(sig_n)
        """
        # Initial signature over identifier and location
        initial_data = f"{permit.identifier}|{permit.location}|{permit.car_hash}"
        sig = hmac.new(
            self.root_key,
            initial_data.encode("utf-8"),
            hashlib.sha256
        ).digest()

        # Chain caveats into signature
        for caveat in permit.caveats:
            caveat_canonical = json.dumps(caveat.to_dict(), sort_keys=True, separators=(",", ":"))
            sig = hmac.new(
                sig,
                caveat_canonical.encode("utf-8"),
                hashlib.sha256
            ).digest()

        return base64.b64encode(sig).decode("utf-8")


class MacaroonValidator:
    """
    Validates macaroon permits by verifying signature chain and caveats.
    """

    def __init__(self, root_key: bytes = MACAROON_ROOT_KEY):
        self.root_key = root_key
        self.used_permits: Dict[str, int] = {}  # permit_id -> use_count

    def validate(
        self,
        permit: Union[MacaroonPermit, Dict[str, Any]],
        current_car: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate a permit against the current action.

        Checks:
        1. Signature is valid (chain verification)
        2. All caveats are satisfied by current CAR
        3. TTL not expired
        4. Use count not exceeded
        5. CAR hash matches

        Args:
            permit: The permit to validate
            current_car: The current CAR being executed

        Returns:
            (valid, error_reason) tuple
        """
        # Deserialize if needed
        if isinstance(permit, dict):
            try:
                permit = MacaroonPermit.from_dict(permit)
            except Exception as e:
                return False, f"Invalid permit format: {e}"

        # 1. Verify signature
        sig_valid, sig_error = self._verify_signature(permit)
        if not sig_valid:
            return False, sig_error

        # 2. Check expiry
        try:
            expires_at = datetime.fromisoformat(permit.expires_at.replace("Z", "+00:00"))
            now = datetime.utcnow().replace(tzinfo=expires_at.tzinfo)

            # Allow 5 second clock skew
            if now > expires_at + timedelta(seconds=5):
                return False, f"Permit expired at {permit.expires_at}"
        except Exception as e:
            return False, f"Invalid expiry timestamp: {e}"

        # 3. Check use count
        current_uses = self.used_permits.get(permit.identifier, 0)
        if current_uses >= permit.max_uses:
            return False, f"Permit use limit exceeded ({current_uses}/{permit.max_uses})"

        # 4. Check CAR hash match (replay protection)
        current_car_hash = current_car.get("car_hash", "")
        if permit.car_hash != current_car_hash:
            return False, f"CAR hash mismatch: permit bound to different action"

        # 5. Validate all caveats
        for caveat in permit.caveats:
            caveat_valid, caveat_error = self._validate_caveat(caveat, current_car)
            if not caveat_valid:
                return False, f"Caveat violated: {caveat_error}"

        # Record use
        self.used_permits[permit.identifier] = current_uses + 1

        return True, None

    def _verify_signature(self, permit: MacaroonPermit) -> Tuple[bool, Optional[str]]:
        """Verify the HMAC signature chain."""
        try:
            # Recompute signature
            initial_data = f"{permit.identifier}|{permit.location}|{permit.car_hash}"
            sig = hmac.new(
                self.root_key,
                initial_data.encode("utf-8"),
                hashlib.sha256
            ).digest()

            for caveat in permit.caveats:
                caveat_canonical = json.dumps(caveat.to_dict(), sort_keys=True, separators=(",", ":"))
                sig = hmac.new(
                    sig,
                    caveat_canonical.encode("utf-8"),
                    hashlib.sha256
                ).digest()

            expected_signature = base64.b64encode(sig).decode("utf-8")

            if not hmac.compare_digest(expected_signature, permit.signature):
                return False, "Signature verification failed"

            return True, None
        except Exception as e:
            return False, f"Signature verification error: {e}"

    def _validate_caveat(self, caveat: Caveat, car: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate a single caveat against the CAR."""
        # Skip expires_at caveat (handled separately)
        if caveat.field == "expires_at":
            return True, None

        # Get field value from CAR (supports nested fields like "args.path")
        field_value = self._get_field_value(car, caveat.field)

        if field_value is None and caveat.field != "car_hash":
            # Field not present - check if caveat requires it
            if caveat.operator in [CaveatOperator.EQUALS, CaveatOperator.CONTAINS]:
                return False, f"Required field '{caveat.field}' not found in CAR"
            return True, None  # Other operators may allow missing fields

        # Apply operator
        try:
            result = self._apply_operator(caveat.operator, field_value, caveat.value)
            if not result:
                return False, f"{caveat.field} {caveat.operator.value} {caveat.value} (got: {field_value})"
            return True, None
        except Exception as e:
            return False, f"Caveat evaluation error: {e}"

    def _get_field_value(self, car: Dict[str, Any], field_path: str) -> Any:
        """Get nested field value from CAR using dot notation."""
        parts = field_path.split(".")
        value = car

        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None

            if value is None:
                return None

        return value

    def _apply_operator(self, operator: CaveatOperator, actual: Any, expected: Any) -> bool:
        """Apply caveat operator to check condition."""
        if operator == CaveatOperator.EQUALS:
            return actual == expected
        elif operator == CaveatOperator.NOT_EQUALS:
            return actual != expected
        elif operator == CaveatOperator.LESS_THAN:
            return actual < expected
        elif operator == CaveatOperator.LESS_THAN_OR_EQUAL:
            return actual <= expected
        elif operator == CaveatOperator.GREATER_THAN:
            return actual > expected
        elif operator == CaveatOperator.GREATER_THAN_OR_EQUAL:
            return actual >= expected
        elif operator == CaveatOperator.CONTAINS:
            return expected in actual if actual else False
        elif operator == CaveatOperator.NOT_CONTAINS:
            return expected not in actual if actual else True
        elif operator == CaveatOperator.MATCHES:
            import re
            return bool(re.match(expected, str(actual)))
        elif operator == CaveatOperator.GLOB:
            import fnmatch
            return fnmatch.fnmatch(str(actual), expected)
        elif operator == CaveatOperator.IN:
            return actual in expected
        elif operator == CaveatOperator.NOT_IN:
            return actual not in expected
        else:
            raise ValueError(f"Unknown operator: {operator}")

    def revoke_permit(self, permit_id: str) -> None:
        """Revoke a permit by marking it as fully used."""
        self.used_permits[permit_id] = 999999  # Effectively revoked


# Convenience functions for creating common caveats
def caveat_tool(tool: str) -> Caveat:
    """Create caveat restricting to specific tool."""
    return Caveat(
        caveat_id=f"caveat_{uuid.uuid4().hex[:8]}",
        field="tool",
        operator=CaveatOperator.EQUALS,
        value=tool,
        reason=f"Only valid for tool: {tool}"
    )


def caveat_path_prefix(prefix: str) -> Caveat:
    """Create caveat restricting to paths under a prefix."""
    return Caveat(
        caveat_id=f"caveat_{uuid.uuid4().hex[:8]}",
        field="target",
        operator=CaveatOperator.GLOB,
        value=f"{prefix}/**",
        reason=f"Only valid for paths under: {prefix}"
    )


def caveat_domain(domain: str) -> Caveat:
    """Create caveat restricting to specific domain."""
    return Caveat(
        caveat_id=f"caveat_{uuid.uuid4().hex[:8]}",
        field="destination",
        operator=CaveatOperator.MATCHES,
        value=f".*@?{domain.replace('.', r'\\.')}$",
        reason=f"Only valid for domain: {domain}"
    )


def caveat_max_amount(amount: float) -> Caveat:
    """Create caveat restricting money amount."""
    return Caveat(
        caveat_id=f"caveat_{uuid.uuid4().hex[:8]}",
        field="sensitivity.money_amount",
        operator=CaveatOperator.LESS_THAN_OR_EQUAL,
        value=amount,
        reason=f"Only valid for amounts up to ${amount}"
    )


def caveat_no_external() -> Caveat:
    """Create caveat blocking external destinations."""
    return Caveat(
        caveat_id=f"caveat_{uuid.uuid4().hex[:8]}",
        field="destination_external",
        operator=CaveatOperator.EQUALS,
        value=False,
        reason="Only valid for internal destinations"
    )


# Singleton instances
_minter: Optional[MacaroonMinter] = None
_validator: Optional[MacaroonValidator] = None


def get_macaroon_minter() -> MacaroonMinter:
    """Get singleton macaroon minter."""
    global _minter
    if _minter is None:
        _minter = MacaroonMinter()
    return _minter


def get_macaroon_validator() -> MacaroonValidator:
    """Get singleton macaroon validator."""
    global _validator
    if _validator is None:
        _validator = MacaroonValidator()
    return _validator
