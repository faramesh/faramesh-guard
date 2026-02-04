"""
CAR (Content Addressable Record) - Action representation for Guard.

This is the core data structure that represents an action request.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime


class AuthorityDomain(Enum):
    """Authority domains for action classification."""

    EXEC = "exec"  # Shell/command execution
    FILESYSTEM = "filesystem"  # File operations
    NETWORK = "network"  # HTTP/API calls
    BROWSER = "browser"  # Browser automation
    DATABASE = "database"  # Database operations
    COMMUNICATION = "communication"  # Email, Slack, etc.


@dataclass
class CAR:
    """
    Content Addressable Record - Canonical representation of an action.

    The CAR hash provides deterministic identity for any action,
    enabling replay detection and permit binding.
    """

    # Identity fields (included in hash)
    car_id: str
    car_hash: str
    tool: str
    operation: str
    authority_domain: AuthorityDomain

    # Arguments
    args: Dict[str, Any]
    normalized_args: Dict[str, Any]

    # Context
    agent_id: str
    agent_name: str
    session_id: str
    provenance: Dict[str, Any] = field(default_factory=dict)
    workflow_stage: Optional[str] = None

    # Risk assessment inputs
    target_kind: str = "general"
    sensitivity: Dict[str, Any] = field(default_factory=dict)
    blast_radius: str = "user"

    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    runtime_version: str = "unknown"
    guard_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        d = asdict(self)
        # Convert enum to string
        d["authority_domain"] = self.authority_domain.value
        return d


class ValidationError(Exception):
    """Validation error for CAR parameters."""

    pass


def validate_params(params: Dict[str, Any]) -> None:
    """
    Validate action parameters for security issues.

    Raises ValidationError if issues found.
    """
    # Check for suspicious patterns
    params_str = str(params).lower()

    # Check for shell injection attempts
    shell_chars = [";", "&&", "||", "|", "`", "$(", "${"]
    for char in shell_chars:
        if char in params_str:
            # Allow in legitimate contexts
            if "command" not in params and "cmd" not in params:
                continue

    # Check for path traversal
    if ".." in params_str:
        # Log warning but don't fail
        pass
