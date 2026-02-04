"""
Base extractor class and types.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from enum import Enum


class RiskFactor(Enum):
    """Risk factors that extractors can identify."""

    # Execution risks
    SHELL_INJECTION = "shell_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    REMOTE_CODE = "remote_code"
    SYSTEM_MODIFICATION = "system_modification"

    # Filesystem risks
    PATH_TRAVERSAL = "path_traversal"
    SENSITIVE_PATH = "sensitive_path"
    PERMISSION_CHANGE = "permission_change"
    RECURSIVE_DELETE = "recursive_delete"

    # Network risks
    EXTERNAL_NETWORK = "external_network"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    DATA_EXFILTRATION = "data_exfiltration"
    UNSECURED_PROTOCOL = "unsecured_protocol"

    # Browser risks
    CREDENTIAL_ACCESS = "credential_access"
    SENSITIVE_SITE = "sensitive_site"
    FORM_SUBMISSION = "form_submission"
    DOWNLOAD = "download"


@dataclass
class ExtractedTarget:
    """Represents an extracted target (file, URL, etc.)."""

    kind: str  # file, url, host, command, etc.
    value: str
    normalized: Optional[str] = None
    sensitive: bool = False
    internal: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtractorResult:
    """Result from a CAR extractor."""

    # Tool classification
    tool_name: str
    operation: str
    authority_domain: str

    # Extracted targets
    targets: List[ExtractedTarget] = field(default_factory=list)

    # Risk assessment
    risk_factors: List[RiskFactor] = field(default_factory=list)
    risk_score: int = 0  # 0-100

    # Normalized representation
    normalized_args: Dict[str, Any] = field(default_factory=dict)

    # Additional context
    blast_radius: str = "user"  # user, workspace, system, network
    reversibility: str = "reversible"  # reversible, partial, irreversible
    human_summary: str = ""

    # Recommendations
    requires_approval: bool = False
    approval_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool_name": self.tool_name,
            "operation": self.operation,
            "authority_domain": self.authority_domain,
            "targets": [
                {
                    "kind": t.kind,
                    "value": t.value,
                    "normalized": t.normalized,
                    "sensitive": t.sensitive,
                    "internal": t.internal,
                    "metadata": t.metadata,
                }
                for t in self.targets
            ],
            "risk_factors": [rf.value for rf in self.risk_factors],
            "risk_score": self.risk_score,
            "normalized_args": self.normalized_args,
            "blast_radius": self.blast_radius,
            "reversibility": self.reversibility,
            "human_summary": self.human_summary,
            "requires_approval": self.requires_approval,
            "approval_reason": self.approval_reason,
        }


class BaseExtractor(ABC):
    """
    Base class for CAR extractors.

    Each extractor specializes in extracting context from specific tool types.
    """

    # Tool patterns this extractor handles
    tool_patterns: List[str] = []

    @classmethod
    def matches(cls, tool_name: str) -> bool:
        """Check if this extractor handles the given tool."""
        tool_lower = tool_name.lower()
        return any(pattern in tool_lower for pattern in cls.tool_patterns)

    @abstractmethod
    def extract(self, tool_name: str, args: Dict[str, Any]) -> ExtractorResult:
        """
        Extract rich context from tool arguments.

        Args:
            tool_name: Name of the tool being called
            args: Arguments passed to the tool

        Returns:
            ExtractorResult with extracted context
        """
        pass

    @staticmethod
    def normalize_path(path: str) -> str:
        """Normalize a file path for comparison."""
        import os

        # Expand user home
        path = os.path.expanduser(path)

        # Resolve relative paths
        if not os.path.isabs(path):
            path = os.path.abspath(path)

        # Normalize path separators
        path = os.path.normpath(path)

        return path

    @staticmethod
    def is_sensitive_path(path: str) -> bool:
        """Check if a path is sensitive."""
        sensitive_patterns = [
            ".ssh",
            ".gnupg",
            ".aws",
            ".config",
            "id_rsa",
            "id_ed25519",
            "credentials",
            ".env",
            "secrets",
            "private",
            "password",
            ".kube",
            "token",
        ]

        path_lower = path.lower()
        return any(pattern in path_lower for pattern in sensitive_patterns)

    @staticmethod
    def is_system_path(path: str) -> bool:
        """Check if a path is a system path."""
        system_prefixes = [
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/System",
            "/Library",
            "/etc",
            "/var",
            "/private",
            "C:\\Windows",
            "C:\\Program Files",
        ]

        return any(path.startswith(prefix) for prefix in system_prefixes)
