"""
Filesystem extractor - extracts context from file operations.
"""

import os
import re
from typing import Dict, Any, List

from .base import (
    BaseExtractor,
    ExtractorResult,
    ExtractedTarget,
    RiskFactor,
)


class FileSystemExtractor(BaseExtractor):
    """Extractor for filesystem operations."""

    tool_patterns = ["file", "fs", "write", "read", "edit", "create"]

    # Sensitive file patterns
    SENSITIVE_PATTERNS = [
        r"\.ssh/",
        r"\.gnupg/",
        r"\.aws/",
        r"\.kube/",
        r"id_rsa",
        r"id_ed25519",
        r"\.env",
        r"secrets?\.",
        r"password",
        r"credential",
        r"token",
        r"api[_-]?key",
        r"private[_-]?key",
        r"\.pem$",
        r"\.key$",
        r"\.p12$",
        r"\.pfx$",
    ]

    # System paths
    SYSTEM_PATHS = [
        "/etc/",
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/System/",
        "/Library/",
        "/var/",
        "/private/",
        "C:\\Windows\\",
        "C:\\Program Files\\",
    ]

    def extract(self, tool_name: str, args: Dict[str, Any]) -> ExtractorResult:
        """Extract context from filesystem operation."""

        # Determine operation type
        operation = self._classify_operation(tool_name, args)

        # Extract file paths
        paths = self._extract_paths(args)

        # Build targets
        targets = []
        for path in paths:
            normalized = self.normalize_path(path)
            targets.append(
                ExtractedTarget(
                    kind="file",
                    value=path,
                    normalized=normalized,
                    sensitive=self._is_sensitive_file(normalized),
                    internal=True,
                    metadata={
                        "system_path": self._is_system_path(normalized),
                        "exists": os.path.exists(normalized),
                        "is_dir": (
                            os.path.isdir(normalized)
                            if os.path.exists(normalized)
                            else None
                        ),
                    },
                )
            )

        # Assess risks
        risk_factors, risk_score = self._assess_risks(operation, targets, args)

        # Determine blast radius
        blast_radius = self._determine_blast_radius(targets)

        # Determine reversibility
        reversibility = self._determine_reversibility(operation, args)

        # Generate summary
        human_summary = self._generate_summary(operation, paths, args)

        # Check if approval needed
        requires_approval, approval_reason = self._needs_approval(
            operation, targets, risk_factors
        )

        return ExtractorResult(
            tool_name=tool_name,
            operation=operation,
            authority_domain="filesystem",
            targets=targets,
            risk_factors=risk_factors,
            risk_score=risk_score,
            normalized_args=args,
            blast_radius=blast_radius,
            reversibility=reversibility,
            human_summary=human_summary,
            requires_approval=requires_approval,
            approval_reason=approval_reason,
        )

    def _classify_operation(self, tool_name: str, args: Dict[str, Any]) -> str:
        """Classify the filesystem operation."""
        tool_lower = tool_name.lower()

        # From tool name
        if "write" in tool_lower or "create" in tool_lower:
            return "write"
        elif "read" in tool_lower or "get" in tool_lower:
            return "read"
        elif "delete" in tool_lower or "remove" in tool_lower:
            return "delete"
        elif "list" in tool_lower or "dir" in tool_lower:
            return "list"
        elif "edit" in tool_lower or "modify" in tool_lower:
            return "edit"
        elif "copy" in tool_lower or "cp" in tool_lower:
            return "copy"
        elif "move" in tool_lower or "mv" in tool_lower or "rename" in tool_lower:
            return "move"
        elif "chmod" in tool_lower or "permission" in tool_lower:
            return "permission"

        # From args
        if "content" in args or "data" in args:
            return "write"
        elif "destination" in args or "dest" in args:
            return "copy" if "source" in args else "write"

        return "access"

    def _extract_paths(self, args: Dict[str, Any]) -> List[str]:
        """Extract file paths from arguments."""
        paths = []

        # Common path argument names
        path_keys = [
            "path",
            "file",
            "filepath",
            "file_path",
            "filename",
            "source",
            "src",
            "destination",
            "dest",
            "target",
            "directory",
            "dir",
            "folder",
        ]

        for key in path_keys:
            if key in args:
                value = args[key]
                if isinstance(value, str):
                    paths.append(value)
                elif isinstance(value, list):
                    paths.extend(str(v) for v in value)

        # Check for paths in nested structures
        for key, value in args.items():
            if isinstance(value, str) and (
                value.startswith("/")
                or value.startswith("~")
                or value.startswith("./")
                or value.startswith("../")
            ):
                if value not in paths:
                    paths.append(value)

        return paths

    def _is_sensitive_file(self, path: str) -> bool:
        """Check if file path is sensitive."""
        path_lower = path.lower()

        for pattern in self.SENSITIVE_PATTERNS:
            if re.search(pattern, path_lower):
                return True

        return False

    def _is_system_path(self, path: str) -> bool:
        """Check if path is a system path."""
        for sys_path in self.SYSTEM_PATHS:
            if path.startswith(sys_path):
                return True
        return False

    def _assess_risks(
        self,
        operation: str,
        targets: List[ExtractedTarget],
        args: Dict[str, Any],
    ) -> tuple[List[RiskFactor], int]:
        """Assess risk factors."""
        factors = []
        score = 0

        # Check for path traversal
        for target in targets:
            if ".." in target.value:
                factors.append(RiskFactor.PATH_TRAVERSAL)
                score += 20
                break

        # Check for sensitive paths
        for target in targets:
            if target.sensitive:
                factors.append(RiskFactor.SENSITIVE_PATH)
                score += 30
                break

        # Check for system paths
        for target in targets:
            if target.metadata.get("system_path"):
                factors.append(RiskFactor.SYSTEM_MODIFICATION)
                score += 25
                break

        # Operation-specific risks
        if operation == "delete":
            score += 20
            # Check for recursive
            if args.get("recursive", False):
                factors.append(RiskFactor.RECURSIVE_DELETE)
                score += 30

        if operation == "permission":
            factors.append(RiskFactor.PERMISSION_CHANGE)
            score += 20

        # Check content for secrets
        content = args.get("content", "")
        if isinstance(content, str):
            secret_patterns = [
                r"password\s*[=:]\s*",
                r"api[_-]?key\s*[=:]\s*",
                r"secret\s*[=:]\s*",
                r"token\s*[=:]\s*",
                r"-----BEGIN.*PRIVATE KEY-----",
            ]
            for pattern in secret_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    factors.append(RiskFactor.CREDENTIAL_EXPOSURE)
                    score += 25
                    break

        return factors, min(score, 100)

    def _determine_blast_radius(self, targets: List[ExtractedTarget]) -> str:
        """Determine blast radius based on targets."""
        for target in targets:
            if target.metadata.get("system_path"):
                return "system"

        return "workspace"

    def _determine_reversibility(self, operation: str, args: Dict[str, Any]) -> str:
        """Determine if operation is reversible."""
        if operation == "delete":
            return "irreversible"

        if operation in ("permission", "move"):
            return "partial"

        if operation == "write":
            # Overwriting existing file is partially reversible
            return "partial"

        return "reversible"

    def _generate_summary(
        self,
        operation: str,
        paths: List[str],
        args: Dict[str, Any],
    ) -> str:
        """Generate human-readable summary."""
        if not paths:
            return f"Filesystem {operation}"

        # Show first path, abbreviate rest
        path_display = paths[0]
        if len(paths) > 1:
            path_display += f" (+{len(paths) - 1} more)"

        return f"{operation.capitalize()} file: {path_display}"

    def _needs_approval(
        self,
        operation: str,
        targets: List[ExtractedTarget],
        risk_factors: List[RiskFactor],
    ) -> tuple[bool, str | None]:
        """Determine if operation needs approval."""

        # Delete always needs approval
        if operation == "delete":
            return True, "File deletion requires approval"

        # System paths need approval
        for target in targets:
            if target.metadata.get("system_path"):
                return True, f"System path access: {target.value}"

        # Sensitive files need approval
        for target in targets:
            if target.sensitive:
                return True, f"Sensitive file access: {target.value}"

        # Permission changes need approval
        if operation == "permission":
            return True, "Permission change requires approval"

        # High risk
        if RiskFactor.CREDENTIAL_EXPOSURE in risk_factors:
            return True, "Credential exposure detected"

        return False, None
