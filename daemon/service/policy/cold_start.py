"""
Cold Start Bootstrap - Domain-Specific Policy Templates

Loads sensible policy defaults for first-run users based on use case:
- DevOps & Development
- Finance Operations
- Customer Support
- Infrastructure & Operations

Following guard-plan-v1.md Section 4: Trust Bootstrapping / First-Run Safety Model
"""

import logging
import yaml
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class UseCaseTemplate(Enum):
    """Available cold-start templates."""

    DEVOPS = "dev"
    FINANCE_OPS = "finance"
    SUPPORT = "support"
    INFRA = "infra"


class SafetyMode(Enum):
    """Safety mode for policy enforcement."""

    SAFE = "safe"  # Balanced: allow common patterns, prompt for risky
    STRICT = "strict"  # Conservative: require approval for most changes
    PERMISSIVE = "permissive"  # Liberal: allow most, block only critical


@dataclass
class PolicyBundle:
    """Policy bundle loaded from cold-start template."""

    name: str
    description: str
    mode: SafetyMode
    allow_patterns: List[Dict]
    require_approval: List[Dict]
    deny_patterns: List[Dict]
    version: str
    source: str


class ColdStartBootstrap:
    """
    Load domain-specific policy packs for first-run users.

    Provides sensible defaults based on use case, eliminating
    the "blank slate" problem for new users.
    """

    def __init__(self, policy_dir: Optional[Path] = None):
        if policy_dir is None:
            # Default to package directory
            policy_dir = Path(__file__).parent / "cold_start"
        self.cold_start_dir = policy_dir
        logger.info(f"ColdStartBootstrap initialized with dir={self.cold_start_dir}")

    def initialize_new_user(
        self, use_case: UseCaseTemplate, mode: Optional[SafetyMode] = None
    ) -> PolicyBundle:
        """
        Load appropriate cold-start policy pack.

        Args:
            use_case: Use case template to load
            mode: Safety mode (if None, uses mode from template)

        Returns:
            PolicyBundle with loaded policies
        """
        pack_file = self.cold_start_dir / f"{use_case.value}.yaml"

        if not pack_file.exists():
            logger.warning(f"Cold-start pack not found: {pack_file}")
            return self._get_default_policy(mode or SafetyMode.SAFE)

        # Load YAML pack
        try:
            with open(pack_file) as f:
                pack = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load policy pack {pack_file}: {e}")
            return self._get_default_policy(mode or SafetyMode.SAFE)

        # Override mode if specified
        if mode is None:
            mode = SafetyMode(pack.get("mode", "safe"))

        policy = PolicyBundle(
            name=pack["name"],
            description=pack["description"],
            mode=mode,
            allow_patterns=pack.get("allow_patterns", []),
            require_approval=pack.get("require_approval", []),
            deny_patterns=pack.get("deny", []),
            version=pack.get("version", "1.0"),
            source="cold_start_template",
        )

        logger.info(
            f"Initialized cold-start policy: {pack['name']} in {mode.value} mode "
            f"({len(policy.allow_patterns)} allow, {len(policy.require_approval)} approval, "
            f"{len(policy.deny_patterns)} deny)"
        )

        return policy

    def list_available_templates(self) -> List[str]:
        """List available cold-start templates."""
        templates = []
        if self.cold_start_dir.exists():
            for file in self.cold_start_dir.glob("*.yaml"):
                templates.append(file.stem)
        return templates

    def get_template_info(self, use_case: UseCaseTemplate) -> Optional[Dict]:
        """Get information about a template without loading full policy."""
        pack_file = self.cold_start_dir / f"{use_case.value}.yaml"

        if not pack_file.exists():
            return None

        try:
            with open(pack_file) as f:
                pack = yaml.safe_load(f)
            return {
                "name": pack.get("name"),
                "description": pack.get("description"),
                "mode": pack.get("mode"),
                "version": pack.get("version"),
            }
        except Exception as e:
            logger.error(f"Failed to load template info: {e}")
            return None

    def _get_default_policy(self, mode: SafetyMode) -> PolicyBundle:
        """
        Get default policy when no template is available.

        Very conservative: require approval for most actions.
        """
        return PolicyBundle(
            name="Default Safe Policy",
            description="Conservative defaults requiring approval for most actions",
            mode=mode,
            allow_patterns=[
                {
                    "tool": "fs",
                    "operation": "read",
                    "risk": "low",
                    "reason": "File reading is safe",
                }
            ],
            require_approval=[
                {
                    "tool": "*",
                    "operation": "*",
                    "risk": "medium",
                    "reason": "All operations require approval by default",
                }
            ],
            deny_patterns=[
                {
                    "tool": "exec",
                    "has_sudo": True,
                    "risk": "critical",
                    "reason": "Privilege escalation blocked",
                }
            ],
            version="1.0",
            source="default_fallback",
        )

    def evaluate_policy(self, policy: PolicyBundle, action: Dict) -> str:
        """
        Evaluate action against policy bundle.

        Args:
            policy: Loaded policy bundle
            action: Action to evaluate (CAR-like dict)

        Returns:
            "ALLOW", "DENY", or "REQUIRE_APPROVAL"
        """
        # Check deny patterns first (highest priority)
        for pattern in policy.deny_patterns:
            if self._matches_pattern(action, pattern):
                logger.info(f"Action denied by pattern: {pattern.get('reason')}")
                return "DENY"

        # Check allow patterns
        for pattern in policy.allow_patterns:
            if self._matches_pattern(action, pattern):
                logger.debug(f"Action allowed by pattern: {pattern.get('reason')}")
                return "ALLOW"

        # Check require_approval patterns
        for pattern in policy.require_approval:
            if self._matches_pattern(action, pattern):
                logger.info(f"Action requires approval: {pattern.get('reason')}")
                return "REQUIRE_APPROVAL"

        # Default: require approval for unknown actions in strict mode
        if policy.mode == SafetyMode.STRICT:
            return "REQUIRE_APPROVAL"
        elif policy.mode == SafetyMode.PERMISSIVE:
            return "ALLOW"
        else:  # SAFE mode
            return "REQUIRE_APPROVAL"

    def _matches_pattern(self, action: Dict, pattern: Dict) -> bool:
        """
        Check if action matches pattern.

        Simple matching logic:
        - tool: exact match or wildcard
        - operation: substring or regex
        - other fields: exact match
        """
        # Check tool
        if "tool" in pattern:
            pattern_tool = pattern["tool"]
            action_tool = action.get("tool", "")

            if pattern_tool != "*" and pattern_tool != action_tool:
                return False

        # Check operation
        if "operation" in pattern:
            pattern_op = pattern["operation"]
            action_op = action.get("operation", "")

            if "|" in pattern_op:
                # Multiple operations (OR)
                if not any(op in action_op for op in pattern_op.split("|")):
                    return False
            elif pattern_op != "*" and pattern_op not in action_op:
                return False

        # Check binary (for exec tools)
        if "binary" in pattern:
            pattern_bin = pattern["binary"]
            action_bin = action.get("binary", "")

            if pattern_bin != "*" and pattern_bin not in action_bin:
                return False

        # More matching logic can be added here
        # For now, this is a simple implementation

        return True


# Singleton instance
_cold_start: Optional[ColdStartBootstrap] = None


def get_cold_start_bootstrap() -> ColdStartBootstrap:
    """Get or create singleton ColdStartBootstrap instance."""
    global _cold_start
    if _cold_start is None:
        _cold_start = ColdStartBootstrap()
    return _cold_start
