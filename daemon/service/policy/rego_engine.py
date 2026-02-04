"""
OPA/Rego Policy Engine - Formal Policy Evaluation

Implements the formal policy engine using OPA (Open Policy Agent) with Rego.
This replaces the hardcoded pattern-matching rules with a real policy runtime.

Features:
- Load policies from .rego files
- Compile YAML policy packs to Rego
- Evaluate CARs against policy bundles
- Support for modes (relaxed/safe/strict/locked)
- Hot-reload policy changes
"""

import json
import hashlib
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging
import os
import yaml

logger = logging.getLogger("guard.policy.rego")


class PolicyDecision(Enum):
    """Policy evaluation result."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"
    ABSTAIN = "ABSTAIN"  # Policy doesn't match, fall through to defaults


@dataclass
class PolicyEvaluationResult:
    """Result of policy evaluation."""
    decision: PolicyDecision
    matched_rules: List[str]
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)
    policy_version: str = "1.0.0"


@dataclass
class PolicyBundle:
    """Collection of policies that apply together."""
    name: str
    mode: str  # relaxed, safe, strict, locked
    rego_modules: Dict[str, str]  # filename -> rego content
    version: str = "1.0.0"
    hash: str = ""

    def compute_hash(self) -> str:
        """Compute deterministic hash of all policy content."""
        content = json.dumps(
            {k: self.rego_modules[k] for k in sorted(self.rego_modules.keys())},
            sort_keys=True
        )
        self.hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        return self.hash


class RegoCompiler:
    """Compile YAML policy packs to OPA Rego."""

    def compile_yaml_to_rego(self, yaml_content: Dict[str, Any]) -> str:
        """Convert YAML policy pack to OPA Rego rules."""
        rego_lines = [
            "package faramesh.guard",
            "",
            "import future.keywords.in",
            "import future.keywords.if",
            "import future.keywords.contains",
            "",
            "# Default decisions",
            "default allow := false",
            "default deny := false",
            "default needs_approval := false",
            "",
        ]

        # Generate allow rules
        for i, pattern in enumerate(yaml_content.get("allow_patterns", [])):
            rule = self._compile_pattern_to_rule("allow", f"allow_rule_{i}", pattern)
            rego_lines.append(rule)
            rego_lines.append("")

        # Generate needs_approval rules
        for i, pattern in enumerate(yaml_content.get("require_approval", [])):
            rule = self._compile_pattern_to_rule("needs_approval", f"approval_rule_{i}", pattern)
            rego_lines.append(rule)
            rego_lines.append("")

        # Generate deny rules
        for i, pattern in enumerate(yaml_content.get("deny", [])):
            rule = self._compile_pattern_to_rule("deny", f"deny_rule_{i}", pattern)
            rego_lines.append(rule)
            rego_lines.append("")

        # Add rule aggregation
        rego_lines.extend([
            "# Final decision (deny > needs_approval > allow)",
            "decision := \"DENY\" if {",
            "    deny",
            "}",
            "",
            "decision := \"NEEDS_APPROVAL\" if {",
            "    not deny",
            "    needs_approval",
            "}",
            "",
            "decision := \"ALLOW\" if {",
            "    not deny",
            "    not needs_approval",
            "    allow",
            "}",
            "",
            "decision := \"ABSTAIN\" if {",
            "    not deny",
            "    not needs_approval",
            "    not allow",
            "}",
        ])

        return "\n".join(rego_lines)

    def _compile_pattern_to_rule(self, rule_type: str, rule_name: str, pattern: Dict[str, Any]) -> str:
        """Compile a single pattern to a Rego rule."""
        conditions = []

        # Tool matching
        if "tool" in pattern:
            conditions.append(f'    input.car.tool == "{pattern["tool"]}"')

        # Binary/command matching with regex
        if "binary" in pattern:
            binary_pattern = pattern["binary"].replace("|", "|")
            conditions.append(f'    regex.match(`^({binary_pattern})$`, input.car.binary)')

        # Operation matching
        if "operation" in pattern:
            ops = pattern["operation"].split("|") if isinstance(pattern["operation"], str) else [pattern["operation"]]
            if len(ops) == 1:
                conditions.append(f'    input.car.operation == "{ops[0]}"')
            else:
                conditions.append(f'    input.car.operation in {json.dumps(ops)}')

        # Path matching with glob
        if "path" in pattern:
            path_pattern = pattern["path"].replace("~", os.path.expanduser("~"))
            conditions.append(f'    glob.match(`{path_pattern}`, [], input.car.target)')

        # External destination check
        if pattern.get("destination_external"):
            conditions.append('    input.car.destination_external == true')

        # Domain matching
        if "domain" in pattern:
            domain_pattern = pattern["domain"].replace("|", "|")
            conditions.append(f'    regex.match(`^.*({domain_pattern})$`, input.car.destination)')

        # Sensitivity checks
        if pattern.get("has_sudo"):
            conditions.append('    input.car.has_sudo == true')

        if pattern.get("contains_financial_ref"):
            conditions.append('    input.car.sensitivity.contains_financial_ref == true')

        if pattern.get("contains_pii"):
            conditions.append('    input.car.sensitivity.contains_pii == true')

        # Money amount checks
        if "money_amount" in pattern:
            money = pattern["money_amount"]
            if isinstance(money, dict):
                if "gt" in money:
                    conditions.append(f'    input.car.sensitivity.money_amount > {money["gt"]}')
                if "lt" in money:
                    conditions.append(f'    input.car.sensitivity.money_amount < {money["lt"]}')
            else:
                conditions.append(f'    input.car.sensitivity.money_amount == {money}')

        # Args contains patterns
        if "args_contains" in pattern:
            for arg_pattern in pattern["args_contains"]:
                conditions.append(f'    contains(input.car.args_string, "{arg_pattern}")')

        # Environment check
        if "environment" in pattern:
            conditions.append(f'    input.car.context.environment == "{pattern["environment"]}"')

        # Risk level checks
        if "risk" in pattern:
            # Add as metadata, not condition
            pass

        # Build the rule
        if not conditions:
            conditions.append("    true  # Always matches")

        rule_comment = f'# {pattern.get("reason", "No reason specified")}'
        rule = f"{rule_comment}\n{rule_type} if {{\n" + "\n".join(conditions) + "\n}"

        return rule


class OPAEngine:
    """
    OPA Policy Engine wrapper.

    Uses OPA (Open Policy Agent) for formal policy evaluation.
    Supports both embedded evaluation and external OPA server.
    """

    def __init__(self, policy_dir: Optional[Path] = None):
        self.policy_dir = policy_dir or Path.home() / ".faramesh-guard" / "policies"
        self.policy_dir.mkdir(parents=True, exist_ok=True)

        self.compiler = RegoCompiler()
        self.active_bundle: Optional[PolicyBundle] = None
        self._opa_available = self._check_opa_available()

        # Initialize with default policies
        self._ensure_default_policies()

    def _check_opa_available(self) -> bool:
        """Check if OPA binary is available."""
        try:
            result = subprocess.run(
                ["opa", "version"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"OPA available: {result.stdout.decode().strip()}")
                return True
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        logger.warning("OPA binary not found, using built-in evaluation")
        return False

    def _ensure_default_policies(self):
        """Create default policy files if they don't exist."""
        modes_dir = self.policy_dir / "modes"
        modes_dir.mkdir(exist_ok=True)

        # Default mode policies
        default_policies = {
            "relaxed.rego": self._generate_relaxed_policy(),
            "safe.rego": self._generate_safe_policy(),
            "strict.rego": self._generate_strict_policy(),
            "locked.rego": self._generate_locked_policy(),
        }

        for filename, content in default_policies.items():
            policy_file = modes_dir / filename
            if not policy_file.exists():
                policy_file.write_text(content)
                logger.info(f"Created default policy: {filename}")

    def _generate_relaxed_policy(self) -> str:
        """Generate relaxed mode policy (most permissive)."""
        return '''package faramesh.guard.relaxed

import future.keywords.in
import future.keywords.if

# Relaxed mode: Allow most actions, only block critical threats

default allow := true
default deny := false
default needs_approval := false

# Only deny truly critical actions
deny if {
    input.car.technical_risk == "critical"
    input.car.tool == "exec"
    contains(input.car.args_string, "rm -rf /")
}

deny if {
    input.car.sensitivity.contains_secrets == true
    input.car.destination_external == true
}

# Minimal approval requirements
needs_approval if {
    input.car.economic_risk == "critical"
    input.car.sensitivity.money_amount > 10000
}

decision := "DENY" if deny
decision := "NEEDS_APPROVAL" if { not deny; needs_approval }
decision := "ALLOW" if { not deny; not needs_approval; allow }
'''

    def _generate_safe_policy(self) -> str:
        """Generate safe mode policy (balanced)."""
        return '''package faramesh.guard.safe

import future.keywords.in
import future.keywords.if

# Safe mode: Balanced protection (default)

default allow := false
default deny := false
default needs_approval := false

# Allow safe operations
allow if {
    input.car.technical_risk == "low"
    input.car.economic_risk == "low"
    input.car.extraction_confidence > 0.8
}

allow if {
    input.car.tool == "exec"
    input.car.operation == "read"
}

allow if {
    input.car.tool == "fs"
    input.car.operation == "read"
}

# Deny critical threats
deny if {
    input.car.technical_risk == "critical"
}

deny if {
    input.car.sensitivity.contains_secrets == true
    input.car.destination_external == true
}

deny if {
    input.car.tool == "exec"
    contains(input.car.args_string, "rm -rf")
}

deny if {
    input.car.tool == "exec"
    contains(input.car.args_string, "sudo")
}

# Require approval for risky operations
needs_approval if {
    not deny
    input.car.destination_external == true
    input.car.sensitivity.contains_financial_ref == true
}

needs_approval if {
    not deny
    input.car.target_kind == "person"
    input.car.destination_external == true
}

needs_approval if {
    not deny
    input.car.technical_risk == "high"
}

needs_approval if {
    not deny
    input.car.economic_risk == "high"
}

needs_approval if {
    not deny
    input.car.extraction_confidence < 0.7
}

decision := "DENY" if deny
decision := "NEEDS_APPROVAL" if { not deny; needs_approval }
decision := "ALLOW" if { not deny; not needs_approval; allow }
decision := "NEEDS_APPROVAL" if { not deny; not needs_approval; not allow }
'''

    def _generate_strict_policy(self) -> str:
        """Generate strict mode policy (very restrictive)."""
        return '''package faramesh.guard.strict

import future.keywords.in
import future.keywords.if

# Strict mode: Maximum protection, most approvals required

default allow := false
default deny := false
default needs_approval := true  # Default to requiring approval

# Only allow trivial read operations
allow if {
    input.car.tool in ["fs", "exec"]
    input.car.operation == "read"
    input.car.technical_risk == "low"
    input.car.economic_risk == "low"
    input.car.extraction_confidence > 0.9
}

# Deny all critical and high-risk
deny if {
    input.car.technical_risk == "critical"
}

deny if {
    input.car.economic_risk == "critical"
}

deny if {
    input.car.sensitivity.contains_secrets == true
}

deny if {
    input.car.tool == "exec"
    input.car.operation in ["execute", "write", "delete"]
}

# Everything else needs approval
needs_approval if {
    not deny
    not allow
}

decision := "DENY" if deny
decision := "NEEDS_APPROVAL" if { not deny; needs_approval }
decision := "ALLOW" if { not deny; not needs_approval; allow }
'''

    def _generate_locked_policy(self) -> str:
        """Generate locked mode policy (read-only, blocks all writes)."""
        return '''package faramesh.guard.locked

import future.keywords.in
import future.keywords.if

# Locked mode: Read-only, agent cannot modify anything

default allow := false
default deny := true  # Default deny
default needs_approval := false

# Only allow pure read operations
allow if {
    input.car.operation == "read"
    input.car.technical_risk == "low"
}

# Deny all write/execute/send operations
deny if {
    input.car.operation in ["write", "execute", "send", "delete", "modify", "create"]
}

deny if {
    input.car.tool == "exec"
}

deny if {
    input.car.destination_external == true
}

deny if {
    input.car.target_kind in ["financial", "person"]
}

decision := "DENY" if deny
decision := "ALLOW" if { not deny; allow }
decision := "DENY" if { not deny; not allow }
'''

    def load_policy_bundle(self, mode: str = "safe") -> PolicyBundle:
        """Load a policy bundle for a given mode."""
        mode_file = self.policy_dir / "modes" / f"{mode}.rego"

        if not mode_file.exists():
            logger.warning(f"Mode file not found: {mode_file}, using safe mode")
            mode = "safe"
            mode_file = self.policy_dir / "modes" / "safe.rego"

        rego_content = mode_file.read_text()

        # Also load any user overrides
        overrides_file = self.policy_dir / "user_overrides.rego"
        if overrides_file.exists():
            rego_content += "\n\n# User Overrides\n" + overrides_file.read_text()

        # Load learned patterns
        learned_file = self.policy_dir / "learned_patterns.rego"
        if learned_file.exists():
            rego_content += "\n\n# Learned Patterns\n" + learned_file.read_text()

        bundle = PolicyBundle(
            name=f"guard-{mode}",
            mode=mode,
            rego_modules={f"{mode}.rego": rego_content},
        )
        bundle.compute_hash()

        self.active_bundle = bundle
        logger.info(f"Loaded policy bundle: {bundle.name} (hash: {bundle.hash})")

        return bundle

    def load_yaml_policy(self, yaml_path: Path) -> PolicyBundle:
        """Load and compile a YAML policy pack."""
        with open(yaml_path) as f:
            yaml_content = yaml.safe_load(f)

        rego_content = self.compiler.compile_yaml_to_rego(yaml_content)

        bundle = PolicyBundle(
            name=yaml_content.get("name", yaml_path.stem),
            mode=yaml_content.get("mode", "safe"),
            rego_modules={f"{yaml_path.stem}.rego": rego_content},
        )
        bundle.compute_hash()

        return bundle

    def evaluate(self, car: Dict[str, Any], mode: str = "safe") -> PolicyEvaluationResult:
        """
        Evaluate a CAR against the active policy bundle.

        Args:
            car: Canonical Action Request
            mode: Policy mode (relaxed/safe/strict/locked)

        Returns:
            PolicyEvaluationResult with decision and matched rules
        """
        # Ensure bundle is loaded
        if not self.active_bundle or self.active_bundle.mode != mode:
            self.load_policy_bundle(mode)

        # Prepare input for OPA
        opa_input = {
            "car": self._normalize_car_for_opa(car)
        }

        if self._opa_available:
            return self._evaluate_with_opa(opa_input)
        else:
            return self._evaluate_builtin(opa_input, mode)

    def _normalize_car_for_opa(self, car: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize CAR fields for OPA evaluation."""
        normalized = dict(car)

        # Ensure required fields exist with defaults
        normalized.setdefault("technical_risk", "medium")
        normalized.setdefault("economic_risk", "low")
        normalized.setdefault("extraction_confidence", 0.8)
        normalized.setdefault("destination_external", False)
        normalized.setdefault("operation", "execute")
        normalized.setdefault("target_kind", "process")

        # Create args_string for pattern matching
        args = car.get("args", {})
        if isinstance(args, dict):
            args_string = " ".join(str(v) for v in args.values())
        else:
            args_string = str(args)
        normalized["args_string"] = args_string

        # Ensure sensitivity object exists
        normalized.setdefault("sensitivity", {
            "contains_pii": False,
            "contains_secrets": False,
            "contains_financial_ref": False,
            "money_amount": 0,
            "confidence": 0.8
        })

        # Ensure context exists
        normalized.setdefault("context", {})

        return normalized

    def _evaluate_with_opa(self, opa_input: Dict[str, Any]) -> PolicyEvaluationResult:
        """Evaluate using external OPA binary."""
        try:
            # Write input to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(opa_input, f)
                input_file = f.name

            # Write policy to temp file
            policy_content = list(self.active_bundle.rego_modules.values())[0]
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rego', delete=False) as f:
                f.write(policy_content)
                policy_file = f.name

            # Run OPA eval
            result = subprocess.run(
                [
                    "opa", "eval",
                    "--data", policy_file,
                    "--input", input_file,
                    "--format", "json",
                    "data.faramesh.guard.decision"
                ],
                capture_output=True,
                timeout=10
            )

            # Parse result
            if result.returncode == 0:
                output = json.loads(result.stdout)
                if output.get("result") and len(output["result"]) > 0:
                    decision_str = output["result"][0].get("expressions", [{}])[0].get("value", "ABSTAIN")
                    decision = PolicyDecision[decision_str]
                else:
                    decision = PolicyDecision.ABSTAIN
            else:
                logger.error(f"OPA evaluation failed: {result.stderr.decode()}")
                decision = PolicyDecision.NEEDS_APPROVAL  # Fail safe

        except Exception as e:
            logger.error(f"OPA evaluation error: {e}")
            decision = PolicyDecision.NEEDS_APPROVAL  # Fail safe
        finally:
            # Cleanup temp files
            try:
                os.unlink(input_file)
                os.unlink(policy_file)
            except:
                pass

        return PolicyEvaluationResult(
            decision=decision,
            matched_rules=["opa_evaluation"],
            reason=f"OPA policy evaluation: {decision.value}",
            policy_version=self.active_bundle.version
        )

    def _evaluate_builtin(self, opa_input: Dict[str, Any], mode: str) -> PolicyEvaluationResult:
        """
        Built-in policy evaluation (fallback when OPA not available).
        Implements core policy logic in Python.
        """
        car = opa_input["car"]
        matched_rules = []

        # Check deny conditions
        deny = False
        deny_reason = ""

        # Critical technical risk
        if car.get("technical_risk") == "critical":
            deny = True
            deny_reason = "Critical technical risk"
            matched_rules.append("deny_critical_technical_risk")

        # Secrets to external
        if car.get("sensitivity", {}).get("contains_secrets") and car.get("destination_external"):
            deny = True
            deny_reason = "Secrets to external destination"
            matched_rules.append("deny_secrets_external")

        # Destructive commands
        args_string = car.get("args_string", "")
        if "rm -rf" in args_string or "rm -r /" in args_string:
            deny = True
            deny_reason = "Destructive command blocked"
            matched_rules.append("deny_destructive_rm")

        # Sudo in strict/locked modes
        if mode in ["strict", "locked"] and "sudo" in args_string:
            deny = True
            deny_reason = "Sudo blocked in strict/locked mode"
            matched_rules.append("deny_sudo_strict")

        if deny:
            return PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                matched_rules=matched_rules,
                reason=deny_reason,
                policy_version="builtin-1.0"
            )

        # Locked mode: only allow reads
        if mode == "locked":
            if car.get("operation") == "read" and car.get("technical_risk") == "low":
                return PolicyEvaluationResult(
                    decision=PolicyDecision.ALLOW,
                    matched_rules=["locked_allow_read"],
                    reason="Read operation allowed in locked mode",
                    policy_version="builtin-1.0"
                )
            else:
                return PolicyEvaluationResult(
                    decision=PolicyDecision.DENY,
                    matched_rules=["locked_deny_nonread"],
                    reason="Only read operations allowed in locked mode",
                    policy_version="builtin-1.0"
                )

        # Check needs_approval conditions
        needs_approval = False
        approval_reason = ""

        # External financial
        if car.get("destination_external") and car.get("sensitivity", {}).get("contains_financial_ref"):
            needs_approval = True
            approval_reason = "External financial communication"
            matched_rules.append("approval_external_financial")

        # External person
        if car.get("target_kind") == "person" and car.get("destination_external"):
            needs_approval = True
            approval_reason = "External person communication"
            matched_rules.append("approval_external_person")

        # High risk
        if car.get("technical_risk") == "high" or car.get("economic_risk") == "high":
            needs_approval = True
            approval_reason = "High risk action"
            matched_rules.append("approval_high_risk")

        # Low extraction confidence
        if car.get("extraction_confidence", 1.0) < 0.7:
            needs_approval = True
            approval_reason = "Low extraction confidence"
            matched_rules.append("approval_low_confidence")

        # Strict mode: more approvals
        if mode == "strict" and car.get("operation") in ["write", "execute", "send", "delete"]:
            needs_approval = True
            approval_reason = "Write/execute requires approval in strict mode"
            matched_rules.append("approval_strict_mode")

        if needs_approval:
            return PolicyEvaluationResult(
                decision=PolicyDecision.NEEDS_APPROVAL,
                matched_rules=matched_rules,
                reason=approval_reason,
                policy_version="builtin-1.0"
            )

        # Check allow conditions
        allow = False
        allow_reason = ""

        # Low risk operations
        if car.get("technical_risk") == "low" and car.get("economic_risk") == "low":
            if car.get("extraction_confidence", 1.0) > 0.8:
                allow = True
                allow_reason = "Low risk operation with high confidence"
                matched_rules.append("allow_low_risk")

        # Safe readonly
        if car.get("operation") == "read":
            allow = True
            allow_reason = "Read operation"
            matched_rules.append("allow_read")

        # Relaxed mode: allow most
        if mode == "relaxed" and not needs_approval:
            allow = True
            allow_reason = "Relaxed mode default allow"
            matched_rules.append("allow_relaxed_default")

        if allow:
            return PolicyEvaluationResult(
                decision=PolicyDecision.ALLOW,
                matched_rules=matched_rules,
                reason=allow_reason,
                policy_version="builtin-1.0"
            )

        # Default: needs approval in safe/strict, allow in relaxed
        if mode == "relaxed":
            return PolicyEvaluationResult(
                decision=PolicyDecision.ALLOW,
                matched_rules=["relaxed_default"],
                reason="Relaxed mode default",
                policy_version="builtin-1.0"
            )
        else:
            return PolicyEvaluationResult(
                decision=PolicyDecision.NEEDS_APPROVAL,
                matched_rules=["safe_default"],
                reason="Requires approval by default",
                policy_version="builtin-1.0"
            )

    def add_user_override(self, rule_type: str, pattern: Dict[str, Any]) -> None:
        """Add a user override rule."""
        overrides_file = self.policy_dir / "user_overrides.rego"

        # Read existing overrides
        if overrides_file.exists():
            existing = overrides_file.read_text()
        else:
            existing = "package faramesh.guard.overrides\n\n"

        # Compile new rule
        rule = self.compiler._compile_pattern_to_rule(rule_type, f"user_{len(existing.split('if'))}", pattern)

        # Append rule
        overrides_file.write_text(existing + "\n" + rule + "\n")

        # Reload bundle
        if self.active_bundle:
            self.load_policy_bundle(self.active_bundle.mode)

        logger.info(f"Added user override: {rule_type} for {pattern}")

    def get_policy_hash(self) -> str:
        """Get hash of current active policy for integrity verification."""
        if self.active_bundle:
            return self.active_bundle.hash
        return ""


# Singleton instance
_opa_engine: Optional[OPAEngine] = None

def get_opa_engine() -> OPAEngine:
    """Get singleton OPA engine instance."""
    global _opa_engine
    if _opa_engine is None:
        _opa_engine = OPAEngine()
    return _opa_engine
