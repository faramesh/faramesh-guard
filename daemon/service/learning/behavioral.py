"""
Behavioral Learning - Learn from User Approvals

Implements behavioral learning to reduce approval fatigue.
Guard learns patterns from user approvals and auto-generates policy rules.

Features:
- Pattern extraction from approved actions
- Confidence scoring based on approval history
- Auto-generated Rego rules
- User review and deletion of learned patterns
- Decay for unused patterns

Reference: guard-plan-v1.md Behavioral Learning section
"""

import json
import hashlib
import sqlite3
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import logging
import threading
import re

logger = logging.getLogger("guard.learning.behavioral")


class PatternType(Enum):
    """Types of learned patterns."""
    TOOL_ALLOW = "tool_allow"  # Allow specific tool
    DESTINATION_ALLOW = "destination_allow"  # Allow specific destination
    DOMAIN_ALLOW = "domain_allow"  # Allow domain
    PATH_ALLOW = "path_allow"  # Allow path prefix
    COMMAND_ALLOW = "command_allow"  # Allow command pattern
    CONTEXT_ALLOW = "context_allow"  # Allow in specific context
    COMBINED = "combined"  # Multiple conditions


@dataclass
class LearnedPattern:
    """A pattern learned from user approvals."""
    pattern_id: str
    pattern_type: PatternType

    # Pattern conditions
    tool: Optional[str] = None
    operation: Optional[str] = None
    destination: Optional[str] = None
    destination_domain: Optional[str] = None
    path_prefix: Optional[str] = None
    command_pattern: Optional[str] = None
    context_key: Optional[str] = None
    context_value: Optional[str] = None

    # Learning metadata
    approval_count: int = 0
    first_approved: str = ""
    last_approved: str = ""

    # Confidence
    confidence: float = 0.0

    # Status
    auto_apply: bool = False  # Auto-allow without approval
    user_reviewed: bool = False  # User has reviewed this pattern
    deleted: bool = False

    # Compiled rule
    rego_rule: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type.value,
            "tool": self.tool,
            "operation": self.operation,
            "destination": self.destination,
            "destination_domain": self.destination_domain,
            "path_prefix": self.path_prefix,
            "command_pattern": self.command_pattern,
            "context_key": self.context_key,
            "context_value": self.context_value,
            "approval_count": self.approval_count,
            "first_approved": self.first_approved,
            "last_approved": self.last_approved,
            "confidence": self.confidence,
            "auto_apply": self.auto_apply,
            "user_reviewed": self.user_reviewed,
            "deleted": self.deleted,
            "rego_rule": self.rego_rule
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LearnedPattern":
        return cls(
            pattern_id=data["pattern_id"],
            pattern_type=PatternType(data["pattern_type"]),
            tool=data.get("tool"),
            operation=data.get("operation"),
            destination=data.get("destination"),
            destination_domain=data.get("destination_domain"),
            path_prefix=data.get("path_prefix"),
            command_pattern=data.get("command_pattern"),
            context_key=data.get("context_key"),
            context_value=data.get("context_value"),
            approval_count=data.get("approval_count", 0),
            first_approved=data.get("first_approved", ""),
            last_approved=data.get("last_approved", ""),
            confidence=data.get("confidence", 0.0),
            auto_apply=data.get("auto_apply", False),
            user_reviewed=data.get("user_reviewed", False),
            deleted=data.get("deleted", False),
            rego_rule=data.get("rego_rule")
        )

    def matches(self, car: Dict[str, Any]) -> bool:
        """Check if CAR matches this pattern."""
        if self.deleted:
            return False

        # Tool match
        if self.tool and car.get("tool") != self.tool:
            return False

        # Operation match
        if self.operation and car.get("operation") != self.operation:
            return False

        # Destination match
        if self.destination:
            car_dest = car.get("destination", "")
            if self.destination != car_dest:
                return False

        # Domain match
        if self.destination_domain:
            car_dest = car.get("destination", "")
            car_domain = self._extract_domain(car_dest)
            if not self._domain_matches(car_domain, self.destination_domain):
                return False

        # Path prefix match
        if self.path_prefix:
            car_target = car.get("target", "")
            if not car_target.startswith(self.path_prefix):
                return False

        # Command pattern match
        if self.command_pattern:
            args = car.get("args", {})
            cmd = args.get("command", args.get("cmd", ""))
            if not re.match(self.command_pattern, cmd):
                return False

        # Context match
        if self.context_key and self.context_value:
            context = car.get("context", {})
            if context.get(self.context_key) != self.context_value:
                return False

        return True

    def _extract_domain(self, address: str) -> str:
        """Extract domain from email or URL."""
        if "@" in address:
            return address.split("@")[-1].lower()
        # URL - extract domain
        if "://" in address:
            address = address.split("://")[1]
        return address.split("/")[0].lower()

    def _domain_matches(self, actual: str, pattern: str) -> bool:
        """Check if domain matches pattern (supports wildcards)."""
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return actual.endswith(suffix) or actual == suffix[1:] if suffix.startswith(".") else actual == suffix
        return actual == pattern


class PatternStore:
    """
    Persistent storage for learned patterns.
    Uses SQLite for durability.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path.home() / ".faramesh-guard" / "learned_patterns.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self.db_path))
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        """Initialize database schema."""
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS learned_patterns (
                pattern_id TEXT PRIMARY KEY,
                pattern_type TEXT NOT NULL,
                tool TEXT,
                operation TEXT,
                destination TEXT,
                destination_domain TEXT,
                path_prefix TEXT,
                command_pattern TEXT,
                context_key TEXT,
                context_value TEXT,
                approval_count INTEGER DEFAULT 0,
                first_approved TEXT,
                last_approved TEXT,
                confidence REAL DEFAULT 0.0,
                auto_apply INTEGER DEFAULT 0,
                user_reviewed INTEGER DEFAULT 0,
                deleted INTEGER DEFAULT 0,
                rego_rule TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_tool ON learned_patterns(tool);
            CREATE INDEX IF NOT EXISTS idx_domain ON learned_patterns(destination_domain);
            CREATE INDEX IF NOT EXISTS idx_auto_apply ON learned_patterns(auto_apply);

            -- Approval history for learning
            CREATE TABLE IF NOT EXISTS approval_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                car_hash TEXT NOT NULL,
                car_json TEXT NOT NULL,
                decision TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                pattern_id TEXT,
                FOREIGN KEY (pattern_id) REFERENCES learned_patterns(pattern_id)
            );

            CREATE INDEX IF NOT EXISTS idx_car_hash ON approval_history(car_hash);
        """)
        conn.commit()

    def save(self, pattern: LearnedPattern) -> None:
        """Save or update a pattern."""
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO learned_patterns (
                pattern_id, pattern_type, tool, operation, destination,
                destination_domain, path_prefix, command_pattern,
                context_key, context_value, approval_count, first_approved,
                last_approved, confidence, auto_apply, user_reviewed, deleted, rego_rule
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pattern.pattern_id, pattern.pattern_type.value, pattern.tool,
            pattern.operation, pattern.destination, pattern.destination_domain,
            pattern.path_prefix, pattern.command_pattern, pattern.context_key,
            pattern.context_value, pattern.approval_count, pattern.first_approved,
            pattern.last_approved, pattern.confidence, 1 if pattern.auto_apply else 0,
            1 if pattern.user_reviewed else 0, 1 if pattern.deleted else 0,
            pattern.rego_rule
        ))
        conn.commit()

    def get(self, pattern_id: str) -> Optional[LearnedPattern]:
        """Get a pattern by ID."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM learned_patterns WHERE pattern_id = ?",
            (pattern_id,)
        )
        row = cursor.fetchone()
        if row:
            return self._row_to_pattern(row)
        return None

    def get_active(self) -> List[LearnedPattern]:
        """Get all active (non-deleted) patterns."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM learned_patterns WHERE deleted = 0 ORDER BY confidence DESC"
        )
        return [self._row_to_pattern(row) for row in cursor.fetchall()]

    def get_auto_apply(self) -> List[LearnedPattern]:
        """Get patterns that should auto-apply."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM learned_patterns WHERE deleted = 0 AND auto_apply = 1"
        )
        return [self._row_to_pattern(row) for row in cursor.fetchall()]

    def find_matching(self, car: Dict[str, Any]) -> List[LearnedPattern]:
        """Find patterns that match a CAR."""
        patterns = self.get_auto_apply()
        return [p for p in patterns if p.matches(car)]

    def record_approval(self, car: Dict[str, Any], decision: str, pattern_id: Optional[str] = None) -> None:
        """Record an approval in history."""
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO approval_history (car_hash, car_json, decision, approved_at, pattern_id)
            VALUES (?, ?, ?, ?, ?)
        """, (
            car.get("car_hash", ""),
            json.dumps(car),
            decision,
            datetime.utcnow().isoformat() + "Z",
            pattern_id
        ))
        conn.commit()

    def get_approval_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent approval history."""
        conn = self._get_conn()
        cursor = conn.execute("""
            SELECT * FROM approval_history ORDER BY approved_at DESC LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def _row_to_pattern(self, row: sqlite3.Row) -> LearnedPattern:
        """Convert database row to LearnedPattern."""
        return LearnedPattern(
            pattern_id=row["pattern_id"],
            pattern_type=PatternType(row["pattern_type"]),
            tool=row["tool"],
            operation=row["operation"],
            destination=row["destination"],
            destination_domain=row["destination_domain"],
            path_prefix=row["path_prefix"],
            command_pattern=row["command_pattern"],
            context_key=row["context_key"],
            context_value=row["context_value"],
            approval_count=row["approval_count"],
            first_approved=row["first_approved"],
            last_approved=row["last_approved"],
            confidence=row["confidence"],
            auto_apply=bool(row["auto_apply"]),
            user_reviewed=bool(row["user_reviewed"]),
            deleted=bool(row["deleted"]),
            rego_rule=row["rego_rule"]
        )


class PatternExtractor:
    """
    Extract patterns from approved CARs.
    Identifies what made the user approve the action.
    """

    def extract(self, car: Dict[str, Any]) -> List[LearnedPattern]:
        """
        Extract potential patterns from an approved CAR.
        Returns multiple patterns for user to choose from.
        """
        patterns = []
        now = datetime.utcnow().isoformat() + "Z"

        # Tool-based pattern
        if car.get("tool"):
            patterns.append(LearnedPattern(
                pattern_id=self._generate_id("tool", car),
                pattern_type=PatternType.TOOL_ALLOW,
                tool=car["tool"],
                operation=car.get("operation"),
                first_approved=now,
                last_approved=now,
                approval_count=1
            ))

        # Destination-based pattern
        destination = car.get("destination", "")
        if destination:
            # Exact destination
            patterns.append(LearnedPattern(
                pattern_id=self._generate_id("dest", car),
                pattern_type=PatternType.DESTINATION_ALLOW,
                tool=car.get("tool"),
                destination=destination,
                first_approved=now,
                last_approved=now,
                approval_count=1
            ))

            # Domain pattern
            domain = self._extract_domain(destination)
            if domain:
                patterns.append(LearnedPattern(
                    pattern_id=self._generate_id("domain", car),
                    pattern_type=PatternType.DOMAIN_ALLOW,
                    tool=car.get("tool"),
                    destination_domain=domain,
                    first_approved=now,
                    last_approved=now,
                    approval_count=1
                ))

        # Path-based pattern
        target = car.get("target", "")
        if target and "/" in target:
            # Extract meaningful prefix
            prefix = self._extract_path_prefix(target)
            if prefix:
                patterns.append(LearnedPattern(
                    pattern_id=self._generate_id("path", car),
                    pattern_type=PatternType.PATH_ALLOW,
                    tool=car.get("tool"),
                    operation=car.get("operation"),
                    path_prefix=prefix,
                    first_approved=now,
                    last_approved=now,
                    approval_count=1
                ))

        # Command pattern (for exec)
        if car.get("tool") == "exec":
            args = car.get("args", {})
            cmd = args.get("command", args.get("cmd", ""))
            if cmd:
                pattern = self._extract_command_pattern(cmd)
                if pattern:
                    patterns.append(LearnedPattern(
                        pattern_id=self._generate_id("cmd", car),
                        pattern_type=PatternType.COMMAND_ALLOW,
                        tool="exec",
                        command_pattern=pattern,
                        first_approved=now,
                        last_approved=now,
                        approval_count=1
                    ))

        # Context-based pattern
        context = car.get("context", {})
        if context.get("intent_detected"):
            patterns.append(LearnedPattern(
                pattern_id=self._generate_id("ctx", car),
                pattern_type=PatternType.CONTEXT_ALLOW,
                tool=car.get("tool"),
                context_key="intent_detected",
                context_value=context["intent_detected"],
                first_approved=now,
                last_approved=now,
                approval_count=1
            ))

        return patterns

    def _generate_id(self, prefix: str, car: Dict[str, Any]) -> str:
        """Generate unique pattern ID."""
        content = f"{prefix}:{car.get('tool')}:{car.get('destination')}:{car.get('target')}"
        return f"pattern_{hashlib.sha256(content.encode()).hexdigest()[:16]}"

    def _extract_domain(self, address: str) -> Optional[str]:
        """Extract domain from email or URL."""
        if "@" in address:
            return address.split("@")[-1].lower()
        if "://" in address:
            address = address.split("://")[1]
        domain = address.split("/")[0].lower()
        return domain if domain else None

    def _extract_path_prefix(self, path: str) -> Optional[str]:
        """Extract meaningful path prefix."""
        parts = path.split("/")

        # Find a good stopping point (not too specific)
        # Stop at project/repo root or ~3 levels deep
        if len(parts) <= 3:
            return "/".join(parts[:-1]) + "/" if len(parts) > 1 else None

        # Look for common project markers
        project_markers = [".git", "package.json", "Cargo.toml", "pyproject.toml"]
        for i, part in enumerate(parts):
            if part in project_markers or i >= 4:
                return "/".join(parts[:i]) + "/"

        return "/".join(parts[:4]) + "/"

    def _extract_command_pattern(self, cmd: str) -> Optional[str]:
        """Extract command pattern (binary + safe prefix)."""
        parts = cmd.strip().split()
        if not parts:
            return None

        binary = parts[0]

        # For safe commands, allow the binary
        safe_binaries = ["git", "ls", "cat", "head", "tail", "grep", "find", "echo"]
        if binary in safe_binaries:
            if len(parts) > 1:
                # Include first subcommand for git
                if binary == "git" and len(parts) > 1:
                    return f"^git\\s+{re.escape(parts[1])}\\b"
            return f"^{re.escape(binary)}\\b"

        return None


class RegoCompiler:
    """
    Compile learned patterns to OPA Rego rules.
    """

    def compile(self, pattern: LearnedPattern) -> str:
        """Compile a pattern to a Rego rule."""
        conditions = []

        if pattern.tool:
            conditions.append(f'input.car.tool == "{pattern.tool}"')

        if pattern.operation:
            conditions.append(f'input.car.operation == "{pattern.operation}"')

        if pattern.destination:
            conditions.append(f'input.car.destination == "{pattern.destination}"')

        if pattern.destination_domain:
            domain = pattern.destination_domain.replace(".", r"\\.")
            if pattern.destination_domain.startswith("*."):
                conditions.append(f'regex.match(`.*{domain[2:]}$`, input.car.destination)')
            else:
                conditions.append(f'regex.match(`.*@?{domain}$`, input.car.destination)')

        if pattern.path_prefix:
            prefix = pattern.path_prefix.replace("\\", "\\\\")
            conditions.append(f'startswith(input.car.target, "{prefix}")')

        if pattern.command_pattern:
            conditions.append(f'regex.match(`{pattern.command_pattern}`, input.car.args_string)')

        if pattern.context_key and pattern.context_value:
            conditions.append(f'input.car.context.{pattern.context_key} == "{pattern.context_value}"')

        if not conditions:
            return ""

        rule = f"""# Learned pattern: {pattern.pattern_id}
# Approved {pattern.approval_count} times, confidence: {pattern.confidence:.2f}
allow if {{
    {chr(10).join('    ' + c for c in conditions)}
}}"""

        return rule

    def compile_all(self, patterns: List[LearnedPattern]) -> str:
        """Compile all patterns to a Rego module."""
        rules = []

        for pattern in patterns:
            if pattern.auto_apply and not pattern.deleted:
                rule = self.compile(pattern)
                if rule:
                    rules.append(rule)

        if not rules:
            return "# No learned patterns\n"

        module = """package faramesh.guard.learned

import future.keywords.if

# Auto-generated from learned patterns
# DO NOT EDIT - managed by Guard behavioral learning

"""
        module += "\n\n".join(rules)

        return module


class BehavioralLearner:
    """
    Main behavioral learning interface.
    Learns from approvals and generates policy rules.
    """

    # Thresholds for auto-apply
    MIN_APPROVALS_FOR_AUTO = 3
    MIN_CONFIDENCE_FOR_AUTO = 0.8
    CONFIDENCE_DECAY_DAYS = 30

    def __init__(
        self,
        store: Optional[PatternStore] = None,
        policy_dir: Optional[Path] = None
    ):
        self.store = store or PatternStore()
        self.extractor = PatternExtractor()
        self.compiler = RegoCompiler()

        self.policy_dir = policy_dir or Path.home() / ".faramesh-guard" / "policies"
        self.policy_dir.mkdir(parents=True, exist_ok=True)

        self.learned_policy_file = self.policy_dir / "learned_patterns.rego"

    def on_approval(self, car: Dict[str, Any], decision: str) -> List[LearnedPattern]:
        """
        Process an approval and learn from it.

        Args:
            car: The approved CAR
            decision: "APPROVE" or "DENY"

        Returns:
            List of extracted/updated patterns
        """
        if decision != "APPROVE":
            # TODO: Learn from denials too (negative patterns)
            self.store.record_approval(car, decision)
            return []

        # Extract potential patterns
        extracted = self.extractor.extract(car)

        updated_patterns = []
        for pattern in extracted:
            # Check if pattern already exists
            existing = self.store.get(pattern.pattern_id)

            if existing:
                # Update existing pattern
                existing.approval_count += 1
                existing.last_approved = datetime.utcnow().isoformat() + "Z"
                existing.confidence = self._calculate_confidence(existing)

                # Check if should auto-apply now
                if not existing.auto_apply and self._should_auto_apply(existing):
                    existing.auto_apply = True
                    existing.rego_rule = self.compiler.compile(existing)
                    logger.info(f"Pattern {existing.pattern_id} now auto-applies")

                self.store.save(existing)
                updated_patterns.append(existing)
            else:
                # New pattern
                pattern.confidence = self._calculate_confidence(pattern)
                self.store.save(pattern)
                updated_patterns.append(pattern)

        # Record in history
        self.store.record_approval(car, decision)

        # Regenerate policy file
        self._regenerate_policy()

        return updated_patterns

    def check_learned_patterns(self, car: Dict[str, Any]) -> Optional[LearnedPattern]:
        """
        Check if any learned pattern matches the CAR.

        Returns:
            Matching pattern if found, None otherwise
        """
        matching = self.store.find_matching(car)

        if matching:
            # Return highest confidence match
            return max(matching, key=lambda p: p.confidence)

        return None

    def get_patterns(self, include_deleted: bool = False) -> List[LearnedPattern]:
        """Get all patterns for UI display."""
        if include_deleted:
            # Would need separate query
            pass
        return self.store.get_active()

    def delete_pattern(self, pattern_id: str) -> bool:
        """Soft-delete a pattern."""
        pattern = self.store.get(pattern_id)
        if pattern:
            pattern.deleted = True
            pattern.auto_apply = False
            self.store.save(pattern)
            self._regenerate_policy()
            return True
        return False

    def review_pattern(self, pattern_id: str, approved: bool) -> bool:
        """Mark a pattern as user-reviewed."""
        pattern = self.store.get(pattern_id)
        if pattern:
            pattern.user_reviewed = True
            if not approved:
                pattern.auto_apply = False
            self.store.save(pattern)
            self._regenerate_policy()
            return True
        return False

    def set_auto_apply(self, pattern_id: str, auto_apply: bool) -> bool:
        """Manually set auto-apply status."""
        pattern = self.store.get(pattern_id)
        if pattern:
            pattern.auto_apply = auto_apply
            if auto_apply:
                pattern.rego_rule = self.compiler.compile(pattern)
            self.store.save(pattern)
            self._regenerate_policy()
            return True
        return False

    def _calculate_confidence(self, pattern: LearnedPattern) -> float:
        """Calculate confidence score for a pattern."""
        # Base confidence from approval count
        if pattern.approval_count >= 10:
            base = 0.95
        elif pattern.approval_count >= 5:
            base = 0.85
        elif pattern.approval_count >= 3:
            base = 0.75
        elif pattern.approval_count >= 2:
            base = 0.6
        else:
            base = 0.4

        # Decay based on last approval
        if pattern.last_approved:
            try:
                last = datetime.fromisoformat(pattern.last_approved.replace("Z", "+00:00"))
                days_ago = (datetime.now(last.tzinfo) - last).days
                decay = max(0, 1 - (days_ago / self.CONFIDENCE_DECAY_DAYS))
                base *= (0.5 + 0.5 * decay)  # Max 50% decay
            except:
                pass

        return min(0.99, base)

    def _should_auto_apply(self, pattern: LearnedPattern) -> bool:
        """Check if pattern should auto-apply."""
        return (
            pattern.approval_count >= self.MIN_APPROVALS_FOR_AUTO and
            pattern.confidence >= self.MIN_CONFIDENCE_FOR_AUTO
        )

    def _regenerate_policy(self) -> None:
        """Regenerate the learned patterns Rego file."""
        patterns = self.store.get_auto_apply()

        policy_content = self.compiler.compile_all(patterns)

        self.learned_policy_file.write_text(policy_content)

        logger.debug(f"Regenerated learned policy with {len(patterns)} patterns")

    def get_stats(self) -> Dict[str, Any]:
        """Get learning statistics."""
        patterns = self.store.get_active()
        auto_apply = [p for p in patterns if p.auto_apply]
        history = self.store.get_approval_history(limit=1000)

        return {
            "total_patterns": len(patterns),
            "auto_apply_patterns": len(auto_apply),
            "total_approvals": len(history),
            "approvals_last_24h": len([
                h for h in history
                if (datetime.utcnow() - datetime.fromisoformat(h["approved_at"].replace("Z", ""))).days < 1
            ])
        }


# Singleton instance
_learner: Optional[BehavioralLearner] = None


def get_behavioral_learner() -> BehavioralLearner:
    """Get singleton behavioral learner."""
    global _learner
    if _learner is None:
        _learner = BehavioralLearner()
    return _learner
