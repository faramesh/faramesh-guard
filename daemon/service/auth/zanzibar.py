"""
Zanzibar-Style Authorization Graph

Implements Google Zanzibar-inspired relationship-based access control.
Instead of if-statement spaghetti, authorization becomes data queries.

Core Concepts:
- Tuples: (subject, relation, object) - e.g., (user:alice, owner, workspace:acme)
- Relations: Predefined relationship types (owner, member, viewer, allowed_for, in_crm)
- Queries: has_relation(subject, relation, object) -> bool
- Computed Relations: Relations derived from other relations (inheritance)

Reference: Google Zanzibar - A Globally Distributed Authorization System
"""

import sqlite3
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Set, Tuple as PyTuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import threading

logger = logging.getLogger("guard.auth.zanzibar")


class RelationType(Enum):
    """Standard relationship types."""
    # User/Agent relationships
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    OPERATOR = "operator"
    VIEWER = "viewer"

    # Domain/Destination relationships
    ALLOWED_FOR = "allowed_for"
    BLOCKED_FOR = "blocked_for"

    # Contact/CRM relationships
    IN_CRM = "in_crm"
    KNOWN_CONTACT = "known_contact"
    TRUSTED_SENDER = "trusted_sender"

    # Tool/Resource relationships
    CAN_USE = "can_use"
    RESTRICTED_TO = "restricted_to"

    # Workspace relationships
    BELONGS_TO = "belongs_to"
    MANAGES = "manages"


@dataclass
class RelationTuple:
    """
    A relationship tuple (subject, relation, object).

    Examples:
    - (user:alice, owner, workspace:acme)
    - (agent:bot-1, member, workspace:acme)
    - (domain:github.com, allowed_for, workspace:acme)
    - (contact:john@client.com, in_crm, workspace:acme)
    """
    subject: str  # e.g., "user:alice", "agent:bot-1", "domain:github.com"
    relation: str  # e.g., "owner", "member", "in_crm"
    object: str   # e.g., "workspace:acme", "tool:exec"

    # Metadata
    created_at: str = ""
    created_by: str = ""
    expires_at: Optional[str] = None
    condition: Optional[str] = None  # Optional conditional expression

    def __hash__(self):
        return hash((self.subject, self.relation, self.object))

    def __eq__(self, other):
        if not isinstance(other, RelationTuple):
            return False
        return (self.subject, self.relation, self.object) == (other.subject, other.relation, other.object)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "relation": self.relation,
            "object": self.object,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "expires_at": self.expires_at,
            "condition": self.condition
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RelationTuple":
        return cls(
            subject=data["subject"],
            relation=data["relation"],
            object=data["object"],
            created_at=data.get("created_at", ""),
            created_by=data.get("created_by", ""),
            expires_at=data.get("expires_at"),
            condition=data.get("condition")
        )


@dataclass
class CheckResult:
    """Result of a relationship check."""
    allowed: bool
    reason: str
    matched_tuples: List[RelationTuple] = field(default_factory=list)
    computed_via: Optional[str] = None  # If result came from computed relation
    cache_hit: bool = False


class RelationshipGraph:
    """
    Zanzibar-style relationship graph with efficient queries.

    Supports:
    - Direct relation checks
    - Computed relations (inheritance)
    - Subject sets (groups of subjects)
    - Conditional relations
    """

    # Relation inheritance: if you have higher role, you inherit lower role permissions
    ROLE_HIERARCHY = {
        "owner": ["admin", "member", "operator", "viewer"],
        "admin": ["member", "operator", "viewer"],
        "member": ["operator", "viewer"],
        "operator": ["viewer"],
        "viewer": [],
    }

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path.home() / ".faramesh-guard" / "auth_graph.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._local = threading.local()
        self._init_db()

        # Query cache (LRU-style, cleared periodically)
        self._cache: Dict[str, CheckResult] = {}
        self._cache_ttl_seconds = 60
        self._cache_max_size = 10000

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
            CREATE TABLE IF NOT EXISTS relation_tuples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT NOT NULL,
                relation TEXT NOT NULL,
                object TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT,
                expires_at TEXT,
                condition TEXT,
                UNIQUE(subject, relation, object)
            );

            CREATE INDEX IF NOT EXISTS idx_subject ON relation_tuples(subject);
            CREATE INDEX IF NOT EXISTS idx_object ON relation_tuples(object);
            CREATE INDEX IF NOT EXISTS idx_relation ON relation_tuples(relation);
            CREATE INDEX IF NOT EXISTS idx_subject_relation ON relation_tuples(subject, relation);
            CREATE INDEX IF NOT EXISTS idx_object_relation ON relation_tuples(object, relation);

            -- Subject sets (groups)
            CREATE TABLE IF NOT EXISTS subject_sets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                set_name TEXT NOT NULL,
                member TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(set_name, member)
            );

            CREATE INDEX IF NOT EXISTS idx_set_name ON subject_sets(set_name);
        """)
        conn.commit()

    def write_tuple(
        self,
        subject: str,
        relation: str,
        object: str,
        created_by: str = "system",
        expires_at: Optional[str] = None,
        condition: Optional[str] = None
    ) -> RelationTuple:
        """
        Write a relationship tuple to the graph.

        Args:
            subject: Subject of the relation (e.g., "user:alice")
            relation: Type of relation (e.g., "owner")
            object: Object of the relation (e.g., "workspace:acme")
            created_by: Who created this tuple
            expires_at: Optional expiration timestamp
            condition: Optional conditional expression

        Returns:
            The created RelationTuple
        """
        conn = self._get_conn()
        now = datetime.utcnow().isoformat() + "Z"

        try:
            conn.execute("""
                INSERT OR REPLACE INTO relation_tuples
                (subject, relation, object, created_at, created_by, expires_at, condition)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (subject, relation, object, now, created_by, expires_at, condition))
            conn.commit()

            # Invalidate cache
            self._invalidate_cache(subject, object)

            tuple_obj = RelationTuple(
                subject=subject,
                relation=relation,
                object=object,
                created_at=now,
                created_by=created_by,
                expires_at=expires_at,
                condition=condition
            )

            logger.info(f"Wrote tuple: ({subject}, {relation}, {object})")
            return tuple_obj

        except Exception as e:
            logger.error(f"Failed to write tuple: {e}")
            raise

    def delete_tuple(self, subject: str, relation: str, object: str) -> bool:
        """Delete a relationship tuple."""
        conn = self._get_conn()
        cursor = conn.execute("""
            DELETE FROM relation_tuples
            WHERE subject = ? AND relation = ? AND object = ?
        """, (subject, relation, object))
        conn.commit()

        self._invalidate_cache(subject, object)

        deleted = cursor.rowcount > 0
        if deleted:
            logger.info(f"Deleted tuple: ({subject}, {relation}, {object})")
        return deleted

    def check(
        self,
        subject: str,
        relation: str,
        object: str,
        use_inheritance: bool = True
    ) -> CheckResult:
        """
        Check if a relationship exists.

        Args:
            subject: Subject to check (e.g., "user:alice")
            relation: Relation to check (e.g., "owner")
            object: Object to check against (e.g., "workspace:acme")
            use_inheritance: Whether to consider role hierarchy

        Returns:
            CheckResult with allowed status and details
        """
        # Check cache
        cache_key = f"{subject}|{relation}|{object}|{use_inheritance}"
        if cache_key in self._cache:
            result = self._cache[cache_key]
            result.cache_hit = True
            return result

        # Direct check
        direct_result = self._check_direct(subject, relation, object)
        if direct_result.allowed:
            self._cache[cache_key] = direct_result
            return direct_result

        # Check role hierarchy (if owner, also has admin/member/etc.)
        if use_inheritance and relation in self.ROLE_HIERARCHY:
            for inherited_relation in self.ROLE_HIERARCHY.get(relation, []):
                # Check if subject has a higher role
                for higher_role, inherits in self.ROLE_HIERARCHY.items():
                    if relation in inherits:
                        higher_result = self._check_direct(subject, higher_role, object)
                        if higher_result.allowed:
                            result = CheckResult(
                                allowed=True,
                                reason=f"Inherited from {higher_role} role",
                                matched_tuples=higher_result.matched_tuples,
                                computed_via=f"hierarchy:{higher_role}->{relation}"
                            )
                            self._cache[cache_key] = result
                            return result

        # Check subject sets (groups)
        group_result = self._check_subject_sets(subject, relation, object)
        if group_result.allowed:
            self._cache[cache_key] = group_result
            return group_result

        # Not found
        result = CheckResult(
            allowed=False,
            reason=f"No relation ({subject}, {relation}, {object}) found"
        )
        self._cache[cache_key] = result
        return result

    def _check_direct(self, subject: str, relation: str, object: str) -> CheckResult:
        """Check for direct tuple match."""
        conn = self._get_conn()
        now = datetime.utcnow().isoformat() + "Z"

        cursor = conn.execute("""
            SELECT * FROM relation_tuples
            WHERE subject = ? AND relation = ? AND object = ?
            AND (expires_at IS NULL OR expires_at > ?)
        """, (subject, relation, object, now))

        row = cursor.fetchone()
        if row:
            tuple_obj = RelationTuple(
                subject=row["subject"],
                relation=row["relation"],
                object=row["object"],
                created_at=row["created_at"],
                created_by=row["created_by"],
                expires_at=row["expires_at"],
                condition=row["condition"]
            )

            # Check condition if present
            if tuple_obj.condition:
                # TODO: Evaluate condition expression
                pass

            return CheckResult(
                allowed=True,
                reason=f"Direct match: ({subject}, {relation}, {object})",
                matched_tuples=[tuple_obj]
            )

        return CheckResult(allowed=False, reason="No direct match")

    def _check_subject_sets(self, subject: str, relation: str, object: str) -> CheckResult:
        """Check if subject is member of a group that has the relation."""
        conn = self._get_conn()

        # Find groups the subject belongs to
        cursor = conn.execute("""
            SELECT set_name FROM subject_sets WHERE member = ?
        """, (subject,))

        groups = [row["set_name"] for row in cursor.fetchall()]

        for group in groups:
            group_subject = f"group:{group}"
            group_result = self._check_direct(group_subject, relation, object)
            if group_result.allowed:
                return CheckResult(
                    allowed=True,
                    reason=f"Via group membership: {group}",
                    matched_tuples=group_result.matched_tuples,
                    computed_via=f"group:{group}"
                )

        return CheckResult(allowed=False, reason="No group match")

    def list_relations(
        self,
        subject: Optional[str] = None,
        relation: Optional[str] = None,
        object: Optional[str] = None,
        limit: int = 100
    ) -> List[RelationTuple]:
        """List relation tuples with optional filters."""
        conn = self._get_conn()

        query = "SELECT * FROM relation_tuples WHERE 1=1"
        params = []

        if subject:
            query += " AND subject = ?"
            params.append(subject)
        if relation:
            query += " AND relation = ?"
            params.append(relation)
        if object:
            query += " AND object = ?"
            params.append(object)

        query += f" LIMIT {limit}"

        cursor = conn.execute(query, params)

        tuples = []
        for row in cursor.fetchall():
            tuples.append(RelationTuple(
                subject=row["subject"],
                relation=row["relation"],
                object=row["object"],
                created_at=row["created_at"],
                created_by=row["created_by"],
                expires_at=row["expires_at"],
                condition=row["condition"]
            ))

        return tuples

    def add_to_subject_set(self, set_name: str, member: str) -> None:
        """Add a member to a subject set (group)."""
        conn = self._get_conn()
        now = datetime.utcnow().isoformat() + "Z"

        conn.execute("""
            INSERT OR IGNORE INTO subject_sets (set_name, member, created_at)
            VALUES (?, ?, ?)
        """, (set_name, member, now))
        conn.commit()

        logger.info(f"Added {member} to subject set {set_name}")

    def remove_from_subject_set(self, set_name: str, member: str) -> None:
        """Remove a member from a subject set."""
        conn = self._get_conn()
        conn.execute("""
            DELETE FROM subject_sets WHERE set_name = ? AND member = ?
        """, (set_name, member))
        conn.commit()

    def get_subject_set_members(self, set_name: str) -> List[str]:
        """Get all members of a subject set."""
        conn = self._get_conn()
        cursor = conn.execute("""
            SELECT member FROM subject_sets WHERE set_name = ?
        """, (set_name,))
        return [row["member"] for row in cursor.fetchall()]

    def _invalidate_cache(self, subject: str, object: str) -> None:
        """Invalidate cache entries related to subject or object."""
        keys_to_delete = [
            k for k in self._cache.keys()
            if subject in k or object in k
        ]
        for key in keys_to_delete:
            del self._cache[key]

        # Also trim cache if too large
        if len(self._cache) > self._cache_max_size:
            # Remove oldest half
            keys = list(self._cache.keys())[:len(self._cache) // 2]
            for key in keys:
                del self._cache[key]

    def clear_cache(self) -> None:
        """Clear the entire cache."""
        self._cache.clear()


class ZanzibarAuthorizer:
    """
    High-level authorization interface using Zanzibar graph.
    Provides convenient methods for common authorization patterns.
    """

    def __init__(self, graph: Optional[RelationshipGraph] = None):
        self.graph = graph or RelationshipGraph()

    def setup_workspace(
        self,
        workspace_id: str,
        owner_id: str,
        allowed_domains: Optional[List[str]] = None,
        trusted_contacts: Optional[List[str]] = None
    ) -> None:
        """
        Initialize a workspace with owner and allowed relationships.

        Args:
            workspace_id: Workspace identifier
            owner_id: Owner user ID
            allowed_domains: List of allowed external domains
            trusted_contacts: List of trusted contact emails
        """
        workspace_obj = f"workspace:{workspace_id}"

        # Set owner
        self.graph.write_tuple(
            subject=f"user:{owner_id}",
            relation="owner",
            object=workspace_obj,
            created_by="system"
        )

        # Add allowed domains
        for domain in (allowed_domains or []):
            self.graph.write_tuple(
                subject=f"domain:{domain}",
                relation="allowed_for",
                object=workspace_obj,
                created_by="system"
            )

        # Add trusted contacts
        for contact in (trusted_contacts or []):
            self.graph.write_tuple(
                subject=f"contact:{contact}",
                relation="in_crm",
                object=workspace_obj,
                created_by="system"
            )

        logger.info(f"Initialized workspace {workspace_id} with owner {owner_id}")

    def can_send_to_recipient(
        self,
        recipient: str,
        workspace_id: str
    ) -> CheckResult:
        """
        Check if recipient is authorized for communication.

        Args:
            recipient: Email address or domain
            workspace_id: Workspace context

        Returns:
            CheckResult indicating if recipient is allowed
        """
        workspace_obj = f"workspace:{workspace_id}"

        # Check if recipient is in CRM
        contact_result = self.graph.check(
            subject=f"contact:{recipient}",
            relation="in_crm",
            object=workspace_obj
        )
        if contact_result.allowed:
            return contact_result

        # Check if domain is allowed
        domain = recipient.split("@")[-1] if "@" in recipient else recipient
        domain_result = self.graph.check(
            subject=f"domain:{domain}",
            relation="allowed_for",
            object=workspace_obj
        )
        if domain_result.allowed:
            return domain_result

        # Check for wildcard domain patterns
        parts = domain.split(".")
        for i in range(len(parts)):
            wildcard_domain = "*." + ".".join(parts[i:])
            wildcard_result = self.graph.check(
                subject=f"domain:{wildcard_domain}",
                relation="allowed_for",
                object=workspace_obj
            )
            if wildcard_result.allowed:
                return wildcard_result

        return CheckResult(
            allowed=False,
            reason=f"Recipient {recipient} not in CRM and domain not allowed"
        )

    def can_use_tool(
        self,
        agent_id: str,
        tool: str,
        workspace_id: str
    ) -> CheckResult:
        """
        Check if agent can use a specific tool in workspace.

        Args:
            agent_id: Agent identifier
            tool: Tool name
            workspace_id: Workspace context

        Returns:
            CheckResult indicating if tool use is allowed
        """
        workspace_obj = f"workspace:{workspace_id}"

        # First check if agent is member of workspace
        membership = self.graph.check(
            subject=f"agent:{agent_id}",
            relation="member",
            object=workspace_obj
        )
        if not membership.allowed:
            return CheckResult(
                allowed=False,
                reason=f"Agent {agent_id} is not a member of workspace {workspace_id}"
            )

        # Check if tool is restricted
        restricted = self.graph.check(
            subject=f"tool:{tool}",
            relation="restricted_to",
            object=workspace_obj
        )

        # If tool is not restricted, allow
        if not restricted.allowed:
            return CheckResult(
                allowed=True,
                reason=f"Tool {tool} is not restricted"
            )

        # Tool is restricted - check if agent has explicit permission
        can_use = self.graph.check(
            subject=f"agent:{agent_id}",
            relation="can_use",
            object=f"tool:{tool}"
        )

        return can_use

    def has_authority(
        self,
        user_id: str,
        required_relation: str,
        workspace_id: str
    ) -> CheckResult:
        """
        Check if user has required authority level in workspace.

        Args:
            user_id: User identifier
            required_relation: Required role (owner, admin, member, etc.)
            workspace_id: Workspace context

        Returns:
            CheckResult with authority check result
        """
        return self.graph.check(
            subject=f"user:{user_id}",
            relation=required_relation,
            object=f"workspace:{workspace_id}",
            use_inheritance=True  # Owner can do what admin can, etc.
        )

    def add_trusted_contact(
        self,
        contact: str,
        workspace_id: str,
        added_by: str
    ) -> RelationTuple:
        """Add a contact to the trusted contacts / CRM."""
        return self.graph.write_tuple(
            subject=f"contact:{contact}",
            relation="in_crm",
            object=f"workspace:{workspace_id}",
            created_by=added_by
        )

    def add_allowed_domain(
        self,
        domain: str,
        workspace_id: str,
        added_by: str
    ) -> RelationTuple:
        """Add a domain to allowed domains."""
        return self.graph.write_tuple(
            subject=f"domain:{domain}",
            relation="allowed_for",
            object=f"workspace:{workspace_id}",
            created_by=added_by
        )

    def block_domain(
        self,
        domain: str,
        workspace_id: str,
        blocked_by: str
    ) -> RelationTuple:
        """Block a domain."""
        # Remove any allowed relation
        self.graph.delete_tuple(
            subject=f"domain:{domain}",
            relation="allowed_for",
            object=f"workspace:{workspace_id}"
        )

        return self.graph.write_tuple(
            subject=f"domain:{domain}",
            relation="blocked_for",
            object=f"workspace:{workspace_id}",
            created_by=blocked_by
        )


# Policy integration function
def has_relation(subject: str, relation: str, object: str) -> bool:
    """
    Check if a relationship exists (for use in policy evaluation).
    This is the main interface used by OPA/Rego policies.

    Example Rego:
        allow {
            input.car.target_kind == "person"
            has_relation(input.car.destination, "in_crm", input.car.workspace_id)
        }
    """
    graph = get_relationship_graph()
    result = graph.check(subject, relation, object)
    return result.allowed


# Singleton instances
_graph: Optional[RelationshipGraph] = None
_authorizer: Optional[ZanzibarAuthorizer] = None


def get_relationship_graph() -> RelationshipGraph:
    """Get singleton relationship graph."""
    global _graph
    if _graph is None:
        _graph = RelationshipGraph()
    return _graph


def get_zanzibar_authorizer() -> ZanzibarAuthorizer:
    """Get singleton Zanzibar authorizer."""
    global _authorizer
    if _authorizer is None:
        _authorizer = ZanzibarAuthorizer(get_relationship_graph())
    return _authorizer
