"""
Runtime Capabilities Registry - Version compatibility management.

This module tracks Guard capabilities, client versions, and ensures
compatibility between different components.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
from datetime import datetime

logger = logging.getLogger("service.runtime_capabilities")


class CapabilityCategory(Enum):
    """Categories of Guard capabilities."""

    CORE = "core"
    POLICY = "policy"
    APPROVAL = "approval"
    AUDIT = "audit"
    BEHAVIORAL = "behavioral"
    INTEGRATION = "integration"
    UI = "ui"


@dataclass
class Capability:
    """Represents a Guard capability."""

    name: str
    version: str
    category: CapabilityCategory
    description: str
    since_version: str
    deprecated: bool = False
    deprecated_in: Optional[str] = None
    replacement: Optional[str] = None
    required_features: Set[str] = field(default_factory=set)

    def is_compatible(self, client_version: str) -> bool:
        """Check if capability is compatible with client version."""
        if self.deprecated:
            # Deprecated features work but warn
            return True

        # Compare versions
        return compare_versions(client_version, self.since_version) >= 0


@dataclass
class ClientInfo:
    """Information about a connected client."""

    client_id: str
    client_type: str  # openclaw, sdk, cli, ui
    client_version: str
    guard_protocol_version: str
    capabilities_requested: Set[str] = field(default_factory=set)
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)

    def supports_capability(self, capability_name: str) -> bool:
        """Check if client supports a capability."""
        return capability_name in self.capabilities_requested


def compare_versions(v1: str, v2: str) -> int:
    """
    Compare two semantic versions.
    Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
    """

    def parse_version(v: str) -> Tuple[int, ...]:
        # Remove any prefix like 'v'
        v = v.lstrip("v")
        # Split by . and convert to ints
        parts = []
        for part in v.split("."):
            # Handle pre-release versions like 1.0.0-beta
            main = re.match(r"^(\d+)", part)
            if main:
                parts.append(int(main.group(1)))
        return tuple(parts)

    p1 = parse_version(v1)
    p2 = parse_version(v2)

    # Pad shorter version
    max_len = max(len(p1), len(p2))
    p1 = p1 + (0,) * (max_len - len(p1))
    p2 = p2 + (0,) * (max_len - len(p2))

    if p1 < p2:
        return -1
    elif p1 > p2:
        return 1
    return 0


class CapabilityRegistry:
    """
    Registry of Guard capabilities and client compatibility.

    Tracks:
    - Available Guard capabilities
    - Client versions and their supported features
    - Protocol compatibility
    """

    # Current Guard version
    GUARD_VERSION = "1.0.0"

    # Minimum supported protocol version
    MIN_PROTOCOL_VERSION = "1.0.0"

    # Current protocol version
    PROTOCOL_VERSION = "1.0.0"

    def __init__(self):
        self.capabilities: Dict[str, Capability] = {}
        self.clients: Dict[str, ClientInfo] = {}
        self._register_builtin_capabilities()

    def _register_builtin_capabilities(self) -> None:
        """Register all built-in capabilities."""

        # Core capabilities
        self.register(
            Capability(
                name="execute",
                version="1.0.0",
                category=CapabilityCategory.CORE,
                description="Execute action authorization",
                since_version="1.0.0",
            )
        )

        self.register(
            Capability(
                name="permit",
                version="1.0.0",
                category=CapabilityCategory.CORE,
                description="HMAC-signed execution permits",
                since_version="1.0.0",
            )
        )

        self.register(
            Capability(
                name="car_v1",
                version="1.0.0",
                category=CapabilityCategory.CORE,
                description="CAR (Content Addressable Record) v1 schema",
                since_version="1.0.0",
            )
        )

        # Policy capabilities
        self.register(
            Capability(
                name="policy_modes",
                version="1.0.0",
                category=CapabilityCategory.POLICY,
                description="Policy mode switching (safe, strict, permissive)",
                since_version="1.0.0",
            )
        )

        self.register(
            Capability(
                name="cold_start_packs",
                version="1.0.0",
                category=CapabilityCategory.POLICY,
                description="Cold-start policy pack loading",
                since_version="1.0.0",
            )
        )

        self.register(
            Capability(
                name="yaml_policies",
                version="1.0.0",
                category=CapabilityCategory.POLICY,
                description="YAML policy file support",
                since_version="1.0.0",
            )
        )

        # Approval capabilities
        self.register(
            Capability(
                name="approval_queue",
                version="1.0.0",
                category=CapabilityCategory.APPROVAL,
                description="Pending action approval queue",
                since_version="1.0.0",
            )
        )

        self.register(
            Capability(
                name="approval_authority",
                version="1.0.0",
                category=CapabilityCategory.APPROVAL,
                description="Role-based approval authority",
                since_version="1.0.0",
            )
        )

        self.register(
            Capability(
                name="quorum",
                version="1.0.0",
                category=CapabilityCategory.APPROVAL,
                description="Multi-approver quorum support",
                since_version="1.0.0",
            )
        )

        # Audit capabilities
        self.register(
            Capability(
                name="audit_log",
                version="1.0.0",
                category=CapabilityCategory.AUDIT,
                description="Tamper-evident audit logging",
                since_version="1.0.0",
            )
        )

        self.register(
            Capability(
                name="merkle_chain",
                version="1.0.0",
                category=CapabilityCategory.AUDIT,
                description="Merkle hash chain for audit integrity",
                since_version="1.0.0",
            )
        )

        # Behavioral capabilities
        self.register(
            Capability(
                name="anomaly_detection",
                version="1.0.0",
                category=CapabilityCategory.BEHAVIORAL,
                description="Behavioral anomaly detection",
                since_version="1.0.0",
            )
        )

        self.register(
            Capability(
                name="rate_limiting",
                version="1.0.0",
                category=CapabilityCategory.BEHAVIORAL,
                description="Rate spike detection and limiting",
                since_version="1.0.0",
            )
        )

        self.register(
            Capability(
                name="sequence_model",
                version="1.0.0",
                category=CapabilityCategory.BEHAVIORAL,
                description="Workflow sequence anomaly detection",
                since_version="1.0.0",
            )
        )

        self.register(
            Capability(
                name="signal_fusion",
                version="1.0.0",
                category=CapabilityCategory.BEHAVIORAL,
                description="Multi-signal fusion for decisions",
                since_version="1.0.0",
            )
        )

        # Integration capabilities
        self.register(
            Capability(
                name="websocket_notifications",
                version="1.0.0",
                category=CapabilityCategory.INTEGRATION,
                description="Real-time WebSocket decision feed",
                since_version="1.0.0",
            )
        )

        self.register(
            Capability(
                name="ipc_socket",
                version="1.0.0",
                category=CapabilityCategory.INTEGRATION,
                description="Unix domain socket for local IPC",
                since_version="1.0.0",
            )
        )

        self.register(
            Capability(
                name="openclaw_integration",
                version="1.0.0",
                category=CapabilityCategory.INTEGRATION,
                description="OpenClaw patcher integration",
                since_version="1.0.0",
            )
        )

        # UI capabilities
        self.register(
            Capability(
                name="cli",
                version="1.0.0",
                category=CapabilityCategory.UI,
                description="Command-line interface",
                since_version="1.0.0",
            )
        )

        self.register(
            Capability(
                name="tauri_ui",
                version="1.0.0",
                category=CapabilityCategory.UI,
                description="Tauri desktop application",
                since_version="1.0.0",
            )
        )

    def register(self, capability: Capability) -> None:
        """Register a capability."""
        self.capabilities[capability.name] = capability
        logger.debug(f"Registered capability: {capability.name} v{capability.version}")

    def get(self, name: str) -> Optional[Capability]:
        """Get a capability by name."""
        return self.capabilities.get(name)

    def list_capabilities(
        self,
        category: Optional[CapabilityCategory] = None,
    ) -> List[Capability]:
        """List all capabilities, optionally filtered by category."""
        caps = list(self.capabilities.values())

        if category:
            caps = [c for c in caps if c.category == category]

        return sorted(caps, key=lambda c: (c.category.value, c.name))

    def register_client(
        self,
        client_id: str,
        client_type: str,
        client_version: str,
        protocol_version: str,
        requested_capabilities: Optional[Set[str]] = None,
    ) -> Tuple[bool, str, Set[str]]:
        """
        Register a client and negotiate capabilities.

        Returns:
            (success, message, granted_capabilities)
        """
        # Check protocol version
        if compare_versions(protocol_version, self.MIN_PROTOCOL_VERSION) < 0:
            return (
                False,
                f"Protocol version {protocol_version} is below minimum {self.MIN_PROTOCOL_VERSION}",
                set(),
            )

        # Determine granted capabilities
        granted = set()
        warnings = []

        if requested_capabilities:
            for cap_name in requested_capabilities:
                cap = self.get(cap_name)
                if cap is None:
                    warnings.append(f"Unknown capability: {cap_name}")
                    continue

                if cap.is_compatible(client_version):
                    granted.add(cap_name)
                    if cap.deprecated:
                        warnings.append(
                            f"Capability {cap_name} is deprecated"
                            f"{f', use {cap.replacement}' if cap.replacement else ''}"
                        )
                else:
                    warnings.append(
                        f"Capability {cap_name} requires Guard {cap.since_version}+"
                    )
        else:
            # Grant all compatible capabilities
            for cap in self.capabilities.values():
                if cap.is_compatible(client_version) and not cap.deprecated:
                    granted.add(cap.name)

        # Register client
        self.clients[client_id] = ClientInfo(
            client_id=client_id,
            client_type=client_type,
            client_version=client_version,
            guard_protocol_version=protocol_version,
            capabilities_requested=granted,
        )

        message = "OK"
        if warnings:
            message = "; ".join(warnings)

        logger.info(
            f"Registered client {client_id} ({client_type} v{client_version}) "
            f"with {len(granted)} capabilities"
        )

        return (True, message, granted)

    def unregister_client(self, client_id: str) -> bool:
        """Unregister a client."""
        if client_id in self.clients:
            del self.clients[client_id]
            logger.info(f"Unregistered client {client_id}")
            return True
        return False

    def get_client(self, client_id: str) -> Optional[ClientInfo]:
        """Get client info."""
        return self.clients.get(client_id)

    def update_client_seen(self, client_id: str) -> None:
        """Update client last seen timestamp."""
        if client_id in self.clients:
            self.clients[client_id].last_seen = datetime.utcnow()

    def client_has_capability(
        self,
        client_id: str,
        capability_name: str,
    ) -> bool:
        """Check if a client has a specific capability."""
        client = self.get_client(client_id)
        if not client:
            return False
        return client.supports_capability(capability_name)

    def get_server_info(self) -> Dict:
        """Get server capability information."""
        return {
            "guard_version": self.GUARD_VERSION,
            "protocol_version": self.PROTOCOL_VERSION,
            "min_protocol_version": self.MIN_PROTOCOL_VERSION,
            "capabilities": [
                {
                    "name": c.name,
                    "version": c.version,
                    "category": c.category.value,
                    "deprecated": c.deprecated,
                }
                for c in self.capabilities.values()
            ],
            "total_capabilities": len(self.capabilities),
            "connected_clients": len(self.clients),
        }

    def get_stats(self) -> Dict:
        """Get registry statistics."""
        by_category = {}
        for cap in self.capabilities.values():
            cat = cap.category.value
            if cat not in by_category:
                by_category[cat] = 0
            by_category[cat] += 1

        return {
            "total_capabilities": len(self.capabilities),
            "by_category": by_category,
            "deprecated_count": sum(
                1 for c in self.capabilities.values() if c.deprecated
            ),
            "connected_clients": len(self.clients),
            "client_types": list(set(c.client_type for c in self.clients.values())),
        }


# Singleton instance
_registry: Optional[CapabilityRegistry] = None


def get_capability_registry() -> CapabilityRegistry:
    """Get or create singleton capability registry."""
    global _registry
    if _registry is None:
        _registry = CapabilityRegistry()
    return _registry
