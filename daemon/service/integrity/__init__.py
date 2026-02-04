"""
Guard Self-Integrity Monitoring Module

From guard-plan-v1.md Meta-Layer 7: Guard Self-Integrity Monitoring

Provides:
- Policy integrity verification (policy_hash)
- Guard health monitoring (watchdog)
- Tamper detection
- Self-healing capabilities
"""

from .policy_hash import (
    PolicyIntegrityVerifier,
    PolicyIntegrityRecord,
    IntegrityVerificationResult,
    get_policy_verifier,
)

from .watchdog import (
    GuardWatchdog,
    HealthCheck,
    HealthStatus,
    get_watchdog,
)

__all__ = [
    # Policy integrity
    "PolicyIntegrityVerifier",
    "PolicyIntegrityRecord",
    "IntegrityVerificationResult",
    "get_policy_verifier",
    # Watchdog
    "GuardWatchdog",
    "HealthCheck",
    "HealthStatus",
    "get_watchdog",
]
