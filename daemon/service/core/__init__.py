"""
Guard Core - Rust Security Kernel Integration.

This module provides Python bindings to the Rust security kernel.
The architecture separates concerns:

Rust Core (Security Kernel) - Trusted Computing Base:
├─ Permit validation (HMAC verification)
├─ CAR canonicalization (deterministic hashing)
├─ Fast decision cache (lock-free)
├─ Replay detection (ring buffer)
└─ IPC server

Python Daemon (Control Plane):
├─ Policy evaluation
├─ ML / anomaly logic
├─ Approval flow
├─ Audit log
├─ State tracking
└─ API
"""

from .rust_client import (
    RustCoreClient,
    RustCoreError,
    FallbackRustCoreClient,
    Decision,
    CachedDecision,
    GateCheckResult,
    VerificationResult,
    CacheStats,
    ReplayStats,
    get_rust_core_client,
    get_rust_core_client_with_fallback,
    reset_rust_core_client,
    DEFAULT_SOCKET_PATH,
)

__all__ = [
    "RustCoreClient",
    "RustCoreError",
    "FallbackRustCoreClient",
    "Decision",
    "CachedDecision",
    "GateCheckResult",
    "VerificationResult",
    "CacheStats",
    "ReplayStats",
    "get_rust_core_client",
    "get_rust_core_client_with_fallback",
    "reset_rust_core_client",
    "DEFAULT_SOCKET_PATH",
]
