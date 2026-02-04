"""
Audit service for Guard - includes tamper-evident logs with Merkle chains.
"""

from .merkle_chain import MerkleAuditLog, AuditEntry, get_audit_log

__all__ = [
    "MerkleAuditLog",
    "AuditEntry",
    "get_audit_log",
]
