"""
Contextual Allowlist module for Faramesh Guard.

Context-aware allowlists with time windows, scopes, and pattern matching.
"""

from .contextual import (
    ContextualAllowlist,
    AllowlistEntry,
    AllowlistMatch,
    AllowlistScope,
    get_contextual_allowlist,
    create_allowlist_routes,
)

__all__ = [
    "ContextualAllowlist",
    "AllowlistEntry",
    "AllowlistMatch",
    "AllowlistScope",
    "get_contextual_allowlist",
    "create_allowlist_routes",
]
