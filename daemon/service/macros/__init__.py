"""
Policy Macros Module for Faramesh Guard.

Provides reusable policy building blocks and templates for
common patterns like $SENSITIVE_PATHS, $PRODUCTION_HOURS, etc.
"""

from .policy_macros import (
    PolicyMacroEngine,
    MacroDefinition,
    MacroCategory,
    get_macro_engine,
    create_macro_routes,
)

__all__ = [
    "PolicyMacroEngine",
    "MacroDefinition",
    "MacroCategory",
    "get_macro_engine",
    "create_macro_routes",
]
