"""
Shadow Mode Module for Faramesh Guard.

Provides shadow mode evaluation to test new policies without affecting
production traffic. Records what would have happened for comparison.
"""

from .evaluator import (
    ShadowModeEvaluator,
    ShadowResult,
    ShadowComparison,
    ShadowStats,
    get_shadow_evaluator,
    create_shadow_routes,
)

__all__ = [
    "ShadowModeEvaluator",
    "ShadowResult",
    "ShadowComparison",
    "ShadowStats",
    "get_shadow_evaluator",
    "create_shadow_routes",
]
