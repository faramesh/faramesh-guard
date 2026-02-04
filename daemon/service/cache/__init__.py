"""
Fast Path Decision Cache module for Faramesh Guard.

High-performance caching for policy decisions.
"""

from .decision_cache import (
    FastPathCache,
    CacheEntry,
    CacheStats,
    CacheDecision,
    CacheStrategy,
    get_fast_path_cache,
    create_cache_routes,
)

__all__ = [
    "FastPathCache",
    "CacheEntry",
    "CacheStats",
    "CacheDecision",
    "CacheStrategy",
    "get_fast_path_cache",
    "create_cache_routes",
]
