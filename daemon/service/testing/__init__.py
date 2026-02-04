"""
Testing Module for Faramesh Guard.

Provides test protection API for verifying live interception.
"""

from .protection_api import (
    TestProtectionAPI,
    InterceptionProof,
    InterceptionTestResult,
    get_test_api,
    create_test_routes,
)

__all__ = [
    "TestProtectionAPI",
    "InterceptionProof",
    "InterceptionTestResult",
    "get_test_api",
    "create_test_routes",
]
