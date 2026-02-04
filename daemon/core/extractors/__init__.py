"""
Rich CAR Extractors - Per-tool context extraction.

This module provides specialized extractors for different tool types,
enabling richer context for policy decisions.
"""

from .base import BaseExtractor, ExtractorResult, RiskFactor, ExtractedTarget
from .bash import BashExtractor
from .filesystem import FileSystemExtractor
from .http import HTTPExtractor
from .browser import BrowserExtractor
from .registry import get_extractor, register_extractor, ExtractorRegistry

__all__ = [
    "BaseExtractor",
    "ExtractorResult",
    "ExtractedTarget",
    "RiskFactor",
    "BashExtractor",
    "FileSystemExtractor",
    "HTTPExtractor",
    "BrowserExtractor",
    "get_extractor",
    "register_extractor",
    "ExtractorRegistry",
]
