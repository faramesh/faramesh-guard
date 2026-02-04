"""
Extractor registry - manages tool-to-extractor mappings.
"""

from typing import Dict, Type, Optional
from .base import BaseExtractor, ExtractorResult


class ExtractorRegistry:
    """Registry for CAR extractors."""

    _extractors: Dict[str, Type[BaseExtractor]] = {}
    _instances: Dict[str, BaseExtractor] = {}

    @classmethod
    def register(cls, name: str, extractor_class: Type[BaseExtractor]) -> None:
        """Register an extractor class."""
        cls._extractors[name] = extractor_class

    @classmethod
    def get(cls, tool_name: str) -> Optional[BaseExtractor]:
        """
        Get extractor for a tool.

        Checks both explicit registrations and pattern matching.
        """
        tool_lower = tool_name.lower()

        # Check explicit registration
        if tool_lower in cls._instances:
            return cls._instances[tool_lower]

        if tool_lower in cls._extractors:
            if tool_lower not in cls._instances:
                cls._instances[tool_lower] = cls._extractors[tool_lower]()
            return cls._instances[tool_lower]

        # Check pattern matching
        for name, extractor_class in cls._extractors.items():
            if extractor_class.matches(tool_name):
                if name not in cls._instances:
                    cls._instances[name] = extractor_class()
                return cls._instances[name]

        return None

    @classmethod
    def extract(cls, tool_name: str, args: Dict) -> ExtractorResult:
        """
        Extract context from tool call.

        Uses the appropriate extractor or returns a generic result.
        """
        extractor = cls.get(tool_name)

        if extractor:
            return extractor.extract(tool_name, args)

        # Generic extraction for unknown tools
        return ExtractorResult(
            tool_name=tool_name,
            operation="unknown",
            authority_domain="general",
            normalized_args=args,
            human_summary=f"Unknown tool: {tool_name}",
        )

    @classmethod
    def list_extractors(cls) -> Dict[str, list]:
        """List all registered extractors and their patterns."""
        result = {}
        for name, extractor_class in cls._extractors.items():
            result[name] = {
                "patterns": extractor_class.tool_patterns,
                "class": extractor_class.__name__,
            }
        return result


# Registration functions
def register_extractor(name: str, extractor_class: Type[BaseExtractor]) -> None:
    """Register an extractor."""
    ExtractorRegistry.register(name, extractor_class)


def get_extractor(tool_name: str) -> Optional[BaseExtractor]:
    """Get extractor for a tool."""
    return ExtractorRegistry.get(tool_name)


# Auto-register built-in extractors
def _register_builtins():
    """Register built-in extractors."""
    from .bash import BashExtractor
    from .filesystem import FileSystemExtractor
    from .http import HTTPExtractor
    from .browser import BrowserExtractor

    register_extractor("bash", BashExtractor)
    register_extractor("filesystem", FileSystemExtractor)
    register_extractor("http", HTTPExtractor)
    register_extractor("browser", BrowserExtractor)


# Register on import
_register_builtins()
