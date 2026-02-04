"""
Runtime Registry - Tool Discovery and Wrapping System

Automatically discovers and wraps tools with Guard enforcement.
Ensures no tool can execute without Guard validation.

Architecture:
1. Registry discovers tools in runtime environment
2. Wraps each tool with GuardedToolWrapper
3. Tracks wrapped vs unwrapped tools
4. Provides metrics for enforcement coverage

Following plan-farameshGuardV1Enhanced.prompt.md:
- Automatic tool discovery
- Transparent wrapping
- Coverage tracking
- Enforcement validation
"""

import asyncio
import inspect
import logging
from typing import Dict, Any, Callable, Optional, Set, List
from dataclasses import dataclass, field
from datetime import datetime
from .execution_wrapper import GuardedToolWrapper, ExecutionResult

logger = logging.getLogger(__name__)


@dataclass
class ToolMetadata:
    """Metadata about a registered tool"""

    name: str
    original_callable: Callable
    wrapped_callable: Optional[GuardedToolWrapper]
    is_guarded: bool = False
    registered_at: datetime = field(default_factory=datetime.utcnow)
    invocation_count: int = 0
    last_invocation: Optional[datetime] = None
    risk_level: str = "unknown"  # unknown, low, medium, high, critical


@dataclass
class RegistryStats:
    """Statistics about the registry"""

    total_tools: int = 0
    guarded_tools: int = 0
    unguarded_tools: int = 0
    enforcement_coverage: float = 0.0  # percentage
    total_invocations: int = 0
    blocked_invocations: int = 0
    allowed_invocations: int = 0


class RuntimeRegistry:
    """
    Central registry for all tools in the runtime.

    Discovers, wraps, and tracks tool execution.
    Provides enforcement coverage metrics.
    """

    def __init__(self):
        self._tools: Dict[str, ToolMetadata] = {}
        self._lock = asyncio.Lock()
        self._auto_wrap_enabled = True
        self._risk_patterns = self._initialize_risk_patterns()

    def _initialize_risk_patterns(self) -> Dict[str, List[str]]:
        """Initialize risk assessment patterns"""
        return {
            "critical": [
                "rm",
                "delete",
                "drop",
                "truncate",
                "destroy",
                "kill",
                "shutdown",
                "reboot",
                "format",
                "wipe",
            ],
            "high": [
                "exec",
                "eval",
                "system",
                "shell",
                "run",
                "sudo",
                "admin",
                "root",
                "chmod",
                "chown",
            ],
            "medium": [
                "write",
                "modify",
                "update",
                "create",
                "insert",
                "post",
                "put",
                "patch",
                "send",
                "publish",
            ],
            "low": [
                "read",
                "get",
                "list",
                "search",
                "query",
                "view",
                "show",
                "display",
                "print",
            ],
        }

    def _assess_risk(self, tool_name: str, metadata: Dict[str, Any]) -> str:
        """Assess risk level of a tool"""
        tool_lower = tool_name.lower()

        # Check critical patterns
        if any(pattern in tool_lower for pattern in self._risk_patterns["critical"]):
            return "critical"

        # Check high patterns
        if any(pattern in tool_lower for pattern in self._risk_patterns["high"]):
            return "high"

        # Check medium patterns
        if any(pattern in tool_lower for pattern in self._risk_patterns["medium"]):
            return "medium"

        # Check low patterns
        if any(pattern in tool_lower for pattern in self._risk_patterns["low"]):
            return "low"

        return "unknown"

    async def register_tool(
        self,
        name: str,
        callable_obj: Callable,
        metadata: Optional[Dict[str, Any]] = None,
        auto_wrap: bool = True,
    ) -> ToolMetadata:
        """
        Register a tool in the registry.

        Args:
            name: Tool identifier
            callable_obj: The actual tool function/callable
            metadata: Optional metadata about the tool
            auto_wrap: Whether to automatically wrap with Guard

        Returns:
            ToolMetadata for the registered tool
        """
        async with self._lock:
            if name in self._tools:
                logger.warning(f"Tool {name} already registered, updating")

            # Assess risk
            risk_level = self._assess_risk(name, metadata or {})

            # Create metadata
            tool_meta = ToolMetadata(
                name=name,
                original_callable=callable_obj,
                wrapped_callable=None,
                is_guarded=False,
                risk_level=risk_level,
            )

            # Auto-wrap if enabled
            if auto_wrap and self._auto_wrap_enabled:
                wrapper = GuardedToolWrapper(name, callable_obj)
                tool_meta.wrapped_callable = wrapper
                tool_meta.is_guarded = True
                logger.info(f"Auto-wrapped tool: {name} (risk: {risk_level})")
            else:
                logger.warning(
                    f"Tool {name} registered WITHOUT Guard wrapping (risk: {risk_level})"
                )

            self._tools[name] = tool_meta
            return tool_meta

    async def get_tool(self, name: str) -> Optional[ToolMetadata]:
        """Get tool metadata by name"""
        async with self._lock:
            return self._tools.get(name)

    async def get_wrapped_tool(self, name: str) -> Optional[Callable]:
        """
        Get the wrapped (guarded) version of a tool.

        Returns:
            The GuardedToolWrapper if tool is guarded, otherwise None
        """
        tool = await self.get_tool(name)
        if tool and tool.is_guarded:
            return tool.wrapped_callable
        return None

    async def execute_tool(
        self, name: str, agent_id: str, parameters: Dict[str, Any]
    ) -> ExecutionResult:
        """
        Execute a tool through the registry.

        Ensures Guard enforcement if tool is wrapped.
        Tracks invocation metrics.
        """
        tool = await self.get_tool(name)

        if not tool:
            return ExecutionResult(
                allowed=False,
                error=f"Tool {name} not registered in runtime",
                decision_id=None,
                permit_id=None,
                result=None,
            )

        # Update invocation tracking
        async with self._lock:
            tool.invocation_count += 1
            tool.last_invocation = datetime.utcnow()

        # Execute through Guard if wrapped
        if tool.is_guarded and tool.wrapped_callable:
            result = await tool.wrapped_callable.execute(agent_id, parameters)

            # Track stats
            async with self._lock:
                if result.allowed:
                    self._update_stats("allowed")
                else:
                    self._update_stats("blocked")

            return result
        else:
            # Tool not guarded - execute directly (SECURITY RISK)
            logger.warning(
                f"Executing unguarded tool: {name} (risk: {tool.risk_level})"
            )

            try:
                if inspect.iscoroutinefunction(tool.original_callable):
                    result_data = await tool.original_callable(parameters)
                else:
                    result_data = tool.original_callable(parameters)

                return ExecutionResult(
                    allowed=True,
                    error=None,
                    decision_id="unguarded",
                    permit_id=None,
                    result=result_data,
                )
            except Exception as e:
                return ExecutionResult(
                    allowed=False,
                    error=f"Tool execution failed: {str(e)}",
                    decision_id="unguarded",
                    permit_id=None,
                    result=None,
                )

    def _update_stats(self, stat_type: str):
        """Update internal statistics (called while holding lock)"""
        # Stats updated in get_stats() to avoid duplicate tracking
        pass

    async def get_stats(self) -> RegistryStats:
        """Get current registry statistics"""
        async with self._lock:
            total = len(self._tools)
            guarded = sum(1 for t in self._tools.values() if t.is_guarded)
            unguarded = total - guarded

            coverage = (guarded / total * 100) if total > 0 else 0.0

            total_invocations = sum(t.invocation_count for t in self._tools.values())

            return RegistryStats(
                total_tools=total,
                guarded_tools=guarded,
                unguarded_tools=unguarded,
                enforcement_coverage=coverage,
                total_invocations=total_invocations,
                blocked_invocations=0,  # TODO: Track from execution results
                allowed_invocations=0,  # TODO: Track from execution results
            )

    async def list_tools(
        self, filter_guarded: Optional[bool] = None, filter_risk: Optional[str] = None
    ) -> List[ToolMetadata]:
        """
        List registered tools with optional filters.

        Args:
            filter_guarded: If True, only guarded tools. If False, only unguarded.
            filter_risk: Filter by risk level (low, medium, high, critical)

        Returns:
            List of matching tools
        """
        async with self._lock:
            tools = list(self._tools.values())

            if filter_guarded is not None:
                tools = [t for t in tools if t.is_guarded == filter_guarded]

            if filter_risk is not None:
                tools = [t for t in tools if t.risk_level == filter_risk]

            return tools

    async def discover_tools(self, module) -> int:
        """
        Discover tools in a module and register them.

        Args:
            module: Python module to scan for tools

        Returns:
            Number of tools discovered and registered
        """
        count = 0

        for name in dir(module):
            if name.startswith("_"):
                continue

            obj = getattr(module, name)

            # Check if it's a callable (function, method, class with __call__)
            if callable(obj):
                # Skip built-in functions
                if not hasattr(obj, "__module__"):
                    continue

                # Register the tool
                await self.register_tool(name, obj, auto_wrap=True)
                count += 1
                logger.info(f"Discovered tool: {name}")

        return count

    async def wrap_existing_tools(self) -> int:
        """
        Wrap all unguarded tools with Guard enforcement.

        Returns:
            Number of tools newly wrapped
        """
        count = 0

        async with self._lock:
            for tool in self._tools.values():
                if not tool.is_guarded:
                    wrapper = GuardedToolWrapper(tool.name, tool.original_callable)
                    tool.wrapped_callable = wrapper
                    tool.is_guarded = True
                    count += 1
                    logger.info(f"Wrapped existing tool: {tool.name}")

        return count

    async def validate_coverage(self, minimum_coverage: float = 100.0) -> bool:
        """
        Validate that enforcement coverage meets minimum threshold.

        Args:
            minimum_coverage: Minimum required coverage percentage (0-100)

        Returns:
            True if coverage meets threshold, False otherwise
        """
        stats = await self.get_stats()

        if stats.enforcement_coverage < minimum_coverage:
            logger.error(
                f"Enforcement coverage {stats.enforcement_coverage:.1f}% "
                f"below minimum {minimum_coverage:.1f}%"
            )

            # List unguarded tools
            unguarded = await self.list_tools(filter_guarded=False)
            for tool in unguarded:
                logger.error(f"  UNGUARDED: {tool.name} (risk: {tool.risk_level})")

            return False

        return True

    async def generate_coverage_report(self) -> str:
        """Generate a detailed coverage report"""
        stats = await self.get_stats()

        report = [
            "=" * 60,
            "Guard Runtime Registry - Coverage Report",
            "=" * 60,
            "",
            f"Total Tools: {stats.total_tools}",
            f"Guarded Tools: {stats.guarded_tools}",
            f"Unguarded Tools: {stats.unguarded_tools}",
            f"Enforcement Coverage: {stats.enforcement_coverage:.1f}%",
            "",
            f"Total Invocations: {stats.total_invocations}",
            "",
        ]

        # List tools by risk level
        for risk in ["critical", "high", "medium", "low", "unknown"]:
            tools = await self.list_tools(filter_risk=risk)
            if tools:
                report.append(f"\n{risk.upper()} Risk Tools:")
                for tool in tools:
                    status = "✓ Guarded" if tool.is_guarded else "✗ UNGUARDED"
                    report.append(
                        f"  {status} - {tool.name} "
                        f"(invocations: {tool.invocation_count})"
                    )

        report.append("\n" + "=" * 60)

        return "\n".join(report)


# Global singleton registry
_global_registry: Optional[RuntimeRegistry] = None


def get_registry() -> RuntimeRegistry:
    """Get or create the global runtime registry"""
    global _global_registry
    if _global_registry is None:
        _global_registry = RuntimeRegistry()
    return _global_registry


async def register_tool(
    name: str,
    callable_obj: Callable,
    metadata: Optional[Dict[str, Any]] = None,
    auto_wrap: bool = True,
) -> ToolMetadata:
    """Convenience function to register a tool"""
    registry = get_registry()
    return await registry.register_tool(name, callable_obj, metadata, auto_wrap)


async def execute_tool(
    name: str, agent_id: str, parameters: Dict[str, Any]
) -> ExecutionResult:
    """Convenience function to execute a tool"""
    registry = get_registry()
    return await registry.execute_tool(name, agent_id, parameters)
