"""
Policy Macros Engine for Faramesh Guard.

Provides reusable policy building blocks that can be referenced in
policy definitions. Macros are expanded at policy evaluation time.

Built-in macros:
- $SENSITIVE_PATHS - System and sensitive file paths
- $PRODUCTION_HOURS - Business hours check
- $HIGH_RISK_COMMANDS - Dangerous shell commands
- $TRUSTED_AGENTS - Pre-approved agent list
- $RESTRICTED_URLS - Blocked API endpoints
- $PII_PATTERNS - Patterns matching personal data
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union
import aiofiles

logger = logging.getLogger(__name__)


class MacroCategory(str, Enum):
    """Categories for organizing macros."""

    PATHS = "paths"
    COMMANDS = "commands"
    PATTERNS = "patterns"
    TIME = "time"
    AGENTS = "agents"
    URLS = "urls"
    CUSTOM = "custom"


class MacroType(str, Enum):
    """Types of macro values."""

    LIST = "list"  # List of values
    PATTERN = "pattern"  # Regex pattern
    FUNCTION = "function"  # Dynamic function
    RANGE = "range"  # Numeric/time range
    COMPOSITE = "composite"  # References other macros


@dataclass
class MacroDefinition:
    """Definition of a policy macro."""

    name: str  # e.g., "SENSITIVE_PATHS"
    category: str
    macro_type: str
    description: str

    # Value based on type
    values: List[str] = field(default_factory=list)  # For LIST type
    pattern: Optional[str] = None  # For PATTERN type
    function_name: Optional[str] = None  # For FUNCTION type
    range_start: Optional[Any] = None  # For RANGE type
    range_end: Optional[Any] = None
    referenced_macros: List[str] = field(default_factory=list)  # For COMPOSITE

    # Metadata
    builtin: bool = False
    enabled: bool = True
    version: str = "1.0.0"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Usage tracking
    usage_count: int = 0
    last_used: Optional[str] = None


@dataclass
class MacroEvaluationResult:
    """Result of evaluating a macro."""

    macro_name: str
    matched: bool
    value_matched: Optional[str] = None
    confidence: float = 1.0
    evaluation_time_ms: float = 0.0
    error: Optional[str] = None


class PolicyMacroEngine:
    """
    Engine for managing and evaluating policy macros.

    Macros are referenced in policies using $MACRO_NAME syntax.
    They provide reusable building blocks for common patterns.

    Example policy using macros:
    ```yaml
    rules:
      - name: "Protect sensitive files"
        match:
          resource: $SENSITIVE_PATHS
        action: deny

      - name: "Allow during business hours"
        match:
          time: $PRODUCTION_HOURS
        action: allow
    ```
    """

    def __init__(
        self,
        data_dir: str = "/var/lib/faramesh-guard/macros",
    ):
        self.data_dir = Path(data_dir)

        # Macro storage
        self._macros: Dict[str, MacroDefinition] = {}
        self._macros_lock = asyncio.Lock()

        # Custom functions
        self._custom_functions: Dict[str, Callable] = {}

        # Running state
        self._running = False

        logger.info("PolicyMacroEngine initialized")

    async def start(self):
        """Start the macro engine and load built-in macros."""
        if self._running:
            return

        self._running = True
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Register built-in macros
        self._register_builtin_macros()

        # Register built-in functions
        self._register_builtin_functions()

        # Load custom macros
        await self._load_custom_macros()

        logger.info(f"PolicyMacroEngine started with {len(self._macros)} macros")

    async def stop(self):
        """Stop the macro engine."""
        self._running = False
        await self._save_custom_macros()
        logger.info("PolicyMacroEngine stopped")

    def _register_builtin_macros(self):
        """Register built-in macros."""
        builtins = [
            # Sensitive paths
            MacroDefinition(
                name="SENSITIVE_PATHS",
                category=MacroCategory.PATHS.value,
                macro_type=MacroType.LIST.value,
                description="System and sensitive file paths that should be protected",
                values=[
                    "/etc/passwd",
                    "/etc/shadow",
                    "/etc/sudoers",
                    "/etc/ssh/*",
                    "~/.ssh/*",
                    "~/.gnupg/*",
                    "~/.aws/credentials",
                    "~/.kube/config",
                    "/root/*",
                    "/var/log/auth.log",
                    "/var/log/secure",
                    "*.key",
                    "*.pem",
                    "*.p12",
                    ".env",
                    ".env.*",
                    "**/secrets/*",
                    "**/credentials/*",
                ],
                builtin=True,
            ),
            # Config paths
            MacroDefinition(
                name="CONFIG_PATHS",
                category=MacroCategory.PATHS.value,
                macro_type=MacroType.LIST.value,
                description="Configuration file paths",
                values=[
                    "/etc/*.conf",
                    "/etc/**/*.conf",
                    "~/.config/*",
                    "*.yaml",
                    "*.yml",
                    "*.toml",
                    "*.ini",
                    "config.*",
                    "settings.*",
                ],
                builtin=True,
            ),
            # High risk commands
            MacroDefinition(
                name="HIGH_RISK_COMMANDS",
                category=MacroCategory.COMMANDS.value,
                macro_type=MacroType.LIST.value,
                description="Shell commands that pose high risk",
                values=[
                    "rm -rf",
                    "rm -r /",
                    "mkfs",
                    "dd if=",
                    ":(){ :|:& };:",  # Fork bomb
                    "chmod -R 777",
                    "chown -R",
                    "sudo su",
                    "curl | sh",
                    "wget | sh",
                    "curl | bash",
                    "wget | bash",
                    "> /dev/sda",
                    "shutdown",
                    "reboot",
                    "init 0",
                    "halt",
                    "poweroff",
                    "kill -9 1",
                    "pkill -9",
                    "iptables -F",
                    "ufw disable",
                ],
                builtin=True,
            ),
            # Production hours (9 AM - 6 PM weekdays)
            MacroDefinition(
                name="PRODUCTION_HOURS",
                category=MacroCategory.TIME.value,
                macro_type=MacroType.FUNCTION.value,
                description="Check if current time is within production/business hours",
                function_name="is_production_hours",
                builtin=True,
            ),
            # After hours
            MacroDefinition(
                name="AFTER_HOURS",
                category=MacroCategory.TIME.value,
                macro_type=MacroType.FUNCTION.value,
                description="Check if current time is outside business hours",
                function_name="is_after_hours",
                builtin=True,
            ),
            # Weekend
            MacroDefinition(
                name="WEEKEND",
                category=MacroCategory.TIME.value,
                macro_type=MacroType.FUNCTION.value,
                description="Check if current time is during weekend",
                function_name="is_weekend",
                builtin=True,
            ),
            # PII patterns
            MacroDefinition(
                name="PII_PATTERNS",
                category=MacroCategory.PATTERNS.value,
                macro_type=MacroType.LIST.value,
                description="Patterns that match personally identifiable information",
                values=[
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
                    r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                    r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",  # Phone
                    r"\b(?:\d{4}[-\s]?){3}\d{4}\b",  # Credit card
                    r"\b\d{5}(?:-\d{4})?\b",  # ZIP code
                ],
                builtin=True,
            ),
            # Secret patterns
            MacroDefinition(
                name="SECRET_PATTERNS",
                category=MacroCategory.PATTERNS.value,
                macro_type=MacroType.LIST.value,
                description="Patterns that match API keys and secrets",
                values=[
                    r"AKIA[0-9A-Z]{16}",  # AWS Access Key
                    r"sk_live_[0-9a-zA-Z]{24}",  # Stripe Live Key
                    r"sk_test_[0-9a-zA-Z]{24}",  # Stripe Test Key
                    r"ghp_[0-9a-zA-Z]{36}",  # GitHub Personal Access Token
                    r"gho_[0-9a-zA-Z]{36}",  # GitHub OAuth Token
                    r"xox[baprs]-[0-9a-zA-Z-]{10,}",  # Slack Token
                    r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",  # Private Key
                ],
                builtin=True,
            ),
            # Restricted URLs
            MacroDefinition(
                name="RESTRICTED_URLS",
                category=MacroCategory.URLS.value,
                macro_type=MacroType.LIST.value,
                description="URLs that should not be accessed",
                values=[
                    "*.internal.*",
                    "localhost:*",
                    "127.0.0.1:*",
                    "0.0.0.0:*",
                    "*.corp.*",
                    "metadata.google.internal",
                    "169.254.169.254",  # AWS metadata
                ],
                builtin=True,
            ),
            # Safe file extensions
            MacroDefinition(
                name="SAFE_EXTENSIONS",
                category=MacroCategory.PATHS.value,
                macro_type=MacroType.LIST.value,
                description="File extensions considered safe for read/write",
                values=[
                    ".txt",
                    ".md",
                    ".json",
                    ".yaml",
                    ".yml",
                    ".log",
                    ".csv",
                    ".xml",
                ],
                builtin=True,
            ),
            # Code file extensions
            MacroDefinition(
                name="CODE_EXTENSIONS",
                category=MacroCategory.PATHS.value,
                macro_type=MacroType.LIST.value,
                description="Source code file extensions",
                values=[
                    ".py",
                    ".js",
                    ".ts",
                    ".jsx",
                    ".tsx",
                    ".java",
                    ".go",
                    ".rs",
                    ".c",
                    ".cpp",
                    ".h",
                    ".hpp",
                    ".rb",
                    ".php",
                    ".swift",
                    ".kt",
                    ".scala",
                    ".cs",
                ],
                builtin=True,
            ),
        ]

        for macro in builtins:
            self._macros[macro.name] = macro

    def _register_builtin_functions(self):
        """Register built-in macro functions."""
        self._custom_functions["is_production_hours"] = self._is_production_hours
        self._custom_functions["is_after_hours"] = self._is_after_hours
        self._custom_functions["is_weekend"] = self._is_weekend
        self._custom_functions["is_weekday"] = self._is_weekday

    def _is_production_hours(self, context: Dict[str, Any]) -> bool:
        """Check if current time is within production hours (9 AM - 6 PM weekdays)."""
        now = datetime.now()

        # Check weekday (Monday = 0, Sunday = 6)
        if now.weekday() >= 5:  # Saturday or Sunday
            return False

        # Check time (9 AM - 6 PM)
        if now.hour < 9 or now.hour >= 18:
            return False

        return True

    def _is_after_hours(self, context: Dict[str, Any]) -> bool:
        """Check if current time is outside business hours."""
        return not self._is_production_hours(context)

    def _is_weekend(self, context: Dict[str, Any]) -> bool:
        """Check if current time is during weekend."""
        now = datetime.now()
        return now.weekday() >= 5

    def _is_weekday(self, context: Dict[str, Any]) -> bool:
        """Check if current time is a weekday."""
        now = datetime.now()
        return now.weekday() < 5

    async def define_macro(
        self,
        name: str,
        category: MacroCategory,
        macro_type: MacroType,
        description: str,
        values: Optional[List[str]] = None,
        pattern: Optional[str] = None,
        function_name: Optional[str] = None,
    ) -> MacroDefinition:
        """
        Define a new custom macro.

        Args:
            name: Macro name (will be uppercase)
            category: Category for organization
            macro_type: Type of macro (list, pattern, function)
            description: Human-readable description
            values: List of values (for LIST type)
            pattern: Regex pattern (for PATTERN type)
            function_name: Function name (for FUNCTION type)

        Returns:
            The created MacroDefinition
        """
        name = name.upper()

        if name in self._macros and self._macros[name].builtin:
            raise ValueError(f"Cannot override built-in macro: {name}")

        macro = MacroDefinition(
            name=name,
            category=category.value,
            macro_type=macro_type.value,
            description=description,
            values=values or [],
            pattern=pattern,
            function_name=function_name,
            builtin=False,
        )

        async with self._macros_lock:
            self._macros[name] = macro

        await self._save_custom_macros()

        logger.info(f"Defined macro: ${name}")

        return macro

    async def delete_macro(self, name: str) -> bool:
        """Delete a custom macro."""
        name = name.upper()

        async with self._macros_lock:
            if name not in self._macros:
                return False

            if self._macros[name].builtin:
                raise ValueError(f"Cannot delete built-in macro: {name}")

            del self._macros[name]

        await self._save_custom_macros()

        logger.info(f"Deleted macro: ${name}")

        return True

    async def add_values(self, name: str, values: List[str]) -> MacroDefinition:
        """Add values to a list macro."""
        name = name.upper()

        async with self._macros_lock:
            if name not in self._macros:
                raise ValueError(f"Macro not found: {name}")

            macro = self._macros[name]

            if macro.macro_type != MacroType.LIST.value:
                raise ValueError(f"Macro {name} is not a list type")

            for value in values:
                if value not in macro.values:
                    macro.values.append(value)

            macro.updated_at = datetime.now(timezone.utc).isoformat()

        if not macro.builtin:
            await self._save_custom_macros()

        return macro

    async def remove_values(self, name: str, values: List[str]) -> MacroDefinition:
        """Remove values from a list macro."""
        name = name.upper()

        async with self._macros_lock:
            if name not in self._macros:
                raise ValueError(f"Macro not found: {name}")

            macro = self._macros[name]

            if macro.macro_type != MacroType.LIST.value:
                raise ValueError(f"Macro {name} is not a list type")

            macro.values = [v for v in macro.values if v not in values]
            macro.updated_at = datetime.now(timezone.utc).isoformat()

        if not macro.builtin:
            await self._save_custom_macros()

        return macro

    def get_macro(self, name: str) -> Optional[MacroDefinition]:
        """Get a macro by name."""
        name = name.upper().lstrip("$")
        return self._macros.get(name)

    def list_macros(
        self,
        category: Optional[MacroCategory] = None,
        builtin_only: bool = False,
        custom_only: bool = False,
    ) -> List[MacroDefinition]:
        """List all macros, optionally filtered."""
        macros = list(self._macros.values())

        if category:
            macros = [m for m in macros if m.category == category.value]

        if builtin_only:
            macros = [m for m in macros if m.builtin]
        elif custom_only:
            macros = [m for m in macros if not m.builtin]

        return macros

    async def evaluate(
        self,
        macro_name: str,
        value: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> MacroEvaluationResult:
        """
        Evaluate a value against a macro.

        Args:
            macro_name: Name of the macro (with or without $)
            value: Value to check against the macro
            context: Additional context for function macros

        Returns:
            MacroEvaluationResult with match status
        """
        import time

        start = time.time()

        name = macro_name.upper().lstrip("$")

        if name not in self._macros:
            return MacroEvaluationResult(
                macro_name=name,
                matched=False,
                error=f"Macro not found: {name}",
            )

        macro = self._macros[name]

        try:
            matched = False
            matched_value = None

            if macro.macro_type == MacroType.LIST.value:
                matched, matched_value = self._evaluate_list(macro, value)

            elif macro.macro_type == MacroType.PATTERN.value:
                matched, matched_value = self._evaluate_pattern(macro, value)

            elif macro.macro_type == MacroType.FUNCTION.value:
                matched = self._evaluate_function(macro, context or {})
                matched_value = str(matched) if matched else None

            # Update usage stats
            macro.usage_count += 1
            macro.last_used = datetime.now(timezone.utc).isoformat()

            elapsed = (time.time() - start) * 1000

            return MacroEvaluationResult(
                macro_name=name,
                matched=matched,
                value_matched=matched_value,
                evaluation_time_ms=elapsed,
            )

        except Exception as e:
            logger.error(f"Error evaluating macro {name}: {e}")
            return MacroEvaluationResult(
                macro_name=name,
                matched=False,
                error=str(e),
            )

    def _evaluate_list(
        self,
        macro: MacroDefinition,
        value: str,
    ) -> tuple:
        """Evaluate a list macro."""
        import fnmatch

        for pattern in macro.values:
            # Check exact match
            if value == pattern:
                return True, pattern

            # Check glob pattern match
            if fnmatch.fnmatch(value, pattern):
                return True, pattern

            # Check if value contains pattern
            if pattern in value:
                return True, pattern

        return False, None

    def _evaluate_pattern(
        self,
        macro: MacroDefinition,
        value: str,
    ) -> tuple:
        """Evaluate a pattern macro."""
        if not macro.pattern:
            return False, None

        match = re.search(macro.pattern, value)
        if match:
            return True, match.group()

        return False, None

    def _evaluate_function(
        self,
        macro: MacroDefinition,
        context: Dict[str, Any],
    ) -> bool:
        """Evaluate a function macro."""
        if not macro.function_name:
            return False

        func = self._custom_functions.get(macro.function_name)
        if not func:
            logger.warning(f"Function not found: {macro.function_name}")
            return False

        return func(context)

    def expand_policy(self, policy_text: str) -> str:
        """
        Expand all macro references in a policy.

        Replaces $MACRO_NAME with the actual values.
        For list macros, expands to a YAML/JSON array.
        """

        def replace_macro(match):
            macro_name = match.group(1)
            macro = self.get_macro(macro_name)

            if not macro:
                return match.group(0)  # Keep original if not found

            if macro.macro_type == MacroType.LIST.value:
                # Return as YAML list format
                return json.dumps(macro.values)
            elif macro.macro_type == MacroType.PATTERN.value:
                return macro.pattern or ""
            else:
                # Functions can't be directly expanded
                return match.group(0)

        # Find all $MACRO_NAME references
        expanded = re.sub(r"\$([A-Z_]+)", replace_macro, policy_text)

        return expanded

    def register_function(self, name: str, func: Callable[[Dict[str, Any]], bool]):
        """Register a custom function for use in function macros."""
        self._custom_functions[name] = func
        logger.info(f"Registered macro function: {name}")

    async def _load_custom_macros(self):
        """Load custom macros from disk."""
        macros_file = self.data_dir / "custom_macros.json"

        if macros_file.exists():
            try:
                async with aiofiles.open(macros_file, "r") as f:
                    content = await f.read()

                data = json.loads(content)

                for macro_data in data.get("macros", []):
                    macro = MacroDefinition(**macro_data)
                    if not macro.builtin:  # Don't override builtins
                        self._macros[macro.name] = macro

                logger.info(f"Loaded {len(data.get('macros', []))} custom macros")

            except Exception as e:
                logger.error(f"Error loading custom macros: {e}")

    async def _save_custom_macros(self):
        """Save custom macros to disk."""
        macros_file = self.data_dir / "custom_macros.json"

        try:
            from dataclasses import asdict

            custom_macros = [asdict(m) for m in self._macros.values() if not m.builtin]

            data = {
                "macros": custom_macros,
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }

            async with aiofiles.open(macros_file, "w") as f:
                await f.write(json.dumps(data, indent=2))

        except Exception as e:
            logger.error(f"Error saving custom macros: {e}")


# =============================================================================
# Singleton instance
# =============================================================================

_macro_engine: Optional[PolicyMacroEngine] = None


def get_macro_engine() -> PolicyMacroEngine:
    """Get the singleton macro engine instance."""
    global _macro_engine
    if _macro_engine is None:
        _macro_engine = PolicyMacroEngine()
    return _macro_engine


# =============================================================================
# FastAPI Routes
# =============================================================================


def create_macro_routes():
    """Create FastAPI routes for policy macros."""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
    from typing import Optional, List

    router = APIRouter(prefix="/api/v1/guard/macros", tags=["macros"])

    class DefineMacroRequest(BaseModel):
        name: str
        category: str
        macro_type: str
        description: str
        values: Optional[List[str]] = None
        pattern: Optional[str] = None

    class ModifyValuesRequest(BaseModel):
        values: List[str]

    class EvaluateRequest(BaseModel):
        macro_name: str
        value: str
        context: Optional[dict] = None

    class ExpandRequest(BaseModel):
        policy_text: str

    @router.get("/")
    async def list_macros(
        category: Optional[str] = None,
        builtin_only: bool = False,
        custom_only: bool = False,
    ):
        """List all macros."""
        engine = get_macro_engine()

        cat = MacroCategory(category) if category else None
        macros = engine.list_macros(
            category=cat,
            builtin_only=builtin_only,
            custom_only=custom_only,
        )

        return {
            "macros": [
                {
                    "name": m.name,
                    "category": m.category,
                    "type": m.macro_type,
                    "description": m.description,
                    "builtin": m.builtin,
                    "values_count": len(m.values),
                    "usage_count": m.usage_count,
                }
                for m in macros
            ]
        }

    @router.get("/{name}")
    async def get_macro(name: str):
        """Get a macro by name."""
        engine = get_macro_engine()
        macro = engine.get_macro(name)

        if not macro:
            raise HTTPException(404, f"Macro not found: {name}")

        return {
            "name": macro.name,
            "category": macro.category,
            "type": macro.macro_type,
            "description": macro.description,
            "builtin": macro.builtin,
            "values": macro.values,
            "pattern": macro.pattern,
            "usage_count": macro.usage_count,
            "last_used": macro.last_used,
        }

    @router.post("/")
    async def define_macro(request: DefineMacroRequest):
        """Define a new custom macro."""
        engine = get_macro_engine()

        try:
            category = MacroCategory(request.category)
            macro_type = MacroType(request.macro_type)
        except ValueError as e:
            raise HTTPException(400, str(e))

        try:
            macro = await engine.define_macro(
                name=request.name,
                category=category,
                macro_type=macro_type,
                description=request.description,
                values=request.values,
                pattern=request.pattern,
            )
        except ValueError as e:
            raise HTTPException(400, str(e))

        return {"name": macro.name, "created": True}

    @router.delete("/{name}")
    async def delete_macro(name: str):
        """Delete a custom macro."""
        engine = get_macro_engine()

        try:
            success = await engine.delete_macro(name)
        except ValueError as e:
            raise HTTPException(400, str(e))

        if not success:
            raise HTTPException(404, f"Macro not found: {name}")

        return {"name": name, "deleted": True}

    @router.post("/{name}/values")
    async def add_values(name: str, request: ModifyValuesRequest):
        """Add values to a list macro."""
        engine = get_macro_engine()

        try:
            macro = await engine.add_values(name, request.values)
        except ValueError as e:
            raise HTTPException(400, str(e))

        return {"name": macro.name, "values_count": len(macro.values)}

    @router.delete("/{name}/values")
    async def remove_values(name: str, request: ModifyValuesRequest):
        """Remove values from a list macro."""
        engine = get_macro_engine()

        try:
            macro = await engine.remove_values(name, request.values)
        except ValueError as e:
            raise HTTPException(400, str(e))

        return {"name": macro.name, "values_count": len(macro.values)}

    @router.post("/evaluate")
    async def evaluate_macro(request: EvaluateRequest):
        """Evaluate a value against a macro."""
        engine = get_macro_engine()

        result = await engine.evaluate(
            macro_name=request.macro_name,
            value=request.value,
            context=request.context,
        )

        return {
            "macro_name": result.macro_name,
            "matched": result.matched,
            "value_matched": result.value_matched,
            "evaluation_time_ms": result.evaluation_time_ms,
            "error": result.error,
        }

    @router.post("/expand")
    async def expand_policy(request: ExpandRequest):
        """Expand macro references in policy text."""
        engine = get_macro_engine()
        expanded = engine.expand_policy(request.policy_text)
        return {"original": request.policy_text, "expanded": expanded}

    return router
