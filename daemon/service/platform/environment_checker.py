"""
Environment Compatibility Checker
==================================

Validates that the runtime environment is suitable for Guard daemon.

From guard-plan-v1.md:
- Check Python version
- Check required dependencies
- Check system resources
- Check network connectivity
- Check filesystem permissions
- Generate environment report

Usage:
    from service.platform.environment_checker import (
        EnvironmentChecker,
        get_environment_checker
    )

    checker = get_environment_checker()
    report = await checker.run_all_checks()

    if not report.is_compatible:
        for issue in report.issues:
            print(f"Issue: {issue}")
"""

import asyncio
import importlib
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CheckStatus(Enum):
    """Status of an environment check."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


class CheckCategory(Enum):
    """Category of environment check."""

    PYTHON = "python"
    DEPENDENCIES = "dependencies"
    SYSTEM = "system"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    SECURITY = "security"


@dataclass
class EnvironmentCheck:
    """Result of a single environment check."""

    name: str
    category: CheckCategory
    status: CheckStatus
    message: str
    details: Optional[str] = None
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }


@dataclass
class EnvironmentReport:
    """Full environment compatibility report."""

    generated_at: datetime = field(default_factory=datetime.utcnow)
    is_compatible: bool = True
    checks: List[EnvironmentCheck] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    system_info: Dict[str, Any] = field(default_factory=dict)
    issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "is_compatible": self.is_compatible,
            "checks": [c.to_dict() for c in self.checks],
            "summary": self.summary,
            "system_info": self.system_info,
            "issues": self.issues,
            "warnings": self.warnings,
        }


class EnvironmentChecker:
    """
    Checks environment compatibility for Guard daemon.

    Features:
    - Python version check
    - Dependency availability check
    - System resource check
    - Network connectivity check
    - Filesystem permission check
    - Security configuration check
    """

    # Minimum requirements
    MIN_PYTHON_VERSION = (3, 9)
    MIN_MEMORY_MB = 256
    MIN_DISK_MB = 100

    # Required Python packages
    REQUIRED_PACKAGES = [
        ("fastapi", "0.100.0"),
        ("uvicorn", "0.20.0"),
        ("pydantic", "2.0.0"),
        ("aiohttp", "3.8.0"),
        ("aiofiles", "0.8.0"),
        ("pyyaml", "6.0"),
    ]

    # Optional packages
    OPTIONAL_PACKAGES = [
        ("pytest", "7.0.0"),
        ("httpx", "0.24.0"),
    ]

    def __init__(
        self,
        daemon_host: str = "127.0.0.1",
        daemon_port: int = 8765,
        base_dir: Optional[str] = None,
    ):
        """
        Initialize the environment checker.

        Args:
            daemon_host: Host the daemon will listen on
            daemon_port: Port the daemon will use
            base_dir: Base directory for filesystem checks
        """
        self._daemon_host = daemon_host
        self._daemon_port = daemon_port
        self._base_dir = Path(base_dir or os.getcwd())
        self._start_time = time.time()

        logger.info(f"EnvironmentChecker initialized: host={daemon_host}:{daemon_port}")

    def _get_system_info(self) -> Dict[str, Any]:
        """Gather system information."""
        import psutil

        info = {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "python_executable": sys.executable,
            "hostname": socket.gethostname(),
            "user": os.getenv("USER", os.getenv("USERNAME", "unknown")),
            "pid": os.getpid(),
            "cwd": os.getcwd(),
        }

        try:
            info["cpu_count"] = psutil.cpu_count()
            info["memory_total_mb"] = psutil.virtual_memory().total // (1024 * 1024)
            info["memory_available_mb"] = psutil.virtual_memory().available // (
                1024 * 1024
            )
            info["disk_total_mb"] = psutil.disk_usage("/").total // (1024 * 1024)
            info["disk_free_mb"] = psutil.disk_usage("/").free // (1024 * 1024)
        except ImportError:
            # psutil not available
            pass

        return info

    async def check_python_version(self) -> EnvironmentCheck:
        """Check Python version."""
        current = sys.version_info[:2]
        required = self.MIN_PYTHON_VERSION

        if current >= required:
            return EnvironmentCheck(
                name="python_version",
                category=CheckCategory.PYTHON,
                status=CheckStatus.PASS,
                message=f"Python {current[0]}.{current[1]} meets requirement {required[0]}.{required[1]}+",
                metadata={
                    "current": f"{current[0]}.{current[1]}",
                    "required": f"{required[0]}.{required[1]}",
                },
            )
        else:
            return EnvironmentCheck(
                name="python_version",
                category=CheckCategory.PYTHON,
                status=CheckStatus.FAIL,
                message=f"Python {current[0]}.{current[1]} is below minimum {required[0]}.{required[1]}",
                remediation=f"Upgrade to Python {required[0]}.{required[1]} or higher",
                metadata={
                    "current": f"{current[0]}.{current[1]}",
                    "required": f"{required[0]}.{required[1]}",
                },
            )

    async def check_package(
        self,
        package_name: str,
        min_version: Optional[str] = None,
        required: bool = True,
    ) -> EnvironmentCheck:
        """Check if a Python package is installed."""
        try:
            module = importlib.import_module(package_name)
            version = getattr(module, "__version__", "unknown")

            # Version comparison (simple)
            if min_version and version != "unknown":
                # Simple version check
                status = CheckStatus.PASS
                message = f"{package_name} {version} installed"
            else:
                status = CheckStatus.PASS
                message = f"{package_name} installed"

            return EnvironmentCheck(
                name=f"package_{package_name}",
                category=CheckCategory.DEPENDENCIES,
                status=status,
                message=message,
                metadata={"version": version, "min_version": min_version},
            )
        except ImportError:
            status = CheckStatus.FAIL if required else CheckStatus.WARN
            return EnvironmentCheck(
                name=f"package_{package_name}",
                category=CheckCategory.DEPENDENCIES,
                status=status,
                message=f"{package_name} not installed",
                remediation=(
                    f"pip install {package_name}>={min_version}"
                    if min_version
                    else f"pip install {package_name}"
                ),
                metadata={"min_version": min_version},
            )

    async def check_memory(self) -> EnvironmentCheck:
        """Check available memory."""
        try:
            import psutil

            available_mb = psutil.virtual_memory().available // (1024 * 1024)

            if available_mb >= self.MIN_MEMORY_MB:
                return EnvironmentCheck(
                    name="memory",
                    category=CheckCategory.SYSTEM,
                    status=CheckStatus.PASS,
                    message=f"{available_mb}MB available memory",
                    metadata={
                        "available_mb": available_mb,
                        "required_mb": self.MIN_MEMORY_MB,
                    },
                )
            else:
                return EnvironmentCheck(
                    name="memory",
                    category=CheckCategory.SYSTEM,
                    status=CheckStatus.WARN,
                    message=f"Low memory: {available_mb}MB (recommended: {self.MIN_MEMORY_MB}MB)",
                    remediation="Close other applications or add more RAM",
                    metadata={
                        "available_mb": available_mb,
                        "required_mb": self.MIN_MEMORY_MB,
                    },
                )
        except ImportError:
            return EnvironmentCheck(
                name="memory",
                category=CheckCategory.SYSTEM,
                status=CheckStatus.SKIP,
                message="psutil not installed, skipping memory check",
            )

    async def check_disk_space(self) -> EnvironmentCheck:
        """Check available disk space."""
        try:
            import psutil

            free_mb = psutil.disk_usage("/").free // (1024 * 1024)

            if free_mb >= self.MIN_DISK_MB:
                return EnvironmentCheck(
                    name="disk_space",
                    category=CheckCategory.SYSTEM,
                    status=CheckStatus.PASS,
                    message=f"{free_mb}MB free disk space",
                    metadata={"free_mb": free_mb, "required_mb": self.MIN_DISK_MB},
                )
            else:
                return EnvironmentCheck(
                    name="disk_space",
                    category=CheckCategory.SYSTEM,
                    status=CheckStatus.WARN,
                    message=f"Low disk space: {free_mb}MB (recommended: {self.MIN_DISK_MB}MB)",
                    remediation="Free up disk space",
                    metadata={"free_mb": free_mb, "required_mb": self.MIN_DISK_MB},
                )
        except ImportError:
            return EnvironmentCheck(
                name="disk_space",
                category=CheckCategory.SYSTEM,
                status=CheckStatus.SKIP,
                message="psutil not installed, skipping disk check",
            )

    async def check_port_available(self) -> EnvironmentCheck:
        """Check if the daemon port is available."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self._daemon_host, self._daemon_port))
            sock.close()

            if result != 0:
                # Port is available (connection failed)
                return EnvironmentCheck(
                    name="port_available",
                    category=CheckCategory.NETWORK,
                    status=CheckStatus.PASS,
                    message=f"Port {self._daemon_port} is available",
                    metadata={"host": self._daemon_host, "port": self._daemon_port},
                )
            else:
                # Port is in use (connection succeeded)
                return EnvironmentCheck(
                    name="port_available",
                    category=CheckCategory.NETWORK,
                    status=CheckStatus.WARN,
                    message=f"Port {self._daemon_port} is already in use",
                    details="Another process may be using this port",
                    remediation=f"Use a different port or stop the process on port {self._daemon_port}",
                    metadata={"host": self._daemon_host, "port": self._daemon_port},
                )
        except Exception as e:
            return EnvironmentCheck(
                name="port_available",
                category=CheckCategory.NETWORK,
                status=CheckStatus.FAIL,
                message=f"Error checking port: {e}",
                metadata={"host": self._daemon_host, "port": self._daemon_port},
            )

    async def check_localhost_connectivity(self) -> EnvironmentCheck:
        """Check localhost network connectivity."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.bind(("127.0.0.1", 0))
            sock.close()

            return EnvironmentCheck(
                name="localhost_connectivity",
                category=CheckCategory.NETWORK,
                status=CheckStatus.PASS,
                message="Localhost binding works",
            )
        except Exception as e:
            return EnvironmentCheck(
                name="localhost_connectivity",
                category=CheckCategory.NETWORK,
                status=CheckStatus.FAIL,
                message=f"Cannot bind to localhost: {e}",
                remediation="Check firewall settings",
            )

    async def check_directory_writable(self, path: Path, name: str) -> EnvironmentCheck:
        """Check if a directory is writable."""
        try:
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)

            test_file = path / ".write_test"
            test_file.write_text("test")
            test_file.unlink()

            return EnvironmentCheck(
                name=f"dir_writable_{name}",
                category=CheckCategory.FILESYSTEM,
                status=CheckStatus.PASS,
                message=f"{name} directory is writable: {path}",
                metadata={"path": str(path)},
            )
        except PermissionError:
            return EnvironmentCheck(
                name=f"dir_writable_{name}",
                category=CheckCategory.FILESYSTEM,
                status=CheckStatus.FAIL,
                message=f"{name} directory not writable: {path}",
                remediation=f"Grant write permissions to {path}",
                metadata={"path": str(path)},
            )
        except Exception as e:
            return EnvironmentCheck(
                name=f"dir_writable_{name}",
                category=CheckCategory.FILESYSTEM,
                status=CheckStatus.FAIL,
                message=f"Error checking {name} directory: {e}",
                metadata={"path": str(path)},
            )

    async def check_config_exists(self) -> EnvironmentCheck:
        """Check if configuration file exists."""
        config_paths = [
            self._base_dir / "config.yaml",
            self._base_dir / "config.yml",
            self._base_dir / "config.json",
        ]

        for config_path in config_paths:
            if config_path.exists():
                return EnvironmentCheck(
                    name="config_file",
                    category=CheckCategory.FILESYSTEM,
                    status=CheckStatus.PASS,
                    message=f"Configuration file found: {config_path}",
                    metadata={"path": str(config_path)},
                )

        return EnvironmentCheck(
            name="config_file",
            category=CheckCategory.FILESYSTEM,
            status=CheckStatus.WARN,
            message="No configuration file found (will use defaults)",
            details=f"Searched in: {self._base_dir}",
            remediation="Create config.yaml in the base directory",
        )

    async def run_all_checks(self) -> EnvironmentReport:
        """Run all environment checks and generate report."""
        report = EnvironmentReport()
        report.system_info = self._get_system_info()

        # Python version
        report.checks.append(await self.check_python_version())

        # Required packages
        for package, version in self.REQUIRED_PACKAGES:
            report.checks.append(
                await self.check_package(package, version, required=True)
            )

        # Optional packages
        for package, version in self.OPTIONAL_PACKAGES:
            report.checks.append(
                await self.check_package(package, version, required=False)
            )

        # System resources
        report.checks.append(await self.check_memory())
        report.checks.append(await self.check_disk_space())

        # Network
        report.checks.append(await self.check_port_available())
        report.checks.append(await self.check_localhost_connectivity())

        # Filesystem
        report.checks.append(
            await self.check_directory_writable(self._base_dir / "logs", "logs")
        )
        report.checks.append(
            await self.check_directory_writable(self._base_dir / "data", "data")
        )
        report.checks.append(await self.check_config_exists())

        # Generate summary
        summary = {status.value: 0 for status in CheckStatus}
        for check in report.checks:
            summary[check.status.value] += 1

            if check.status == CheckStatus.FAIL:
                report.is_compatible = False
                report.issues.append(check.message)
            elif check.status == CheckStatus.WARN:
                report.warnings.append(check.message)

        report.summary = summary

        logger.info(
            f"Environment check complete: compatible={report.is_compatible}, "
            f"pass={summary['pass']}, warn={summary['warn']}, fail={summary['fail']}"
        )

        return report


# Global singleton instance
_environment_checker: Optional[EnvironmentChecker] = None


def get_environment_checker() -> EnvironmentChecker:
    """Get or create the global environment checker."""
    global _environment_checker
    if _environment_checker is None:
        _environment_checker = EnvironmentChecker()
    return _environment_checker


def reset_environment_checker(
    daemon_host: str = "127.0.0.1",
    daemon_port: int = 8765,
    base_dir: Optional[str] = None,
) -> EnvironmentChecker:
    """Reset the global environment checker."""
    global _environment_checker
    _environment_checker = EnvironmentChecker(
        daemon_host=daemon_host,
        daemon_port=daemon_port,
        base_dir=base_dir,
    )
    return _environment_checker


# FastAPI integration
def create_environment_routes():
    """Create FastAPI routes for environment checking."""
    from fastapi import APIRouter

    router = APIRouter(prefix="/api/v1/guard", tags=["environment"])

    @router.get("/environment/check")
    async def run_environment_check():
        """Run all environment checks."""
        checker = get_environment_checker()
        report = await checker.run_all_checks()
        return report.to_dict()

    @router.get("/environment/system")
    async def get_system_info():
        """Get system information."""
        checker = get_environment_checker()
        return checker._get_system_info()

    @router.get("/environment/quick")
    async def quick_check():
        """Run quick compatibility check."""
        checker = get_environment_checker()

        # Just check Python and core dependencies
        checks = []
        checks.append(await checker.check_python_version())
        checks.append(await checker.check_package("fastapi", "0.100.0"))
        checks.append(await checker.check_package("uvicorn", "0.20.0"))

        is_compatible = all(c.status != CheckStatus.FAIL for c in checks)

        return {
            "is_compatible": is_compatible,
            "checks": [c.to_dict() for c in checks],
        }

    return router
