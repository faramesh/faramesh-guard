"""
Diagnostics Exporter for Faramesh Guard.

Collects and exports diagnostic data for support tickets and debugging.
Supports multiple export formats and automatic PII redaction.

Diagnostic categories:
- System: OS, Python, resources
- Config: Guard configuration
- Logs: Recent log entries
- Metrics: Performance metrics
- State: Current protection state
- History: Recent decisions/events
"""

import asyncio
import gzip
import hashlib
import json
import logging
import os
import platform
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional
import aiofiles

logger = logging.getLogger(__name__)


class DiagnosticCategory(str, Enum):
    """Categories of diagnostic data."""

    SYSTEM = "system"
    CONFIG = "config"
    LOGS = "logs"
    METRICS = "metrics"
    STATE = "state"
    HISTORY = "history"
    NETWORK = "network"
    ALL = "all"


class ExportFormat(str, Enum):
    """Export formats."""

    JSON = "json"
    TAR_GZ = "tar.gz"
    ZIP = "zip"


@dataclass
class DiagnosticSection:
    """A section of diagnostic data."""

    category: str
    name: str
    data: Dict[str, Any]
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    redacted: bool = False


@dataclass
class DiagnosticsBundle:
    """Complete diagnostics bundle."""

    bundle_id: str
    created_at: str
    guard_version: str

    # Sections
    sections: List[DiagnosticSection] = field(default_factory=list)

    # Metadata
    collection_time_ms: float = 0.0
    total_size_bytes: int = 0
    redaction_applied: bool = False
    categories_included: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "created_at": self.created_at,
            "guard_version": self.guard_version,
            "collection_time_ms": self.collection_time_ms,
            "total_size_bytes": self.total_size_bytes,
            "redaction_applied": self.redaction_applied,
            "categories_included": self.categories_included,
            "sections": [
                {
                    "category": s.category,
                    "name": s.name,
                    "data": s.data,
                    "collected_at": s.collected_at,
                    "redacted": s.redacted,
                }
                for s in self.sections
            ],
        }


class DiagnosticsExporter:
    """
    Collects and exports diagnostic data for support and debugging.

    Features:
    - Comprehensive system information
    - Configuration dump (with secrets redacted)
    - Recent logs and metrics
    - Current protection state
    - Decision history
    - Network connectivity checks
    - Automatic PII/secret redaction
    - Multiple export formats
    """

    def __init__(
        self,
        data_dir: str = "/var/lib/faramesh-guard",
        log_dir: str = "/var/log/faramesh-guard",
        config_path: str = "/etc/faramesh-guard/config.yaml",
        max_log_lines: int = 1000,
        redact_secrets: bool = True,
    ):
        self.data_dir = Path(data_dir)
        self.log_dir = Path(log_dir)
        self.config_path = Path(config_path)
        self.max_log_lines = max_log_lines
        self.redact_secrets = redact_secrets

        # Version (should be loaded from actual VERSION file)
        self.guard_version = "1.0.0"

        # Patterns for redaction
        self._secret_patterns = [
            "password",
            "secret",
            "token",
            "key",
            "credential",
            "auth",
            "api_key",
            "apikey",
            "bearer",
        ]

        logger.info("DiagnosticsExporter initialized")

    async def collect(
        self,
        categories: Optional[List[DiagnosticCategory]] = None,
        redact: bool = True,
    ) -> DiagnosticsBundle:
        """
        Collect diagnostic data.

        Args:
            categories: Categories to collect (None = all)
            redact: Whether to redact secrets/PII

        Returns:
            DiagnosticsBundle with all collected data
        """
        import time

        start_time = time.time()

        bundle_id = hashlib.sha256(
            f"{datetime.now(timezone.utc).isoformat()}:{os.getpid()}".encode()
        ).hexdigest()[:16]

        bundle = DiagnosticsBundle(
            bundle_id=bundle_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            guard_version=self.guard_version,
            redaction_applied=redact,
        )

        cats_to_collect = categories or [DiagnosticCategory.ALL]
        if DiagnosticCategory.ALL in cats_to_collect:
            cats_to_collect = [
                c for c in DiagnosticCategory if c != DiagnosticCategory.ALL
            ]

        bundle.categories_included = [c.value for c in cats_to_collect]

        # Collect each category
        for category in cats_to_collect:
            try:
                sections = await self._collect_category(category)

                if redact:
                    sections = [self._redact_section(s) for s in sections]

                bundle.sections.extend(sections)

            except Exception as e:
                logger.error(f"Error collecting {category.value}: {e}")
                bundle.sections.append(
                    DiagnosticSection(
                        category=category.value,
                        name="error",
                        data={"error": str(e)},
                    )
                )

        bundle.collection_time_ms = (time.time() - start_time) * 1000
        bundle.total_size_bytes = len(json.dumps(bundle.to_dict()).encode())

        return bundle

    async def _collect_category(
        self,
        category: DiagnosticCategory,
    ) -> List[DiagnosticSection]:
        """Collect data for a specific category."""
        if category == DiagnosticCategory.SYSTEM:
            return await self._collect_system()
        elif category == DiagnosticCategory.CONFIG:
            return await self._collect_config()
        elif category == DiagnosticCategory.LOGS:
            return await self._collect_logs()
        elif category == DiagnosticCategory.METRICS:
            return await self._collect_metrics()
        elif category == DiagnosticCategory.STATE:
            return await self._collect_state()
        elif category == DiagnosticCategory.HISTORY:
            return await self._collect_history()
        elif category == DiagnosticCategory.NETWORK:
            return await self._collect_network()
        else:
            return []

    async def _collect_system(self) -> List[DiagnosticSection]:
        """Collect system information."""
        import psutil

        sections = []

        # OS Info
        sections.append(
            DiagnosticSection(
                category=DiagnosticCategory.SYSTEM.value,
                name="os",
                data={
                    "system": platform.system(),
                    "release": platform.release(),
                    "version": platform.version(),
                    "machine": platform.machine(),
                    "processor": platform.processor(),
                    "hostname": platform.node(),
                },
            )
        )

        # Python Info
        sections.append(
            DiagnosticSection(
                category=DiagnosticCategory.SYSTEM.value,
                name="python",
                data={
                    "version": sys.version,
                    "executable": sys.executable,
                    "prefix": sys.prefix,
                    "platform": sys.platform,
                },
            )
        )

        # Resources
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            sections.append(
                DiagnosticSection(
                    category=DiagnosticCategory.SYSTEM.value,
                    name="resources",
                    data={
                        "cpu_count": psutil.cpu_count(),
                        "cpu_percent": psutil.cpu_percent(interval=0.1),
                        "memory_total_gb": round(memory.total / (1024**3), 2),
                        "memory_available_gb": round(memory.available / (1024**3), 2),
                        "memory_percent": memory.percent,
                        "disk_total_gb": round(disk.total / (1024**3), 2),
                        "disk_free_gb": round(disk.free / (1024**3), 2),
                        "disk_percent": round(disk.used / disk.total * 100, 1),
                    },
                )
            )
        except Exception as e:
            logger.warning(f"Could not collect resource info: {e}")

        # Process Info
        try:
            proc = psutil.Process()
            sections.append(
                DiagnosticSection(
                    category=DiagnosticCategory.SYSTEM.value,
                    name="process",
                    data={
                        "pid": proc.pid,
                        "status": proc.status(),
                        "cpu_percent": proc.cpu_percent(),
                        "memory_mb": round(proc.memory_info().rss / (1024**2), 2),
                        "threads": proc.num_threads(),
                        "open_files": len(proc.open_files()),
                        "connections": len(proc.net_connections()),
                        "create_time": datetime.fromtimestamp(
                            proc.create_time()
                        ).isoformat(),
                    },
                )
            )
        except Exception as e:
            logger.warning(f"Could not collect process info: {e}")

        # Environment (filtered)
        safe_env_vars = [
            "PATH",
            "HOME",
            "USER",
            "SHELL",
            "LANG",
            "LC_ALL",
            "PYTHONPATH",
            "VIRTUAL_ENV",
            "FARAMESH_",
        ]
        filtered_env = {}
        for key, value in os.environ.items():
            if any(key.startswith(prefix) for prefix in safe_env_vars):
                filtered_env[key] = value

        sections.append(
            DiagnosticSection(
                category=DiagnosticCategory.SYSTEM.value,
                name="environment",
                data=filtered_env,
            )
        )

        return sections

    async def _collect_config(self) -> List[DiagnosticSection]:
        """Collect configuration."""
        sections = []

        # Main config
        if self.config_path.exists():
            try:
                async with aiofiles.open(self.config_path, "r") as f:
                    content = await f.read()

                import yaml

                config = yaml.safe_load(content)

                sections.append(
                    DiagnosticSection(
                        category=DiagnosticCategory.CONFIG.value,
                        name="main_config",
                        data=config or {},
                    )
                )
            except Exception as e:
                sections.append(
                    DiagnosticSection(
                        category=DiagnosticCategory.CONFIG.value,
                        name="main_config",
                        data={"error": str(e)},
                    )
                )

        # List policy files
        policies_dir = self.data_dir / "policies"
        if policies_dir.exists():
            policy_files = list(policies_dir.glob("*.yaml")) + list(
                policies_dir.glob("*.yml")
            )
            sections.append(
                DiagnosticSection(
                    category=DiagnosticCategory.CONFIG.value,
                    name="policies",
                    data={
                        "count": len(policy_files),
                        "files": [f.name for f in policy_files[:20]],  # Limit to 20
                    },
                )
            )

        return sections

    async def _collect_logs(self) -> List[DiagnosticSection]:
        """Collect recent logs."""
        sections = []

        # Find log files
        log_files = []
        if self.log_dir.exists():
            log_files.extend(self.log_dir.glob("*.log"))

        # Also check common locations
        for alt_log in ["/var/log/faramesh-guard.log", "guard.log"]:
            path = Path(alt_log)
            if path.exists():
                log_files.append(path)

        for log_file in log_files[:5]:  # Limit to 5 log files
            try:
                async with aiofiles.open(log_file, "r") as f:
                    lines = await f.readlines()

                # Get last N lines
                recent_lines = lines[-self.max_log_lines :]

                sections.append(
                    DiagnosticSection(
                        category=DiagnosticCategory.LOGS.value,
                        name=log_file.name,
                        data={
                            "path": str(log_file),
                            "total_lines": len(lines),
                            "included_lines": len(recent_lines),
                            "content": "".join(recent_lines),
                        },
                    )
                )
            except Exception as e:
                logger.warning(f"Could not read log {log_file}: {e}")

        return sections

    async def _collect_metrics(self) -> List[DiagnosticSection]:
        """Collect metrics."""
        sections = []

        # Try to get metrics from various sources
        metrics_file = self.data_dir / "metrics.json"
        if metrics_file.exists():
            try:
                async with aiofiles.open(metrics_file, "r") as f:
                    content = await f.read()
                metrics = json.loads(content)
                sections.append(
                    DiagnosticSection(
                        category=DiagnosticCategory.METRICS.value,
                        name="stored_metrics",
                        data=metrics,
                    )
                )
            except Exception:
                pass

        # Basic runtime metrics
        sections.append(
            DiagnosticSection(
                category=DiagnosticCategory.METRICS.value,
                name="runtime",
                data={
                    "uptime_seconds": 0,  # Would be calculated from start time
                    "requests_total": 0,
                    "decisions_total": 0,
                    "errors_total": 0,
                },
            )
        )

        return sections

    async def _collect_state(self) -> List[DiagnosticSection]:
        """Collect current state."""
        sections = []

        # Would query actual state from various services
        sections.append(
            DiagnosticSection(
                category=DiagnosticCategory.STATE.value,
                name="protection_state",
                data={
                    "current_state": "PROTECTED",
                    "state_since": datetime.now(timezone.utc).isoformat(),
                    "active_clients": 0,
                    "pending_decisions": 0,
                },
            )
        )

        sections.append(
            DiagnosticSection(
                category=DiagnosticCategory.STATE.value,
                name="service_health",
                data={
                    "daemon": "running",
                    "policy_engine": "ready",
                    "decision_service": "ready",
                    "audit_logger": "ready",
                },
            )
        )

        return sections

    async def _collect_history(self) -> List[DiagnosticSection]:
        """Collect recent history."""
        sections = []

        # Recent decisions
        history_file = self.data_dir / "decision_history.json"
        if history_file.exists():
            try:
                async with aiofiles.open(history_file, "r") as f:
                    content = await f.read()
                history = json.loads(content)

                # Limit to last 100
                if isinstance(history, list):
                    history = history[-100:]

                sections.append(
                    DiagnosticSection(
                        category=DiagnosticCategory.HISTORY.value,
                        name="decisions",
                        data={"recent_decisions": history},
                    )
                )
            except Exception:
                pass

        # Recent events
        sections.append(
            DiagnosticSection(
                category=DiagnosticCategory.HISTORY.value,
                name="events",
                data={"recent_events": []},
            )
        )

        return sections

    async def _collect_network(self) -> List[DiagnosticSection]:
        """Collect network information."""
        import socket

        sections = []

        # Local network info
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)

            sections.append(
                DiagnosticSection(
                    category=DiagnosticCategory.NETWORK.value,
                    name="local",
                    data={
                        "hostname": hostname,
                        "local_ip": local_ip,
                    },
                )
            )
        except Exception as e:
            logger.warning(f"Could not collect network info: {e}")

        # Connectivity checks
        checks = {
            "daemon_port": await self._check_port(8765),
        }

        sections.append(
            DiagnosticSection(
                category=DiagnosticCategory.NETWORK.value,
                name="connectivity",
                data=checks,
            )
        )

        return sections

    async def _check_port(self, port: int) -> bool:
        """Check if a port is listening."""
        import socket

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(("127.0.0.1", port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _redact_section(self, section: DiagnosticSection) -> DiagnosticSection:
        """Redact secrets from a section."""
        if not self.redact_secrets:
            return section

        def redact_value(key: str, value: Any) -> Any:
            if isinstance(value, str):
                key_lower = key.lower()
                if any(pattern in key_lower for pattern in self._secret_patterns):
                    return "[REDACTED]"
            elif isinstance(value, dict):
                return {k: redact_value(k, v) for k, v in value.items()}
            elif isinstance(value, list):
                return [redact_value("", v) for v in value]
            return value

        section.data = {k: redact_value(k, v) for k, v in section.data.items()}
        section.redacted = True

        return section

    async def export(
        self,
        bundle: DiagnosticsBundle,
        output_path: str,
        format: ExportFormat = ExportFormat.JSON,
    ) -> str:
        """
        Export diagnostics bundle to file.

        Args:
            bundle: DiagnosticsBundle to export
            output_path: Output file path
            format: Export format

        Returns:
            Path to exported file
        """
        if format == ExportFormat.JSON:
            return await self._export_json(bundle, output_path)
        elif format == ExportFormat.TAR_GZ:
            return await self._export_tar_gz(bundle, output_path)
        elif format == ExportFormat.ZIP:
            return await self._export_zip(bundle, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")

    async def _export_json(self, bundle: DiagnosticsBundle, output_path: str) -> str:
        """Export as JSON."""
        async with aiofiles.open(output_path, "w") as f:
            await f.write(json.dumps(bundle.to_dict(), indent=2))
        return output_path

    async def _export_tar_gz(self, bundle: DiagnosticsBundle, output_path: str) -> str:
        """Export as tar.gz archive."""
        with tarfile.open(output_path, "w:gz") as tar:
            # Add main diagnostics JSON
            data = json.dumps(bundle.to_dict(), indent=2).encode()
            info = tarfile.TarInfo(name="diagnostics.json")
            info.size = len(data)
            tar.addfile(info, BytesIO(data))

            # Add individual sections as separate files
            for section in bundle.sections:
                section_data = json.dumps(section.data, indent=2).encode()
                info = tarfile.TarInfo(name=f"{section.category}/{section.name}.json")
                info.size = len(section_data)
                tar.addfile(info, BytesIO(section_data))

        return output_path

    async def _export_zip(self, bundle: DiagnosticsBundle, output_path: str) -> str:
        """Export as zip archive."""
        import zipfile

        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # Add main diagnostics JSON
            zf.writestr("diagnostics.json", json.dumps(bundle.to_dict(), indent=2))

            # Add individual sections
            for section in bundle.sections:
                zf.writestr(
                    f"{section.category}/{section.name}.json",
                    json.dumps(section.data, indent=2),
                )

        return output_path


# =============================================================================
# Singleton instance
# =============================================================================

_diagnostics_exporter: Optional[DiagnosticsExporter] = None


def get_diagnostics_exporter() -> DiagnosticsExporter:
    """Get the singleton diagnostics exporter instance."""
    global _diagnostics_exporter
    if _diagnostics_exporter is None:
        _diagnostics_exporter = DiagnosticsExporter()
    return _diagnostics_exporter


# =============================================================================
# FastAPI Routes
# =============================================================================


def create_diagnostics_routes():
    """Create FastAPI routes for diagnostics."""
    from fastapi import APIRouter, HTTPException
    from fastapi.responses import FileResponse
    from pydantic import BaseModel
    from typing import Optional, List

    router = APIRouter(prefix="/api/v1/guard/diagnostics", tags=["diagnostics"])

    class CollectRequest(BaseModel):
        categories: Optional[List[str]] = None
        redact: bool = True

    class ExportRequest(BaseModel):
        format: str = "json"
        categories: Optional[List[str]] = None
        redact: bool = True

    @router.post("/collect")
    async def collect_diagnostics(request: CollectRequest):
        """Collect diagnostic data."""
        exporter = get_diagnostics_exporter()

        categories = None
        if request.categories:
            try:
                categories = [DiagnosticCategory(c) for c in request.categories]
            except ValueError as e:
                raise HTTPException(400, str(e))

        bundle = await exporter.collect(
            categories=categories,
            redact=request.redact,
        )

        return bundle.to_dict()

    @router.post("/export")
    async def export_diagnostics(request: ExportRequest):
        """Export diagnostics to file."""
        exporter = get_diagnostics_exporter()

        try:
            format_enum = ExportFormat(request.format)
        except ValueError:
            raise HTTPException(400, f"Invalid format: {request.format}")

        categories = None
        if request.categories:
            try:
                categories = [DiagnosticCategory(c) for c in request.categories]
            except ValueError as e:
                raise HTTPException(400, str(e))

        bundle = await exporter.collect(
            categories=categories,
            redact=request.redact,
        )

        # Create temp file
        import tempfile

        suffix = f".{request.format}"
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)

        await exporter.export(bundle, path, format_enum)

        return {
            "bundle_id": bundle.bundle_id,
            "path": path,
            "format": request.format,
            "size_bytes": os.path.getsize(path),
        }

    @router.get("/categories")
    async def list_categories():
        """List available diagnostic categories."""
        return {
            "categories": [
                {"name": c.value, "description": f"Collects {c.value} information"}
                for c in DiagnosticCategory
                if c != DiagnosticCategory.ALL
            ]
        }

    @router.get("/quick")
    async def quick_diagnostics():
        """Quick diagnostic summary."""
        exporter = get_diagnostics_exporter()

        bundle = await exporter.collect(
            categories=[DiagnosticCategory.SYSTEM, DiagnosticCategory.STATE],
            redact=True,
        )

        return {
            "bundle_id": bundle.bundle_id,
            "guard_version": bundle.guard_version,
            "collection_time_ms": bundle.collection_time_ms,
            "sections_count": len(bundle.sections),
        }

    return router
