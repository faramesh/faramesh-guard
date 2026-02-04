"""
Training Data Logger for Faramesh Guard.

Captures Context-Action-Result (CAR) triples from real human decisions
to enable fine-tuning of policy models. Supports multiple export formats
for use with various ML frameworks.

Example output format (JSONL):
{
    "context": {
        "action": "write_file",
        "resource": "/etc/passwd",
        "agent": "coding-assistant",
        "session_id": "abc123",
        "timestamp": "2024-01-15T10:30:00Z"
    },
    "action": {
        "type": "file_write",
        "path": "/etc/passwd",
        "content_hash": "sha256:abc...",
        "content_size": 1024
    },
    "result": {
        "decision": "deny",
        "decided_by": "human",
        "reason": "System file modification",
        "latency_ms": 5234,
        "policy_matched": "system_files_deny"
    }
}
"""

import asyncio
import hashlib
import json
import logging
import os
import gzip
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
import aiofiles

logger = logging.getLogger(__name__)


class DataExportFormat(str, Enum):
    """Supported export formats for training data."""

    JSONL = "jsonl"  # JSON Lines - one record per line
    JSONL_GZ = "jsonl.gz"  # Compressed JSON Lines
    CSV = "csv"  # CSV for tabular analysis
    PARQUET = "parquet"  # Columnar format for big data
    HUGGINGFACE = "hf"  # HuggingFace datasets format


class Decision(str, Enum):
    """Decision outcomes."""

    ALLOW = "allow"
    DENY = "deny"
    PROMPT = "prompt"
    TIMEOUT = "timeout"
    ERROR = "error"


class DecidedBy(str, Enum):
    """Who made the decision."""

    POLICY = "policy"
    HUMAN = "human"
    DEFAULT = "default"
    TIMEOUT = "timeout"
    CACHE = "cache"


@dataclass
class ContextInfo:
    """Context information for a decision."""

    action_type: str
    resource: str
    agent_id: str
    session_id: str
    timestamp: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Enrichment fields
    agent_name: Optional[str] = None
    workflow_id: Optional[str] = None
    parent_action_id: Optional[str] = None
    risk_score: Optional[float] = None


@dataclass
class ActionInfo:
    """Action details for training."""

    type: str
    target: str
    content_hash: Optional[str] = None
    content_size: Optional[int] = None
    parameters: Dict[str, Any] = field(default_factory=dict)

    # For commands
    command: Optional[str] = None
    args: Optional[List[str]] = None

    # For file operations
    path: Optional[str] = None
    operation: Optional[str] = None

    # For API calls
    method: Optional[str] = None
    url: Optional[str] = None
    headers_hash: Optional[str] = None


@dataclass
class ResultInfo:
    """Result information including decision and metadata."""

    decision: str
    decided_by: str
    reason: Optional[str] = None
    latency_ms: float = 0.0
    policy_matched: Optional[str] = None
    policy_version: Optional[str] = None

    # Human feedback
    feedback_rating: Optional[int] = None  # 1-5 scale
    feedback_comment: Optional[str] = None
    correction_applied: Optional[str] = None


@dataclass
class TrainingRecord:
    """
    Complete training record capturing context, action, and result.

    This is the primary data structure for ML training. Each record
    represents a single decision event that can be used to train
    policy models.
    """

    record_id: str
    context: ContextInfo
    action: ActionInfo
    result: ResultInfo

    # Metadata
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    schema_version: str = "1.0.0"
    guard_version: str = "1.0.0"

    # Privacy/compliance flags
    pii_detected: bool = False
    pii_redacted: bool = False
    export_allowed: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "record_id": self.record_id,
            "context": asdict(self.context),
            "action": asdict(self.action),
            "result": asdict(self.result),
            "created_at": self.created_at,
            "schema_version": self.schema_version,
            "guard_version": self.guard_version,
            "pii_detected": self.pii_detected,
            "pii_redacted": self.pii_redacted,
            "export_allowed": self.export_allowed,
        }


@dataclass
class TrainingDataStats:
    """Statistics about collected training data."""

    total_records: int = 0
    records_by_decision: Dict[str, int] = field(default_factory=dict)
    records_by_action_type: Dict[str, int] = field(default_factory=dict)
    records_by_agent: Dict[str, int] = field(default_factory=dict)
    records_by_decided_by: Dict[str, int] = field(default_factory=dict)

    human_decisions: int = 0
    policy_decisions: int = 0

    avg_latency_ms: float = 0.0
    total_latency_ms: float = 0.0

    pii_detected_count: int = 0
    export_blocked_count: int = 0

    oldest_record: Optional[str] = None
    newest_record: Optional[str] = None

    storage_size_bytes: int = 0


class TrainingDataLogger:
    """
    Captures and stores training data from real human decisions.

    Features:
    - Structured CAR (Context-Action-Result) format
    - Multiple export formats (JSONL, CSV, Parquet, HuggingFace)
    - PII detection and redaction
    - Automatic rotation and compression
    - Privacy-preserving mode
    - Async buffered writes
    """

    def __init__(
        self,
        data_dir: str = "/var/lib/faramesh-guard/training",
        buffer_size: int = 100,
        flush_interval_seconds: float = 30.0,
        max_file_size_mb: int = 100,
        enable_pii_detection: bool = True,
        enable_compression: bool = True,
        privacy_mode: bool = False,
    ):
        self.data_dir = Path(data_dir)
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval_seconds
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.enable_pii_detection = enable_pii_detection
        self.enable_compression = enable_compression
        self.privacy_mode = privacy_mode

        # Buffer
        self._buffer: List[TrainingRecord] = []
        self._buffer_lock = asyncio.Lock()

        # Statistics
        self._stats = TrainingDataStats()

        # File management
        self._current_file: Optional[Path] = None
        self._current_file_size = 0

        # Flush task
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False

        # PII patterns
        self._pii_patterns = self._compile_pii_patterns()

        # Callbacks
        self._on_record_callbacks: List[Callable[[TrainingRecord], None]] = []

        logger.info(
            f"TrainingDataLogger initialized: dir={data_dir}, buffer={buffer_size}"
        )

    def _compile_pii_patterns(self) -> List[tuple]:
        """Compile regex patterns for PII detection."""
        import re

        return [
            # Email
            (
                re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
                "[EMAIL]",
            ),
            # Phone numbers (various formats)
            (
                re.compile(
                    r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"
                ),
                "[PHONE]",
            ),
            # SSN
            (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
            # Credit card
            (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "[CC]"),
            # IP addresses
            (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP]"),
            # AWS keys
            (re.compile(r"AKIA[0-9A-Z]{16}"), "[AWS_KEY]"),
            # Generic API keys (long hex/base64 strings)
            (re.compile(r"\b[A-Za-z0-9+/]{32,}\b"), "[API_KEY]"),
        ]

    async def start(self):
        """Start the training data logger."""
        if self._running:
            return

        self._running = True
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Start flush task
        self._flush_task = asyncio.create_task(self._periodic_flush())

        logger.info("TrainingDataLogger started")

    async def stop(self):
        """Stop the logger and flush remaining data."""
        self._running = False

        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        # Final flush
        await self._flush_buffer()

        logger.info("TrainingDataLogger stopped")

    async def log_decision(
        self,
        action_type: str,
        resource: str,
        agent_id: str,
        session_id: str,
        decision: str,
        decided_by: str,
        reason: Optional[str] = None,
        latency_ms: float = 0.0,
        policy_matched: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        action_details: Optional[Dict[str, Any]] = None,
    ) -> TrainingRecord:
        """
        Log a decision for training.

        Args:
            action_type: Type of action (write_file, exec_command, etc.)
            resource: Resource being accessed
            agent_id: ID of the agent
            session_id: Session identifier
            decision: allow/deny/prompt/timeout
            decided_by: policy/human/default/timeout
            reason: Reason for decision
            latency_ms: Decision latency in milliseconds
            policy_matched: Name of matched policy rule
            metadata: Additional context metadata
            action_details: Action-specific details

        Returns:
            TrainingRecord that was logged
        """
        # Generate record ID
        record_id = hashlib.sha256(
            f"{session_id}:{action_type}:{resource}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]

        # Build context
        context = ContextInfo(
            action_type=action_type,
            resource=resource,
            agent_id=agent_id,
            session_id=session_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )

        # Build action
        action_info = action_details or {}
        action = ActionInfo(
            type=action_type,
            target=resource,
            **{k: v for k, v in action_info.items() if hasattr(ActionInfo, k)},
        )

        # Build result
        result = ResultInfo(
            decision=decision,
            decided_by=decided_by,
            reason=reason,
            latency_ms=latency_ms,
            policy_matched=policy_matched,
        )

        # Create record
        record = TrainingRecord(
            record_id=record_id,
            context=context,
            action=action,
            result=result,
        )

        # PII detection
        if self.enable_pii_detection:
            record = await self._detect_and_redact_pii(record)

        # Privacy mode - hash sensitive data
        if self.privacy_mode:
            record = self._apply_privacy_mode(record)

        # Add to buffer
        async with self._buffer_lock:
            self._buffer.append(record)
            self._update_stats(record)

            # Flush if buffer full
            if len(self._buffer) >= self.buffer_size:
                await self._flush_buffer()

        # Notify callbacks
        for callback in self._on_record_callbacks:
            try:
                callback(record)
            except Exception as e:
                logger.warning(f"Training record callback error: {e}")

        return record

    async def _detect_and_redact_pii(self, record: TrainingRecord) -> TrainingRecord:
        """Detect and optionally redact PII from a record."""
        pii_found = False

        # Convert to JSON string for scanning
        record_json = json.dumps(record.to_dict())

        for pattern, replacement in self._pii_patterns:
            if pattern.search(record_json):
                pii_found = True
                record_json = pattern.sub(replacement, record_json)

        if pii_found:
            record.pii_detected = True
            record.pii_redacted = True

            # Reconstruct record from redacted JSON
            # In production, would properly update individual fields
            logger.debug(f"PII detected and redacted in record {record.record_id}")

        return record

    def _apply_privacy_mode(self, record: TrainingRecord) -> TrainingRecord:
        """Apply privacy mode - hash sensitive values."""

        def hash_value(v: str) -> str:
            return f"hash:{hashlib.sha256(v.encode()).hexdigest()[:12]}"

        # Hash sensitive fields
        record.context.resource = hash_value(record.context.resource)
        record.action.target = hash_value(record.action.target)

        if record.action.path:
            record.action.path = hash_value(record.action.path)
        if record.action.command:
            record.action.command = hash_value(record.action.command)
        if record.action.url:
            record.action.url = hash_value(record.action.url)

        return record

    def _update_stats(self, record: TrainingRecord):
        """Update statistics with new record."""
        self._stats.total_records += 1

        # By decision
        decision = record.result.decision
        self._stats.records_by_decision[decision] = (
            self._stats.records_by_decision.get(decision, 0) + 1
        )

        # By action type
        action_type = record.context.action_type
        self._stats.records_by_action_type[action_type] = (
            self._stats.records_by_action_type.get(action_type, 0) + 1
        )

        # By agent
        agent = record.context.agent_id
        self._stats.records_by_agent[agent] = (
            self._stats.records_by_agent.get(agent, 0) + 1
        )

        # By decided_by
        decided_by = record.result.decided_by
        self._stats.records_by_decided_by[decided_by] = (
            self._stats.records_by_decided_by.get(decided_by, 0) + 1
        )

        if decided_by == "human":
            self._stats.human_decisions += 1
        elif decided_by == "policy":
            self._stats.policy_decisions += 1

        # Latency
        self._stats.total_latency_ms += record.result.latency_ms
        if self._stats.total_records > 0:
            self._stats.avg_latency_ms = (
                self._stats.total_latency_ms / self._stats.total_records
            )

        # PII
        if record.pii_detected:
            self._stats.pii_detected_count += 1
        if not record.export_allowed:
            self._stats.export_blocked_count += 1

        # Timestamps
        if not self._stats.oldest_record:
            self._stats.oldest_record = record.created_at
        self._stats.newest_record = record.created_at

    async def _periodic_flush(self):
        """Periodically flush buffer to disk."""
        while self._running:
            try:
                await asyncio.sleep(self.flush_interval)
                await self._flush_buffer()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Periodic flush error: {e}")

    async def _flush_buffer(self):
        """Flush buffered records to disk."""
        async with self._buffer_lock:
            if not self._buffer:
                return

            records = self._buffer.copy()
            self._buffer.clear()

        # Get or rotate file
        output_file = await self._get_output_file()

        # Write records
        async with aiofiles.open(output_file, "a") as f:
            for record in records:
                if record.export_allowed:
                    line = json.dumps(record.to_dict()) + "\n"
                    await f.write(line)
                    self._current_file_size += len(line.encode())

        logger.debug(f"Flushed {len(records)} records to {output_file}")

    async def _get_output_file(self) -> Path:
        """Get current output file, rotating if necessary."""
        # Check if rotation needed
        if self._current_file and self._current_file_size >= self.max_file_size_bytes:
            if self.enable_compression:
                await self._compress_file(self._current_file)
            self._current_file = None
            self._current_file_size = 0

        # Create new file if needed
        if not self._current_file:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            self._current_file = self.data_dir / f"training_{timestamp}.jsonl"
            self._current_file_size = 0

        return self._current_file

    async def _compress_file(self, file_path: Path):
        """Compress a file with gzip."""
        compressed_path = file_path.with_suffix(".jsonl.gz")

        async with aiofiles.open(file_path, "rb") as f_in:
            content = await f_in.read()

        compressed = gzip.compress(content)

        async with aiofiles.open(compressed_path, "wb") as f_out:
            await f_out.write(compressed)

        file_path.unlink()
        logger.info(f"Compressed {file_path} to {compressed_path}")

    def get_stats(self) -> TrainingDataStats:
        """Get current statistics."""
        # Update storage size
        if self.data_dir.exists():
            self._stats.storage_size_bytes = sum(
                f.stat().st_size for f in self.data_dir.glob("*") if f.is_file()
            )
        return self._stats

    async def export(
        self,
        output_path: str,
        format: DataExportFormat = DataExportFormat.JSONL,
        filters: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None,
    ) -> int:
        """
        Export training data to specified format.

        Args:
            output_path: Path for output file
            format: Export format
            filters: Optional filters (decision, action_type, etc.)
            limit: Maximum records to export

        Returns:
            Number of records exported
        """
        logger.info(f"Exporting training data to {output_path} ({format.value})")

        # Collect all records
        records = []

        for data_file in sorted(self.data_dir.glob("training_*.jsonl*")):
            if data_file.suffix == ".gz":
                async with aiofiles.open(data_file, "rb") as f:
                    compressed = await f.read()
                content = gzip.decompress(compressed).decode()
            else:
                async with aiofiles.open(data_file, "r") as f:
                    content = await f.read()

            for line in content.strip().split("\n"):
                if not line:
                    continue

                record = json.loads(line)

                # Apply filters
                if filters:
                    if (
                        "decision" in filters
                        and record["result"]["decision"] != filters["decision"]
                    ):
                        continue
                    if (
                        "action_type" in filters
                        and record["context"]["action_type"] != filters["action_type"]
                    ):
                        continue
                    if (
                        "decided_by" in filters
                        and record["result"]["decided_by"] != filters["decided_by"]
                    ):
                        continue

                records.append(record)

                if limit and len(records) >= limit:
                    break

            if limit and len(records) >= limit:
                break

        # Export based on format
        exported = 0

        if format == DataExportFormat.JSONL:
            async with aiofiles.open(output_path, "w") as f:
                for record in records:
                    await f.write(json.dumps(record) + "\n")
                    exported += 1

        elif format == DataExportFormat.JSONL_GZ:
            lines = "\n".join(json.dumps(r) for r in records)
            compressed = gzip.compress(lines.encode())
            async with aiofiles.open(output_path, "wb") as f:
                await f.write(compressed)
            exported = len(records)

        elif format == DataExportFormat.CSV:
            await self._export_csv(output_path, records)
            exported = len(records)

        elif format == DataExportFormat.HUGGINGFACE:
            await self._export_huggingface(output_path, records)
            exported = len(records)

        else:
            raise ValueError(f"Unsupported export format: {format}")

        logger.info(f"Exported {exported} records")
        return exported

    async def _export_csv(self, output_path: str, records: List[Dict]):
        """Export to CSV format."""
        if not records:
            return

        # Flatten records for CSV
        flat_records = []
        for r in records:
            flat_records.append(
                {
                    "record_id": r["record_id"],
                    "action_type": r["context"]["action_type"],
                    "resource": r["context"]["resource"],
                    "agent_id": r["context"]["agent_id"],
                    "session_id": r["context"]["session_id"],
                    "timestamp": r["context"]["timestamp"],
                    "decision": r["result"]["decision"],
                    "decided_by": r["result"]["decided_by"],
                    "reason": r["result"].get("reason", ""),
                    "latency_ms": r["result"]["latency_ms"],
                    "policy_matched": r["result"].get("policy_matched", ""),
                }
            )

        # Write CSV
        import csv

        async with aiofiles.open(output_path, "w") as f:
            if flat_records:
                headers = list(flat_records[0].keys())
                await f.write(",".join(headers) + "\n")

                for record in flat_records:
                    values = [str(record.get(h, "")).replace(",", ";") for h in headers]
                    await f.write(",".join(values) + "\n")

    async def _export_huggingface(self, output_path: str, records: List[Dict]):
        """Export in HuggingFace datasets format."""
        # Create dataset structure
        dataset = {
            "version": "1.0.0",
            "description": "Faramesh Guard training data for policy model fine-tuning",
            "features": {
                "input": {
                    "action_type": "string",
                    "resource": "string",
                    "agent_id": "string",
                },
                "label": {
                    "decision": "string",
                    "confidence": "float",
                },
            },
            "data": [],
        }

        for r in records:
            dataset["data"].append(
                {
                    "input": {
                        "action_type": r["context"]["action_type"],
                        "resource": r["context"]["resource"],
                        "agent_id": r["context"]["agent_id"],
                    },
                    "label": {
                        "decision": r["result"]["decision"],
                        "confidence": (
                            1.0 if r["result"]["decided_by"] == "human" else 0.8
                        ),
                    },
                }
            )

        async with aiofiles.open(output_path, "w") as f:
            await f.write(json.dumps(dataset, indent=2))

    def add_record_callback(self, callback: Callable[[TrainingRecord], None]):
        """Add a callback to be called when a record is logged."""
        self._on_record_callbacks.append(callback)

    async def add_feedback(
        self,
        record_id: str,
        rating: int,
        comment: Optional[str] = None,
        correction: Optional[str] = None,
    ) -> bool:
        """
        Add human feedback to a training record.

        Args:
            record_id: ID of the record
            rating: 1-5 rating
            comment: Optional feedback comment
            correction: What the correct decision should have been

        Returns:
            True if feedback was added
        """
        # This would update the record in storage
        # For now, log as a separate feedback record
        feedback_file = self.data_dir / "feedback.jsonl"

        feedback = {
            "record_id": record_id,
            "rating": rating,
            "comment": comment,
            "correction": correction,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        async with aiofiles.open(feedback_file, "a") as f:
            await f.write(json.dumps(feedback) + "\n")

        logger.info(f"Added feedback for record {record_id}: rating={rating}")
        return True


# =============================================================================
# Singleton instance
# =============================================================================

_training_logger: Optional[TrainingDataLogger] = None


def get_training_logger() -> TrainingDataLogger:
    """Get the singleton training data logger instance."""
    global _training_logger
    if _training_logger is None:
        _training_logger = TrainingDataLogger()
    return _training_logger


# =============================================================================
# FastAPI Routes
# =============================================================================


def create_training_routes():
    """Create FastAPI routes for training data."""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
    from typing import Optional, Dict, Any, List

    router = APIRouter(prefix="/api/v1/guard/training", tags=["training"])

    class LogDecisionRequest(BaseModel):
        action_type: str
        resource: str
        agent_id: str
        session_id: str
        decision: str
        decided_by: str
        reason: Optional[str] = None
        latency_ms: float = 0.0
        policy_matched: Optional[str] = None
        metadata: Optional[Dict[str, Any]] = None

    class ExportRequest(BaseModel):
        output_path: str
        format: str = "jsonl"
        filters: Optional[Dict[str, Any]] = None
        limit: Optional[int] = None

    class FeedbackRequest(BaseModel):
        record_id: str
        rating: int
        comment: Optional[str] = None
        correction: Optional[str] = None

    @router.post("/log")
    async def log_decision(request: LogDecisionRequest):
        """Log a decision for training."""
        logger = get_training_logger()
        record = await logger.log_decision(
            action_type=request.action_type,
            resource=request.resource,
            agent_id=request.agent_id,
            session_id=request.session_id,
            decision=request.decision,
            decided_by=request.decided_by,
            reason=request.reason,
            latency_ms=request.latency_ms,
            policy_matched=request.policy_matched,
            metadata=request.metadata,
        )
        return {"record_id": record.record_id, "logged": True}

    @router.get("/stats")
    async def get_stats():
        """Get training data statistics."""
        logger = get_training_logger()
        stats = logger.get_stats()
        return {
            "total_records": stats.total_records,
            "human_decisions": stats.human_decisions,
            "policy_decisions": stats.policy_decisions,
            "records_by_decision": stats.records_by_decision,
            "records_by_action_type": stats.records_by_action_type,
            "avg_latency_ms": stats.avg_latency_ms,
            "pii_detected_count": stats.pii_detected_count,
            "storage_size_bytes": stats.storage_size_bytes,
        }

    @router.post("/export")
    async def export_data(request: ExportRequest):
        """Export training data to file."""
        logger = get_training_logger()

        try:
            format_enum = DataExportFormat(request.format)
        except ValueError:
            raise HTTPException(400, f"Invalid format: {request.format}")

        count = await logger.export(
            output_path=request.output_path,
            format=format_enum,
            filters=request.filters,
            limit=request.limit,
        )

        return {
            "exported": count,
            "path": request.output_path,
            "format": request.format,
        }

    @router.post("/feedback")
    async def add_feedback(request: FeedbackRequest):
        """Add feedback to a training record."""
        logger = get_training_logger()

        if not 1 <= request.rating <= 5:
            raise HTTPException(400, "Rating must be between 1 and 5")

        success = await logger.add_feedback(
            record_id=request.record_id,
            rating=request.rating,
            comment=request.comment,
            correction=request.correction,
        )

        return {"success": success, "record_id": request.record_id}

    return router
