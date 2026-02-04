"""
Workflow Detector for Faramesh Guard.

Detects common development workflows and adjusts risk assessment
based on recognized patterns.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import aiofiles

logger = logging.getLogger(__name__)


class WorkflowType(str, Enum):
    """Known workflow types."""

    UNKNOWN = "unknown"

    # Development workflows
    CODE_REVIEW = "code_review"
    FEATURE_DEVELOPMENT = "feature_development"
    BUG_FIX = "bug_fix"
    REFACTORING = "refactoring"
    TESTING = "testing"
    DOCUMENTATION = "documentation"

    # Infrastructure workflows
    DEPLOYMENT = "deployment"
    INFRASTRUCTURE = "infrastructure"
    DATABASE_MIGRATION = "database_migration"

    # Data workflows
    DATA_ANALYSIS = "data_analysis"
    DATA_PIPELINE = "data_pipeline"
    ML_TRAINING = "ml_training"

    # Operations
    INCIDENT_RESPONSE = "incident_response"
    MONITORING = "monitoring"
    DEBUGGING = "debugging"


class WorkflowPhase(str, Enum):
    """Phase within a workflow."""

    STARTING = "starting"
    ACTIVE = "active"
    COMPLETING = "completing"
    COMPLETED = "completed"


@dataclass
class WorkflowSignal:
    """A signal that indicates a workflow."""

    signal_id: str
    workflow_type: str
    weight: float  # 0.0 to 1.0

    # Matching
    action_pattern: Optional[str] = None
    resource_pattern: Optional[str] = None
    sequence_position: Optional[int] = None  # For sequence detection


@dataclass
class DetectedWorkflow:
    """A detected workflow instance."""

    workflow_id: str
    workflow_type: str
    phase: str = WorkflowPhase.STARTING.value
    confidence: float = 0.0

    # Context
    session_id: Optional[str] = None
    agent_id: Optional[str] = None

    # Signals
    signals_matched: List[str] = field(default_factory=list)
    actions_in_workflow: int = 0

    # Timing
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_activity: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Risk adjustment
    risk_modifier: float = 1.0  # < 1.0 reduces risk, > 1.0 increases


@dataclass
class WorkflowDefinition:
    """Definition of a workflow pattern."""

    workflow_type: str
    name: str
    description: str

    # Signal patterns
    start_signals: List[WorkflowSignal] = field(default_factory=list)
    activity_signals: List[WorkflowSignal] = field(default_factory=list)
    completion_signals: List[WorkflowSignal] = field(default_factory=list)

    # Thresholds
    min_confidence: float = 0.6
    timeout_minutes: int = 60

    # Risk adjustment
    base_risk_modifier: float = 1.0


class WorkflowDetector:
    """
    Detects and tracks development workflows.

    Features:
    - Pattern-based workflow detection
    - Signal aggregation for confidence
    - Workflow phase tracking
    - Risk adjustment based on context
    - Workflow history
    """

    def __init__(self, data_dir: str = "/var/lib/faramesh-guard/workflows"):
        self.data_dir = Path(data_dir)
        self._definitions: Dict[str, WorkflowDefinition] = {}
        self._active_workflows: Dict[str, DetectedWorkflow] = {}
        self._workflow_history: List[DetectedWorkflow] = []
        self._lock = asyncio.Lock()

        self._init_default_definitions()
        logger.info("WorkflowDetector initialized")

    def _init_default_definitions(self):
        """Initialize default workflow definitions."""

        # Code Review workflow
        self._definitions["code_review"] = WorkflowDefinition(
            workflow_type=WorkflowType.CODE_REVIEW.value,
            name="Code Review",
            description="Reviewing code changes",
            start_signals=[
                WorkflowSignal(
                    "cr_start_1",
                    WorkflowType.CODE_REVIEW.value,
                    0.8,
                    action_pattern="file_read",
                    resource_pattern="*.diff",
                ),
                WorkflowSignal(
                    "cr_start_2",
                    WorkflowType.CODE_REVIEW.value,
                    0.7,
                    action_pattern="shell_execute",
                    resource_pattern="*git diff*",
                ),
                WorkflowSignal(
                    "cr_start_3",
                    WorkflowType.CODE_REVIEW.value,
                    0.6,
                    action_pattern="shell_execute",
                    resource_pattern="*git log*",
                ),
            ],
            activity_signals=[
                WorkflowSignal(
                    "cr_act_1",
                    WorkflowType.CODE_REVIEW.value,
                    0.5,
                    action_pattern="file_read",
                ),
                WorkflowSignal(
                    "cr_act_2",
                    WorkflowType.CODE_REVIEW.value,
                    0.4,
                    action_pattern="shell_execute",
                    resource_pattern="*git show*",
                ),
            ],
            base_risk_modifier=0.8,  # Lower risk during code review
        )

        # Feature Development workflow
        self._definitions["feature_development"] = WorkflowDefinition(
            workflow_type=WorkflowType.FEATURE_DEVELOPMENT.value,
            name="Feature Development",
            description="Building new features",
            start_signals=[
                WorkflowSignal(
                    "fd_start_1",
                    WorkflowType.FEATURE_DEVELOPMENT.value,
                    0.7,
                    action_pattern="shell_execute",
                    resource_pattern="*git checkout -b*",
                ),
                WorkflowSignal(
                    "fd_start_2",
                    WorkflowType.FEATURE_DEVELOPMENT.value,
                    0.6,
                    action_pattern="file_create",
                ),
            ],
            activity_signals=[
                WorkflowSignal(
                    "fd_act_1",
                    WorkflowType.FEATURE_DEVELOPMENT.value,
                    0.5,
                    action_pattern="file_write",
                ),
                WorkflowSignal(
                    "fd_act_2",
                    WorkflowType.FEATURE_DEVELOPMENT.value,
                    0.4,
                    action_pattern="shell_execute",
                    resource_pattern="*npm*",
                ),
                WorkflowSignal(
                    "fd_act_3",
                    WorkflowType.FEATURE_DEVELOPMENT.value,
                    0.4,
                    action_pattern="shell_execute",
                    resource_pattern="*pip*",
                ),
            ],
            completion_signals=[
                WorkflowSignal(
                    "fd_end_1",
                    WorkflowType.FEATURE_DEVELOPMENT.value,
                    0.8,
                    action_pattern="shell_execute",
                    resource_pattern="*git commit*",
                ),
                WorkflowSignal(
                    "fd_end_2",
                    WorkflowType.FEATURE_DEVELOPMENT.value,
                    0.7,
                    action_pattern="shell_execute",
                    resource_pattern="*git push*",
                ),
            ],
            base_risk_modifier=0.9,
        )

        # Testing workflow
        self._definitions["testing"] = WorkflowDefinition(
            workflow_type=WorkflowType.TESTING.value,
            name="Testing",
            description="Running tests",
            start_signals=[
                WorkflowSignal(
                    "test_start_1",
                    WorkflowType.TESTING.value,
                    0.9,
                    action_pattern="shell_execute",
                    resource_pattern="*pytest*",
                ),
                WorkflowSignal(
                    "test_start_2",
                    WorkflowType.TESTING.value,
                    0.9,
                    action_pattern="shell_execute",
                    resource_pattern="*npm test*",
                ),
                WorkflowSignal(
                    "test_start_3",
                    WorkflowType.TESTING.value,
                    0.8,
                    action_pattern="shell_execute",
                    resource_pattern="*jest*",
                ),
            ],
            activity_signals=[
                WorkflowSignal(
                    "test_act_1",
                    WorkflowType.TESTING.value,
                    0.6,
                    action_pattern="file_read",
                    resource_pattern="*test*",
                ),
            ],
            base_risk_modifier=0.7,  # Lower risk during testing
        )

        # Deployment workflow
        self._definitions["deployment"] = WorkflowDefinition(
            workflow_type=WorkflowType.DEPLOYMENT.value,
            name="Deployment",
            description="Deploying to production",
            start_signals=[
                WorkflowSignal(
                    "deploy_start_1",
                    WorkflowType.DEPLOYMENT.value,
                    0.9,
                    action_pattern="shell_execute",
                    resource_pattern="*deploy*",
                ),
                WorkflowSignal(
                    "deploy_start_2",
                    WorkflowType.DEPLOYMENT.value,
                    0.8,
                    action_pattern="shell_execute",
                    resource_pattern="*kubectl*",
                ),
                WorkflowSignal(
                    "deploy_start_3",
                    WorkflowType.DEPLOYMENT.value,
                    0.8,
                    action_pattern="shell_execute",
                    resource_pattern="*docker*push*",
                ),
            ],
            activity_signals=[
                WorkflowSignal(
                    "deploy_act_1",
                    WorkflowType.DEPLOYMENT.value,
                    0.6,
                    action_pattern="api_call",
                    resource_pattern="*aws*",
                ),
                WorkflowSignal(
                    "deploy_act_2",
                    WorkflowType.DEPLOYMENT.value,
                    0.6,
                    action_pattern="shell_execute",
                    resource_pattern="*helm*",
                ),
            ],
            base_risk_modifier=1.2,  # Higher risk during deployment
            timeout_minutes=30,
        )

        # Database Migration workflow
        self._definitions["database_migration"] = WorkflowDefinition(
            workflow_type=WorkflowType.DATABASE_MIGRATION.value,
            name="Database Migration",
            description="Running database migrations",
            start_signals=[
                WorkflowSignal(
                    "db_start_1",
                    WorkflowType.DATABASE_MIGRATION.value,
                    0.9,
                    action_pattern="shell_execute",
                    resource_pattern="*migrate*",
                ),
                WorkflowSignal(
                    "db_start_2",
                    WorkflowType.DATABASE_MIGRATION.value,
                    0.9,
                    action_pattern="shell_execute",
                    resource_pattern="*alembic*",
                ),
                WorkflowSignal(
                    "db_start_3",
                    WorkflowType.DATABASE_MIGRATION.value,
                    0.8,
                    action_pattern="database_query",
                    resource_pattern="*ALTER*",
                ),
            ],
            base_risk_modifier=1.5,  # Higher risk for DB migrations
            timeout_minutes=15,
        )

        # Incident Response workflow
        self._definitions["incident_response"] = WorkflowDefinition(
            workflow_type=WorkflowType.INCIDENT_RESPONSE.value,
            name="Incident Response",
            description="Responding to production incident",
            start_signals=[
                WorkflowSignal(
                    "ir_start_1",
                    WorkflowType.INCIDENT_RESPONSE.value,
                    0.7,
                    action_pattern="shell_execute",
                    resource_pattern="*kubectl logs*",
                ),
                WorkflowSignal(
                    "ir_start_2",
                    WorkflowType.INCIDENT_RESPONSE.value,
                    0.7,
                    action_pattern="shell_execute",
                    resource_pattern="*tail -f*",
                ),
            ],
            activity_signals=[
                WorkflowSignal(
                    "ir_act_1",
                    WorkflowType.INCIDENT_RESPONSE.value,
                    0.5,
                    action_pattern="shell_execute",
                    resource_pattern="*grep*",
                ),
                WorkflowSignal(
                    "ir_act_2",
                    WorkflowType.INCIDENT_RESPONSE.value,
                    0.6,
                    action_pattern="api_call",
                    resource_pattern="*monitoring*",
                ),
            ],
            base_risk_modifier=1.3,  # Higher risk during incidents
            min_confidence=0.5,  # Lower threshold for incident detection
            timeout_minutes=120,
        )

        # Data Analysis workflow
        self._definitions["data_analysis"] = WorkflowDefinition(
            workflow_type=WorkflowType.DATA_ANALYSIS.value,
            name="Data Analysis",
            description="Analyzing data",
            start_signals=[
                WorkflowSignal(
                    "da_start_1",
                    WorkflowType.DATA_ANALYSIS.value,
                    0.8,
                    action_pattern="shell_execute",
                    resource_pattern="*jupyter*",
                ),
                WorkflowSignal(
                    "da_start_2",
                    WorkflowType.DATA_ANALYSIS.value,
                    0.7,
                    action_pattern="file_read",
                    resource_pattern="*.csv",
                ),
                WorkflowSignal(
                    "da_start_3",
                    WorkflowType.DATA_ANALYSIS.value,
                    0.7,
                    action_pattern="file_read",
                    resource_pattern="*.parquet",
                ),
            ],
            activity_signals=[
                WorkflowSignal(
                    "da_act_1",
                    WorkflowType.DATA_ANALYSIS.value,
                    0.5,
                    action_pattern="database_query",
                ),
            ],
            base_risk_modifier=0.9,
        )

    async def start(self):
        """Start the detector."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        await self._load_state()

        # Start cleanup task
        asyncio.create_task(self._cleanup_loop())

    async def stop(self):
        """Stop and save state."""
        await self._save_state()

    async def process_action(
        self,
        action_type: str,
        resource: str,
        agent_id: str,
        session_id: Optional[str] = None,
    ) -> Optional[DetectedWorkflow]:
        """
        Process an action and detect/update workflows.

        Returns the current workflow if one is detected/active.
        """
        import fnmatch
        import hashlib

        async with self._lock:
            now = datetime.now(timezone.utc)

            # Check for matching signals across all definitions
            matched_signals: Dict[str, List[WorkflowSignal]] = {}

            for wf_type, definition in self._definitions.items():
                all_signals = (
                    definition.start_signals
                    + definition.activity_signals
                    + definition.completion_signals
                )

                for signal in all_signals:
                    if self._signal_matches(signal, action_type, resource):
                        if wf_type not in matched_signals:
                            matched_signals[wf_type] = []
                        matched_signals[wf_type].append(signal)

            # Find or update workflow
            workflow_key = f"{session_id or 'global'}:{agent_id}"
            current_workflow = self._active_workflows.get(workflow_key)

            if current_workflow:
                # Update existing workflow
                current_workflow.last_activity = now.isoformat()
                current_workflow.actions_in_workflow += 1

                # Check for completion signals
                wf_def = self._definitions.get(current_workflow.workflow_type)
                if wf_def:
                    for signal in matched_signals.get(
                        current_workflow.workflow_type, []
                    ):
                        if signal in wf_def.completion_signals:
                            current_workflow.phase = WorkflowPhase.COMPLETING.value

                return current_workflow

            # Try to start new workflow
            if matched_signals:
                # Find best matching workflow type
                best_type = None
                best_confidence = 0.0

                for wf_type, signals in matched_signals.items():
                    definition = self._definitions[wf_type]

                    # Calculate confidence
                    start_weight = sum(
                        s.weight for s in signals if s in definition.start_signals
                    )
                    confidence = min(1.0, start_weight)

                    if (
                        confidence >= definition.min_confidence
                        and confidence > best_confidence
                    ):
                        best_type = wf_type
                        best_confidence = confidence

                if best_type:
                    definition = self._definitions[best_type]

                    workflow_id = hashlib.sha256(
                        f"{workflow_key}:{now.isoformat()}".encode()
                    ).hexdigest()[:12]

                    workflow = DetectedWorkflow(
                        workflow_id=workflow_id,
                        workflow_type=best_type,
                        phase=WorkflowPhase.ACTIVE.value,
                        confidence=best_confidence,
                        session_id=session_id,
                        agent_id=agent_id,
                        signals_matched=[
                            s.signal_id for s in matched_signals[best_type]
                        ],
                        actions_in_workflow=1,
                        risk_modifier=definition.base_risk_modifier,
                    )

                    self._active_workflows[workflow_key] = workflow
                    logger.info(
                        f"Detected workflow: {best_type} (confidence: {best_confidence:.2f})"
                    )

                    return workflow

            return None

    def _signal_matches(
        self,
        signal: WorkflowSignal,
        action_type: str,
        resource: str,
    ) -> bool:
        """Check if signal matches action."""
        import fnmatch

        if signal.action_pattern:
            if not fnmatch.fnmatch(action_type, signal.action_pattern):
                return False

        if signal.resource_pattern:
            if not fnmatch.fnmatch(resource.lower(), signal.resource_pattern.lower()):
                return False

        return True

    async def get_current_workflow(
        self,
        agent_id: str,
        session_id: Optional[str] = None,
    ) -> Optional[DetectedWorkflow]:
        """Get current active workflow for agent/session."""
        workflow_key = f"{session_id or 'global'}:{agent_id}"
        return self._active_workflows.get(workflow_key)

    async def complete_workflow(
        self,
        agent_id: str,
        session_id: Optional[str] = None,
    ) -> bool:
        """Mark current workflow as completed."""
        workflow_key = f"{session_id or 'global'}:{agent_id}"

        async with self._lock:
            if workflow_key in self._active_workflows:
                workflow = self._active_workflows.pop(workflow_key)
                workflow.phase = WorkflowPhase.COMPLETED.value
                self._workflow_history.append(workflow)

                # Keep history limited
                if len(self._workflow_history) > 1000:
                    self._workflow_history = self._workflow_history[-500:]

                return True

        return False

    async def get_risk_modifier(
        self,
        agent_id: str,
        session_id: Optional[str] = None,
    ) -> float:
        """Get risk modifier for current workflow."""
        workflow = await self.get_current_workflow(agent_id, session_id)
        return workflow.risk_modifier if workflow else 1.0

    def get_workflow_stats(self) -> Dict[str, Any]:
        """Get workflow detection statistics."""
        stats: Dict[str, int] = {}

        for workflow in self._workflow_history:
            wf_type = workflow.workflow_type
            stats[wf_type] = stats.get(wf_type, 0) + 1

        return {
            "active_workflows": len(self._active_workflows),
            "total_detected": len(self._workflow_history),
            "by_type": stats,
        }

    async def _cleanup_loop(self):
        """Clean up timed-out workflows."""
        while True:
            await asyncio.sleep(60)  # Check every minute

            try:
                now = datetime.now(timezone.utc)

                async with self._lock:
                    expired = []

                    for key, workflow in self._active_workflows.items():
                        definition = self._definitions.get(workflow.workflow_type)
                        if not definition:
                            continue

                        last_activity = datetime.fromisoformat(
                            workflow.last_activity.replace("Z", "+00:00")
                        )

                        if now - last_activity > timedelta(
                            minutes=definition.timeout_minutes
                        ):
                            expired.append(key)

                    for key in expired:
                        workflow = self._active_workflows.pop(key)
                        workflow.phase = WorkflowPhase.COMPLETED.value
                        self._workflow_history.append(workflow)
                        logger.info(f"Workflow {workflow.workflow_id} timed out")

            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")

    async def _load_state(self):
        """Load state from disk."""
        state_file = self.data_dir / "workflow_state.json"

        if state_file.exists():
            try:
                async with aiofiles.open(state_file, "r") as f:
                    content = await f.read()

                data = json.loads(content)

                for wf_data in data.get("history", []):
                    self._workflow_history.append(DetectedWorkflow(**wf_data))

                logger.info(
                    f"Loaded {len(self._workflow_history)} workflow history entries"
                )

            except Exception as e:
                logger.error(f"Error loading workflow state: {e}")

    async def _save_state(self):
        """Save state to disk."""
        state_file = self.data_dir / "workflow_state.json"

        try:
            from dataclasses import asdict

            data = {
                "history": [asdict(w) for w in self._workflow_history[-1000:]],
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }

            async with aiofiles.open(state_file, "w") as f:
                await f.write(json.dumps(data, indent=2))

        except Exception as e:
            logger.error(f"Error saving workflow state: {e}")


# Singleton
_detector: Optional[WorkflowDetector] = None


def get_workflow_detector() -> WorkflowDetector:
    global _detector
    if _detector is None:
        _detector = WorkflowDetector()
    return _detector


def create_workflow_routes():
    """Create FastAPI routes for workflow detection."""
    from fastapi import APIRouter
    from pydantic import BaseModel
    from typing import Optional

    router = APIRouter(prefix="/api/v1/guard/workflow", tags=["workflow"])

    class ProcessActionRequest(BaseModel):
        action_type: str
        resource: str
        agent_id: str
        session_id: Optional[str] = None

    @router.post("/process")
    async def process_action(request: ProcessActionRequest):
        """Process action for workflow detection."""
        detector = get_workflow_detector()

        workflow = await detector.process_action(
            action_type=request.action_type,
            resource=request.resource,
            agent_id=request.agent_id,
            session_id=request.session_id,
        )

        if workflow:
            return {
                "detected": True,
                "workflow_id": workflow.workflow_id,
                "workflow_type": workflow.workflow_type,
                "phase": workflow.phase,
                "confidence": workflow.confidence,
                "risk_modifier": workflow.risk_modifier,
            }

        return {"detected": False}

    @router.get("/current")
    async def get_current(agent_id: str, session_id: Optional[str] = None):
        """Get current workflow for agent/session."""
        detector = get_workflow_detector()
        workflow = await detector.get_current_workflow(agent_id, session_id)

        if workflow:
            return {
                "active": True,
                "workflow_id": workflow.workflow_id,
                "workflow_type": workflow.workflow_type,
                "phase": workflow.phase,
                "actions": workflow.actions_in_workflow,
                "risk_modifier": workflow.risk_modifier,
            }

        return {"active": False}

    @router.post("/complete")
    async def complete_workflow(agent_id: str, session_id: Optional[str] = None):
        """Complete current workflow."""
        detector = get_workflow_detector()
        success = await detector.complete_workflow(agent_id, session_id)

        return {"completed": success}

    @router.get("/stats")
    async def get_stats():
        """Get workflow detection statistics."""
        detector = get_workflow_detector()
        return detector.get_workflow_stats()

    @router.get("/risk-modifier")
    async def get_risk_modifier(agent_id: str, session_id: Optional[str] = None):
        """Get risk modifier for current workflow."""
        detector = get_workflow_detector()
        modifier = await detector.get_risk_modifier(agent_id, session_id)

        return {"risk_modifier": modifier}

    return router
