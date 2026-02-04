"""
Workflow Detection module for Faramesh Guard.

Detects common development workflows and adjusts risk assessment.
"""

from .detector import (
    WorkflowDetector,
    WorkflowType,
    WorkflowPhase,
    WorkflowSignal,
    DetectedWorkflow,
    WorkflowDefinition,
    get_workflow_detector,
    create_workflow_routes,
)

__all__ = [
    "WorkflowDetector",
    "WorkflowType",
    "WorkflowPhase",
    "WorkflowSignal",
    "DetectedWorkflow",
    "WorkflowDefinition",
    "get_workflow_detector",
    "create_workflow_routes",
]
