"""
Browser Action Classifier module for Faramesh Guard.

Classifies browser automation actions for risk assessment.
"""

from .classifier import (
    BrowserActionClassifier,
    BrowserActionType,
    DomainCategory,
    RiskCategory,
    BrowserContext,
    ElementContext,
    ClassifiedAction,
    get_browser_classifier,
    create_browser_routes,
)

__all__ = [
    "BrowserActionClassifier",
    "BrowserActionType",
    "DomainCategory",
    "RiskCategory",
    "BrowserContext",
    "ElementContext",
    "ClassifiedAction",
    "get_browser_classifier",
    "create_browser_routes",
]
