"""
Browser Action Classifier for Faramesh Guard.

Classifies browser-based actions (clicks, form submissions, navigation)
and determines risk levels for browser automation agents.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Pattern, Set

logger = logging.getLogger(__name__)


class BrowserActionType(str, Enum):
    """Types of browser actions."""

    CLICK = "click"
    TYPE = "type"
    NAVIGATE = "navigate"
    SCROLL = "scroll"
    SELECT = "select"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    SUBMIT = "submit"
    HOVER = "hover"
    DRAG_DROP = "drag_drop"
    SCREENSHOT = "screenshot"
    EXECUTE_SCRIPT = "execute_script"


class DomainCategory(str, Enum):
    """Categories of domains."""

    BANKING = "banking"
    PAYMENT = "payment"
    SOCIAL_MEDIA = "social_media"
    EMAIL = "email"
    CLOUD_PROVIDER = "cloud_provider"
    CODE_HOSTING = "code_hosting"
    ADMIN_PANEL = "admin_panel"
    GOVERNMENT = "government"
    HEALTHCARE = "healthcare"
    GENERAL = "general"


class RiskCategory(str, Enum):
    """Risk categories for browser actions."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BrowserContext:
    """Context for a browser action."""

    url: str
    domain: str
    path: str

    # Page context
    page_title: Optional[str] = None
    is_secure: bool = True

    # Session
    has_session: bool = False
    logged_in: bool = False


@dataclass
class ElementContext:
    """Context about the target element."""

    tag_name: str
    element_type: Optional[str] = None
    element_id: Optional[str] = None
    element_name: Optional[str] = None
    element_class: Optional[str] = None
    text_content: Optional[str] = None

    # Form context
    is_password_field: bool = False
    is_card_field: bool = False
    is_submit_button: bool = False
    is_delete_button: bool = False

    # Link context
    href: Optional[str] = None
    target: Optional[str] = None


@dataclass
class ClassifiedAction:
    """Result of classifying a browser action."""

    action_type: str
    risk_category: str
    risk_score: float  # 0.0 to 1.0

    # Context
    domain_category: str

    # Description
    summary: str
    warnings: List[str] = field(default_factory=list)

    # Recommendations
    require_approval: bool = False
    suggested_timeout: int = 30  # seconds

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


class BrowserActionClassifier:
    """
    Classifies browser actions for risk assessment.

    Features:
    - Domain categorization (banking, social, admin, etc.)
    - Element-based risk assessment
    - Action pattern recognition
    - Sensitive field detection
    - Context-aware scoring
    """

    def __init__(self):
        self._domain_patterns: Dict[DomainCategory, List[Pattern]] = {}
        self._init_domain_patterns()

        self._sensitive_patterns: Dict[str, List[Pattern]] = {}
        self._init_sensitive_patterns()

        self._action_stats: Dict[str, int] = {}

        logger.info("BrowserActionClassifier initialized")

    def _init_domain_patterns(self):
        """Initialize domain categorization patterns."""
        self._domain_patterns = {
            DomainCategory.BANKING: [
                re.compile(
                    r"(chase|bankofamerica|wellsfargo|citibank|usbank|pnc|capital-?one)\.com",
                    re.I,
                ),
                re.compile(r"(hsbc|barclays|lloyds|natwest|santander)\.co\.uk", re.I),
                re.compile(r"online\.?banking", re.I),
            ],
            DomainCategory.PAYMENT: [
                re.compile(
                    r"(paypal|stripe|square|venmo|zelle|wise|revolut)\.com", re.I
                ),
                re.compile(r"checkout\.", re.I),
                re.compile(r"pay\.(google|apple)\.com", re.I),
            ],
            DomainCategory.SOCIAL_MEDIA: [
                re.compile(
                    r"(facebook|twitter|x|instagram|linkedin|tiktok|reddit)\.com", re.I
                ),
                re.compile(r"(threads\.net|mastodon\.social)", re.I),
            ],
            DomainCategory.EMAIL: [
                re.compile(
                    r"(gmail|mail\.google|outlook|mail\.yahoo|proton\.me)\.com", re.I
                ),
                re.compile(r"mail\.", re.I),
            ],
            DomainCategory.CLOUD_PROVIDER: [
                re.compile(
                    r"(console\.aws|portal\.azure|console\.cloud\.google)\.com", re.I
                ),
                re.compile(
                    r"(app\.vercel|dashboard\.heroku|fly\.io|railway\.app)", re.I
                ),
            ],
            DomainCategory.CODE_HOSTING: [
                re.compile(r"github\.com", re.I),
                re.compile(r"gitlab\.com", re.I),
                re.compile(r"bitbucket\.org", re.I),
            ],
            DomainCategory.ADMIN_PANEL: [
                re.compile(r"admin\.", re.I),
                re.compile(r"/admin/?", re.I),
                re.compile(r"dashboard\.", re.I),
                re.compile(r"/dashboard/?", re.I),
            ],
            DomainCategory.GOVERNMENT: [
                re.compile(r"\.gov$", re.I),
                re.compile(r"\.gov\.\w{2}$", re.I),
            ],
            DomainCategory.HEALTHCARE: [
                re.compile(r"(mychart|epic|cerner)", re.I),
                re.compile(r"health\.(com|org|gov)", re.I),
            ],
        }

    def _init_sensitive_patterns(self):
        """Initialize sensitive field patterns."""
        self._sensitive_patterns = {
            "password": [
                re.compile(r"(password|passwd|pwd|secret)", re.I),
                re.compile(r"type=['\"]password['\"]", re.I),
            ],
            "card": [
                re.compile(r"(card.?number|credit.?card|cc.?num)", re.I),
                re.compile(r"(cvv|cvc|security.?code)", re.I),
                re.compile(r"(expir|exp.?date)", re.I),
            ],
            "ssn": [
                re.compile(r"(ssn|social.?security|tax.?id)", re.I),
            ],
            "bank_account": [
                re.compile(r"(routing.?number|account.?number|iban|swift)", re.I),
            ],
            "delete": [
                re.compile(r"(delete|remove|destroy|terminate)", re.I),
            ],
            "submit": [
                re.compile(r"(submit|confirm|proceed|continue|pay|send)", re.I),
            ],
            "transfer": [
                re.compile(r"(transfer|send.?money|wire|payout)", re.I),
            ],
        }

    def classify(
        self,
        action_type: BrowserActionType,
        browser_context: BrowserContext,
        element_context: Optional[ElementContext] = None,
        action_data: Optional[Dict[str, Any]] = None,
    ) -> ClassifiedAction:
        """
        Classify a browser action.

        Args:
            action_type: Type of browser action
            browser_context: Context about the page/URL
            element_context: Context about target element (if applicable)
            action_data: Additional action data (input text, etc.)

        Returns:
            ClassifiedAction with risk assessment
        """
        action_data = action_data or {}

        # Categorize domain
        domain_category = self._categorize_domain(
            browser_context.domain,
            browser_context.path,
        )

        # Calculate base risk from action type
        base_risk = self._get_action_base_risk(action_type)

        # Adjust for domain category
        domain_multiplier = self._get_domain_risk_multiplier(domain_category)

        # Adjust for element context
        element_risk, element_warnings = self._assess_element_risk(element_context)

        # Adjust for action data
        data_risk, data_warnings = self._assess_action_data(action_type, action_data)

        # Calculate final risk
        risk_score = min(1.0, base_risk * domain_multiplier + element_risk + data_risk)

        # Determine category
        risk_category = self._score_to_category(risk_score)

        # Generate summary
        summary = self._generate_summary(
            action_type, browser_context, element_context, domain_category
        )

        # Collect warnings
        warnings = element_warnings + data_warnings

        # Additional security checks
        if not browser_context.is_secure:
            warnings.append("Page is not using HTTPS")
            risk_score = min(1.0, risk_score + 0.1)

        if domain_category in [DomainCategory.BANKING, DomainCategory.PAYMENT]:
            if action_type in [BrowserActionType.SUBMIT, BrowserActionType.CLICK]:
                warnings.append(f"Financial action on {domain_category.value} site")

        # Track stats
        self._action_stats[action_type.value] = (
            self._action_stats.get(action_type.value, 0) + 1
        )

        return ClassifiedAction(
            action_type=action_type.value,
            risk_category=risk_category.value,
            risk_score=risk_score,
            domain_category=domain_category.value,
            summary=summary,
            warnings=warnings,
            require_approval=risk_score >= 0.5,
            suggested_timeout=self._get_suggested_timeout(risk_score),
            metadata={
                "url": browser_context.url,
                "domain": browser_context.domain,
                "logged_in": browser_context.logged_in,
            },
        )

    def _categorize_domain(self, domain: str, path: str) -> DomainCategory:
        """Categorize a domain."""
        full_url = f"{domain}{path}"

        for category, patterns in self._domain_patterns.items():
            for pattern in patterns:
                if pattern.search(full_url):
                    return category

        return DomainCategory.GENERAL

    def _get_action_base_risk(self, action_type: BrowserActionType) -> float:
        """Get base risk for action type."""
        risks = {
            BrowserActionType.SCROLL: 0.0,
            BrowserActionType.HOVER: 0.0,
            BrowserActionType.SCREENSHOT: 0.1,
            BrowserActionType.CLICK: 0.2,
            BrowserActionType.SELECT: 0.2,
            BrowserActionType.NAVIGATE: 0.2,
            BrowserActionType.TYPE: 0.3,
            BrowserActionType.DOWNLOAD: 0.4,
            BrowserActionType.UPLOAD: 0.5,
            BrowserActionType.SUBMIT: 0.5,
            BrowserActionType.DRAG_DROP: 0.3,
            BrowserActionType.EXECUTE_SCRIPT: 0.8,
        }
        return risks.get(action_type, 0.3)

    def _get_domain_risk_multiplier(self, category: DomainCategory) -> float:
        """Get risk multiplier for domain category."""
        multipliers = {
            DomainCategory.GENERAL: 1.0,
            DomainCategory.SOCIAL_MEDIA: 1.2,
            DomainCategory.EMAIL: 1.3,
            DomainCategory.CODE_HOSTING: 1.2,
            DomainCategory.CLOUD_PROVIDER: 1.5,
            DomainCategory.ADMIN_PANEL: 1.5,
            DomainCategory.BANKING: 2.0,
            DomainCategory.PAYMENT: 2.0,
            DomainCategory.GOVERNMENT: 1.5,
            DomainCategory.HEALTHCARE: 1.5,
        }
        return multipliers.get(category, 1.0)

    def _assess_element_risk(
        self,
        element: Optional[ElementContext],
    ) -> tuple[float, List[str]]:
        """Assess risk from element context."""
        if not element:
            return 0.0, []

        risk = 0.0
        warnings = []

        # Check for password field
        if element.is_password_field:
            risk += 0.3
            warnings.append("Interacting with password field")

        # Check for card field
        if element.is_card_field:
            risk += 0.4
            warnings.append("Interacting with payment card field")

        # Check for submit/delete buttons
        if element.is_submit_button:
            risk += 0.2
            warnings.append("Clicking submit button")

        if element.is_delete_button:
            risk += 0.3
            warnings.append("Clicking delete/remove button")

        # Check element attributes for sensitive patterns
        attrs_to_check = [
            element.element_id or "",
            element.element_name or "",
            element.element_class or "",
            element.text_content or "",
        ]

        for pattern_name, patterns in self._sensitive_patterns.items():
            for attr in attrs_to_check:
                for pattern in patterns:
                    if pattern.search(attr):
                        if pattern_name == "password" and not element.is_password_field:
                            risk += 0.2
                            warnings.append(f"Element related to: {pattern_name}")
                        elif pattern_name == "delete" and not element.is_delete_button:
                            risk += 0.2
                            warnings.append(f"Element related to: {pattern_name}")
                        break

        return risk, warnings

    def _assess_action_data(
        self,
        action_type: BrowserActionType,
        data: Dict[str, Any],
    ) -> tuple[float, List[str]]:
        """Assess risk from action data."""
        risk = 0.0
        warnings = []

        if action_type == BrowserActionType.TYPE:
            text = data.get("text", "")

            # Check if typing sensitive data
            if re.search(r"\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}", text):
                risk += 0.5
                warnings.append("Typing what appears to be a card number")

            if re.search(r"\d{3}-\d{2}-\d{4}", text):
                risk += 0.5
                warnings.append("Typing what appears to be an SSN")

        if action_type == BrowserActionType.NAVIGATE:
            url = data.get("url", "")

            # Check for suspicious URL patterns
            if re.search(r"(delete|remove|terminate|cancel)", url, re.I):
                risk += 0.2
                warnings.append("Navigating to potentially destructive page")

            if "admin" in url.lower():
                risk += 0.1
                warnings.append("Navigating to admin page")

        if action_type == BrowserActionType.UPLOAD:
            filename = data.get("filename", "")

            # Check for sensitive file types
            if re.search(r"\.(key|pem|p12|pfx|env|credentials)$", filename, re.I):
                risk += 0.4
                warnings.append("Uploading potentially sensitive file")

        if action_type == BrowserActionType.EXECUTE_SCRIPT:
            script = data.get("script", "")

            # Check for dangerous operations
            if re.search(
                r"(eval|innerHTML|document\.write|localStorage|sessionStorage)",
                script,
                re.I,
            ):
                risk += 0.3
                warnings.append("Script contains potentially dangerous operations")

        return risk, warnings

    def _score_to_category(self, score: float) -> RiskCategory:
        """Convert risk score to category."""
        if score < 0.1:
            return RiskCategory.SAFE
        elif score < 0.3:
            return RiskCategory.LOW
        elif score < 0.5:
            return RiskCategory.MEDIUM
        elif score < 0.7:
            return RiskCategory.HIGH
        else:
            return RiskCategory.CRITICAL

    def _generate_summary(
        self,
        action_type: BrowserActionType,
        browser: BrowserContext,
        element: Optional[ElementContext],
        domain_category: DomainCategory,
    ) -> str:
        """Generate human-readable summary."""
        action_desc = action_type.value.replace("_", " ").title()

        target = ""
        if element:
            if element.text_content:
                target = (
                    f' "{element.text_content[:30]}..."'
                    if len(element.text_content) > 30
                    else f' "{element.text_content}"'
                )
            elif element.element_id:
                target = f" #{element.element_id}"

        domain_desc = (
            f" on {domain_category.value.replace('_', ' ')}"
            if domain_category != DomainCategory.GENERAL
            else ""
        )

        return f"{action_desc}{target}{domain_desc} ({browser.domain})"

    def _get_suggested_timeout(self, risk_score: float) -> int:
        """Get suggested approval timeout based on risk."""
        if risk_score < 0.3:
            return 60
        elif risk_score < 0.5:
            return 30
        elif risk_score < 0.7:
            return 15
        else:
            return 10

    def get_stats(self) -> Dict[str, Any]:
        """Get classification statistics."""
        return {
            "actions_classified": sum(self._action_stats.values()),
            "by_type": dict(self._action_stats),
        }


# Singleton
_classifier: Optional[BrowserActionClassifier] = None


def get_browser_classifier() -> BrowserActionClassifier:
    global _classifier
    if _classifier is None:
        _classifier = BrowserActionClassifier()
    return _classifier


def create_browser_routes():
    """Create FastAPI routes for browser action classification."""
    from fastapi import APIRouter
    from pydantic import BaseModel
    from typing import Optional, Dict, Any

    router = APIRouter(prefix="/api/v1/guard/browser", tags=["browser"])

    class BrowserContextModel(BaseModel):
        url: str
        domain: str
        path: str
        page_title: Optional[str] = None
        is_secure: bool = True
        has_session: bool = False
        logged_in: bool = False

    class ElementContextModel(BaseModel):
        tag_name: str
        element_type: Optional[str] = None
        element_id: Optional[str] = None
        element_name: Optional[str] = None
        element_class: Optional[str] = None
        text_content: Optional[str] = None
        is_password_field: bool = False
        is_card_field: bool = False
        is_submit_button: bool = False
        is_delete_button: bool = False
        href: Optional[str] = None
        target: Optional[str] = None

    class ClassifyRequest(BaseModel):
        action_type: str
        browser_context: BrowserContextModel
        element_context: Optional[ElementContextModel] = None
        action_data: Optional[Dict[str, Any]] = None

    @router.post("/classify")
    async def classify_action(request: ClassifyRequest):
        """Classify a browser action."""
        classifier = get_browser_classifier()

        try:
            action_type = BrowserActionType(request.action_type)
        except ValueError:
            action_type = BrowserActionType.CLICK

        browser_ctx = BrowserContext(
            url=request.browser_context.url,
            domain=request.browser_context.domain,
            path=request.browser_context.path,
            page_title=request.browser_context.page_title,
            is_secure=request.browser_context.is_secure,
            has_session=request.browser_context.has_session,
            logged_in=request.browser_context.logged_in,
        )

        element_ctx = None
        if request.element_context:
            element_ctx = ElementContext(
                tag_name=request.element_context.tag_name,
                element_type=request.element_context.element_type,
                element_id=request.element_context.element_id,
                element_name=request.element_context.element_name,
                element_class=request.element_context.element_class,
                text_content=request.element_context.text_content,
                is_password_field=request.element_context.is_password_field,
                is_card_field=request.element_context.is_card_field,
                is_submit_button=request.element_context.is_submit_button,
                is_delete_button=request.element_context.is_delete_button,
                href=request.element_context.href,
                target=request.element_context.target,
            )

        result = classifier.classify(
            action_type=action_type,
            browser_context=browser_ctx,
            element_context=element_ctx,
            action_data=request.action_data,
        )

        from dataclasses import asdict

        return asdict(result)

    @router.get("/stats")
    async def get_stats():
        """Get classification statistics."""
        classifier = get_browser_classifier()
        return classifier.get_stats()

    @router.get("/action-types")
    async def list_action_types():
        """List supported action types."""
        return {"action_types": [t.value for t in BrowserActionType]}

    @router.get("/domain-categories")
    async def list_domain_categories():
        """List domain categories."""
        return {"categories": [c.value for c in DomainCategory]}

    return router
