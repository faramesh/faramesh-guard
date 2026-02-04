"""
Browser extractor - extracts context from browser automation.
"""

import re
from typing import Dict, Any, List
from urllib.parse import urlparse

from .base import (
    BaseExtractor,
    ExtractorResult,
    ExtractedTarget,
    RiskFactor,
)


class BrowserExtractor(BaseExtractor):
    """Extractor for browser automation operations."""

    tool_patterns = ["browser", "puppeteer", "playwright", "selenium", "web"]

    # Sensitive site patterns
    SENSITIVE_SITES = [
        r"bank",
        r"paypal",
        r"stripe\.com",
        r"venmo",
        r"chase\.com",
        r"wellsfargo",
        r"accounts\.google",
        r"login\.",
        r"signin\.",
        r"auth\.",
        r"oauth",
        r"admin\.",
        r"dashboard\.",
        r"portal\.",
    ]

    # Sensitive form fields
    SENSITIVE_FIELDS = [
        "password",
        "passwd",
        "credit_card",
        "creditcard",
        "card_number",
        "cvv",
        "cvc",
        "ssn",
        "social_security",
        "bank_account",
        "routing_number",
        "pin",
    ]

    # Actions that access credentials
    CREDENTIAL_ACTIONS = [
        "get_cookies",
        "get_storage",
        "get_credentials",
        "export_cookies",
        "get_passwords",
    ]

    def extract(self, tool_name: str, args: Dict[str, Any]) -> ExtractorResult:
        """Extract context from browser automation."""

        # Get URL and action
        url = args.get("url", args.get("page", ""))
        action = args.get("action", args.get("command", "navigate"))

        # Parse URL
        parsed_url = urlparse(url) if url else None
        host = parsed_url.netloc if parsed_url else ""

        # Classify operation
        operation = self._classify_operation(action, args)

        # Build targets
        targets = []
        if url:
            targets.append(
                ExtractedTarget(
                    kind="url",
                    value=url,
                    normalized=url,
                    sensitive=self._is_sensitive_site(url, host),
                    internal=self._is_internal_site(host),
                    metadata={
                        "host": host,
                        "action": action,
                    },
                )
            )

        # Assess risks
        risk_factors, risk_score = self._assess_risks(action, url, host, args)

        # Determine blast radius
        blast_radius = "network" if not self._is_internal_site(host) else "user"

        # Determine reversibility
        reversibility = self._determine_reversibility(action, args)

        # Generate summary
        human_summary = self._generate_summary(action, url, host)

        # Check if approval needed
        requires_approval, approval_reason = self._needs_approval(
            action, url, host, targets, risk_factors, args
        )

        return ExtractorResult(
            tool_name=tool_name,
            operation=operation,
            authority_domain="browser",
            targets=targets,
            risk_factors=risk_factors,
            risk_score=risk_score,
            normalized_args=args,
            blast_radius=blast_radius,
            reversibility=reversibility,
            human_summary=human_summary,
            requires_approval=requires_approval,
            approval_reason=approval_reason,
        )

    def _classify_operation(self, action: str, args: Dict[str, Any]) -> str:
        """Classify browser operation."""
        action_lower = action.lower()

        if any(nav in action_lower for nav in ["navigate", "goto", "open", "visit"]):
            return "navigate"
        elif any(click in action_lower for click in ["click", "press", "tap"]):
            return "interact"
        elif any(
            input_action in action_lower
            for input_action in ["type", "fill", "input", "enter"]
        ):
            return "input"
        elif any(submit in action_lower for submit in ["submit", "form"]):
            return "submit"
        elif any(
            screenshot in action_lower for screenshot in ["screenshot", "capture"]
        ):
            return "capture"
        elif any(download in action_lower for download in ["download", "save"]):
            return "download"
        elif any(
            cookie in action_lower for cookie in ["cookie", "storage", "credential"]
        ):
            return "credential_access"
        elif any(
            scrape in action_lower
            for scrape in ["scrape", "extract", "get_text", "get_content"]
        ):
            return "scrape"
        elif any(wait in action_lower for wait in ["wait", "delay", "sleep"]):
            return "wait"
        else:
            return "browse"

    def _is_sensitive_site(self, url: str, host: str) -> bool:
        """Check if site is sensitive."""
        combined = f"{url} {host}".lower()

        for pattern in self.SENSITIVE_SITES:
            if re.search(pattern, combined):
                return True

        return False

    def _is_internal_site(self, host: str) -> bool:
        """Check if site is internal."""
        if not host:
            return True

        internal_patterns = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "192.168.",
            "10.",
            "172.16.",
            ".local",
            ".internal",
            ".corp",
        ]

        host_lower = host.lower()
        return any(pattern in host_lower for pattern in internal_patterns)

    def _assess_risks(
        self,
        action: str,
        url: str,
        host: str,
        args: Dict[str, Any],
    ) -> tuple[List[RiskFactor], int]:
        """Assess risk factors."""
        factors = []
        score = 0

        # Credential access
        action_lower = action.lower()
        if any(cred in action_lower for cred in self.CREDENTIAL_ACTIONS):
            factors.append(RiskFactor.CREDENTIAL_ACCESS)
            score += 40

        # Sensitive site
        if self._is_sensitive_site(url, host):
            factors.append(RiskFactor.SENSITIVE_SITE)
            score += 30

        # Form submission
        if "submit" in action_lower or "form" in action_lower:
            factors.append(RiskFactor.FORM_SUBMISSION)
            score += 20

            # Check for sensitive field input
            input_data = args.get("data", args.get("fields", {}))
            if isinstance(input_data, dict):
                for field_name in input_data:
                    if any(
                        sensitive in field_name.lower()
                        for sensitive in self.SENSITIVE_FIELDS
                    ):
                        factors.append(RiskFactor.CREDENTIAL_EXPOSURE)
                        score += 30
                        break

        # Download
        if "download" in action_lower:
            factors.append(RiskFactor.DOWNLOAD)
            score += 15

        # External network
        if not self._is_internal_site(host):
            factors.append(RiskFactor.EXTERNAL_NETWORK)
            score += 10

        return factors, min(score, 100)

    def _determine_reversibility(self, action: str, args: Dict[str, Any]) -> str:
        """Determine reversibility."""
        action_lower = action.lower()

        # Form submissions are partially reversible
        if "submit" in action_lower or "form" in action_lower:
            return "partial"

        # Downloads create new files but don't change state
        if "download" in action_lower:
            return "reversible"

        # Navigation and scraping are reversible
        return "reversible"

    def _generate_summary(self, action: str, url: str, host: str) -> str:
        """Generate human-readable summary."""
        if not url:
            return f"Browser: {action}"

        # Truncate URL
        if len(url) > 50:
            url_display = url[:47] + "..."
        else:
            url_display = url

        return f"Browser {action}: {url_display}"

    def _needs_approval(
        self,
        action: str,
        url: str,
        host: str,
        targets: List[ExtractedTarget],
        risk_factors: List[RiskFactor],
        args: Dict[str, Any],
    ) -> tuple[bool, str | None]:
        """Determine if operation needs approval."""

        # Credential access always needs approval
        if RiskFactor.CREDENTIAL_ACCESS in risk_factors:
            return True, "Credential access operation"

        # Sensitive sites need approval
        if RiskFactor.SENSITIVE_SITE in risk_factors:
            return True, f"Accessing sensitive site: {host}"

        # Form submission with sensitive data
        if (
            RiskFactor.FORM_SUBMISSION in risk_factors
            and RiskFactor.CREDENTIAL_EXPOSURE in risk_factors
        ):
            return True, "Form submission with sensitive data"

        # Downloads need approval
        if RiskFactor.DOWNLOAD in risk_factors:
            return True, f"Downloading from: {host}"

        return False, None
