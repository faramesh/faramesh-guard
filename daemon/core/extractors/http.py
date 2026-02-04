"""
HTTP/API extractor - extracts context from HTTP requests.
"""

import re
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs

from .base import (
    BaseExtractor,
    ExtractorResult,
    ExtractedTarget,
    RiskFactor,
)


class HTTPExtractor(BaseExtractor):
    """Extractor for HTTP/API requests."""

    tool_patterns = ["http", "api", "fetch", "request", "curl", "webhook"]

    # Sensitive URL patterns
    SENSITIVE_URL_PATTERNS = [
        r"/auth",
        r"/login",
        r"/oauth",
        r"/token",
        r"/password",
        r"/admin",
        r"/api/key",
        r"/secrets?",
        r"/credentials?",
        r"/payment",
        r"/billing",
        r"/checkout",
    ]

    # Sensitive header names
    SENSITIVE_HEADERS = [
        "authorization",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "cookie",
        "set-cookie",
        "x-csrf-token",
        "x-access-token",
    ]

    # Internal hosts
    INTERNAL_PATTERNS = [
        r"^localhost",
        r"^127\.",
        r"^0\.0\.0\.0",
        r"^192\.168\.",
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"\.local$",
        r"\.internal$",
        r"\.corp$",
        r"\.lan$",
    ]

    def extract(self, tool_name: str, args: Dict[str, Any]) -> ExtractorResult:
        """Extract context from HTTP request."""

        # Extract URL
        url = args.get("url", args.get("endpoint", ""))
        method = args.get("method", "GET").upper()

        # Parse URL
        parsed_url = urlparse(url) if url else None
        host = parsed_url.netloc if parsed_url else ""
        path = parsed_url.path if parsed_url else ""

        # Determine operation
        operation = self._classify_operation(method, path)

        # Build targets
        targets = []
        if url:
            targets.append(
                ExtractedTarget(
                    kind="url",
                    value=url,
                    normalized=url,
                    sensitive=self._is_sensitive_url(url, path),
                    internal=self._is_internal_host(host),
                    metadata={
                        "host": host,
                        "path": path,
                        "method": method,
                        "scheme": parsed_url.scheme if parsed_url else "",
                        "query_params": (
                            list(parse_qs(parsed_url.query).keys())
                            if parsed_url
                            else []
                        ),
                    },
                )
            )

        # Assess risks
        risk_factors, risk_score = self._assess_risks(method, url, host, args)

        # Determine blast radius
        blast_radius = "network"  # HTTP is always network

        # Determine reversibility
        reversibility = self._determine_reversibility(method)

        # Generate summary
        human_summary = self._generate_summary(method, url, host)

        # Check if approval needed
        requires_approval, approval_reason = self._needs_approval(
            method, url, host, targets, risk_factors, args
        )

        return ExtractorResult(
            tool_name=tool_name,
            operation=operation,
            authority_domain="network",
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

    def _classify_operation(self, method: str, path: str) -> str:
        """Classify HTTP operation."""
        method = method.upper()

        if method == "GET":
            return "read"
        elif method == "POST":
            # Check path for specific operations
            path_lower = path.lower()
            if "/auth" in path_lower or "/login" in path_lower:
                return "authenticate"
            if "/upload" in path_lower:
                return "upload"
            return "create"
        elif method == "PUT":
            return "update"
        elif method == "PATCH":
            return "modify"
        elif method == "DELETE":
            return "delete"
        elif method == "HEAD":
            return "probe"
        elif method == "OPTIONS":
            return "preflight"
        else:
            return "request"

    def _is_sensitive_url(self, url: str, path: str) -> bool:
        """Check if URL is sensitive."""
        for pattern in self.SENSITIVE_URL_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return True

        # Check URL parameters
        url_lower = url.lower()
        sensitive_params = ["api_key", "token", "password", "secret"]
        for param in sensitive_params:
            if param in url_lower:
                return True

        return False

    def _is_internal_host(self, host: str) -> bool:
        """Check if host is internal."""
        if not host:
            return True  # No host = likely local

        host_lower = host.lower()
        for pattern in self.INTERNAL_PATTERNS:
            if re.search(pattern, host_lower):
                return True

        return False

    def _assess_risks(
        self,
        method: str,
        url: str,
        host: str,
        args: Dict[str, Any],
    ) -> tuple[List[RiskFactor], int]:
        """Assess risk factors."""
        factors = []
        score = 0

        # External network
        if not self._is_internal_host(host):
            factors.append(RiskFactor.EXTERNAL_NETWORK)
            score += 20

        # Check for credentials in URL
        if any(
            pattern in url.lower()
            for pattern in ["password", "token", "api_key", "secret"]
        ):
            factors.append(RiskFactor.CREDENTIAL_EXPOSURE)
            score += 30

        # Check headers for credentials
        headers = args.get("headers", {})
        if isinstance(headers, dict):
            for header_name in headers:
                if header_name.lower() in self.SENSITIVE_HEADERS:
                    factors.append(RiskFactor.CREDENTIAL_EXPOSURE)
                    score += 15
                    break

        # Unsecured protocol
        if url.startswith("http://") and not self._is_internal_host(host):
            factors.append(RiskFactor.UNSECURED_PROTOCOL)
            score += 15

        # Data exfiltration patterns
        body = args.get("body", args.get("data", args.get("json", {})))
        if body and not self._is_internal_host(host):
            if isinstance(body, dict):
                body_str = str(body).lower()
            else:
                body_str = str(body).lower()

            exfil_patterns = ["file", "content", "data", "export", "dump"]
            if any(pattern in body_str for pattern in exfil_patterns):
                factors.append(RiskFactor.DATA_EXFILTRATION)
                score += 25

        # Method-based risk
        if method in ("DELETE", "POST", "PUT", "PATCH"):
            score += 10  # Mutation operations are riskier

        return factors, min(score, 100)

    def _determine_reversibility(self, method: str) -> str:
        """Determine reversibility based on HTTP method."""
        if method == "DELETE":
            return "irreversible"

        if method in ("PUT", "PATCH", "POST"):
            return "partial"

        return "reversible"

    def _generate_summary(self, method: str, url: str, host: str) -> str:
        """Generate human-readable summary."""
        if not url:
            return f"HTTP {method} request"

        # Truncate URL for display
        if len(url) > 60:
            url_display = url[:57] + "..."
        else:
            url_display = url

        return f"{method} {url_display}"

    def _needs_approval(
        self,
        method: str,
        url: str,
        host: str,
        targets: List[ExtractedTarget],
        risk_factors: List[RiskFactor],
        args: Dict[str, Any],
    ) -> tuple[bool, str | None]:
        """Determine if request needs approval."""

        # DELETE to external always needs approval
        if method == "DELETE" and not self._is_internal_host(host):
            return True, f"DELETE request to external host: {host}"

        # Credential exposure needs approval
        if RiskFactor.CREDENTIAL_EXPOSURE in risk_factors:
            return True, "Credential exposure detected in request"

        # Data exfiltration pattern needs approval
        if RiskFactor.DATA_EXFILTRATION in risk_factors:
            return True, "Potential data exfiltration detected"

        # POST to sensitive endpoints
        for target in targets:
            if target.sensitive and method == "POST":
                return True, f"POST to sensitive endpoint: {target.value}"

        # Unknown external hosts with mutations
        if method in ("POST", "PUT", "PATCH", "DELETE") and not self._is_internal_host(
            host
        ):
            # Check if host is in trusted list
            # For now, always require approval for external mutations
            return True, f"Mutation request to external host: {host}"

        return False, None
