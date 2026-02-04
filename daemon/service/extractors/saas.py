"""
SaaS Extractors for Faramesh Guard.

Extract meaningful context from SaaS API calls to enhance
risk assessment and provide better user prompts.
"""

import asyncio
import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Pattern, Tuple

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    """Risk level for extracted operations."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ExtractedContext:
    """Context extracted from a SaaS API call."""

    service: str
    operation: str
    description: str
    risk_level: str = RiskLevel.MEDIUM.value

    # Resource info
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None

    # Additional context
    metadata: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    # Monetary impact
    estimated_cost: Optional[float] = None
    currency: str = "USD"

    # Scope
    affects_production: bool = False
    is_destructive: bool = False
    is_irreversible: bool = False


class SaaSExtractor(ABC):
    """Base class for SaaS API extractors."""

    @property
    @abstractmethod
    def service_name(self) -> str:
        """Name of the SaaS service."""
        pass

    @property
    @abstractmethod
    def url_patterns(self) -> List[Pattern]:
        """URL patterns to match for this service."""
        pass

    @abstractmethod
    def extract(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[Dict[str, Any]],
    ) -> Optional[ExtractedContext]:
        """Extract context from API call."""
        pass

    def matches_url(self, url: str) -> bool:
        """Check if URL matches this extractor."""
        return any(p.search(url) for p in self.url_patterns)


class StripeExtractor(SaaSExtractor):
    """Extract context from Stripe API calls."""

    @property
    def service_name(self) -> str:
        return "stripe"

    @property
    def url_patterns(self) -> List[Pattern]:
        return [
            re.compile(r"api\.stripe\.com"),
        ]

    # Operation patterns
    OPERATIONS = {
        # Charges
        (r"/v1/charges$", "POST"): ("create_charge", "Create a charge", RiskLevel.HIGH),
        (r"/v1/charges/(\w+)/capture", "POST"): (
            "capture_charge",
            "Capture a charge",
            RiskLevel.HIGH,
        ),
        (r"/v1/charges/(\w+)/refund", "POST"): (
            "refund_charge",
            "Refund a charge",
            RiskLevel.MEDIUM,
        ),
        # Payment Intents
        (r"/v1/payment_intents$", "POST"): (
            "create_payment_intent",
            "Create payment intent",
            RiskLevel.HIGH,
        ),
        (r"/v1/payment_intents/(\w+)/confirm", "POST"): (
            "confirm_payment",
            "Confirm payment",
            RiskLevel.CRITICAL,
        ),
        (r"/v1/payment_intents/(\w+)/cancel", "POST"): (
            "cancel_payment",
            "Cancel payment intent",
            RiskLevel.MEDIUM,
        ),
        # Subscriptions
        (r"/v1/subscriptions$", "POST"): (
            "create_subscription",
            "Create subscription",
            RiskLevel.HIGH,
        ),
        (r"/v1/subscriptions/(\w+)$", "DELETE"): (
            "cancel_subscription",
            "Cancel subscription",
            RiskLevel.MEDIUM,
        ),
        (r"/v1/subscriptions/(\w+)$", "POST"): (
            "update_subscription",
            "Update subscription",
            RiskLevel.MEDIUM,
        ),
        # Customers
        (r"/v1/customers$", "POST"): (
            "create_customer",
            "Create customer",
            RiskLevel.LOW,
        ),
        (r"/v1/customers/(\w+)$", "DELETE"): (
            "delete_customer",
            "Delete customer",
            RiskLevel.HIGH,
        ),
        # Invoices
        (r"/v1/invoices/(\w+)/pay", "POST"): (
            "pay_invoice",
            "Pay invoice",
            RiskLevel.HIGH,
        ),
        (r"/v1/invoices/(\w+)/void", "POST"): (
            "void_invoice",
            "Void invoice",
            RiskLevel.MEDIUM,
        ),
        # Payouts
        (r"/v1/payouts$", "POST"): (
            "create_payout",
            "Create payout",
            RiskLevel.CRITICAL,
        ),
        (r"/v1/payouts/(\w+)/cancel", "POST"): (
            "cancel_payout",
            "Cancel payout",
            RiskLevel.MEDIUM,
        ),
        # Transfers
        (r"/v1/transfers$", "POST"): (
            "create_transfer",
            "Create transfer",
            RiskLevel.CRITICAL,
        ),
        # Account
        (r"/v1/account$", "DELETE"): (
            "delete_account",
            "Delete account",
            RiskLevel.CRITICAL,
        ),
    }

    def extract(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[Dict[str, Any]],
    ) -> Optional[ExtractedContext]:
        """Extract context from Stripe API call."""
        body = body or {}

        for (pattern, op_method), (op_name, desc, risk) in self.OPERATIONS.items():
            if method.upper() == op_method:
                match = re.search(pattern, url)
                if match:
                    context = ExtractedContext(
                        service="stripe",
                        operation=op_name,
                        description=desc,
                        risk_level=risk.value,
                    )

                    # Extract resource ID if captured
                    if match.groups():
                        context.resource_id = match.group(1)

                    # Extract amount
                    if "amount" in body:
                        amount = body["amount"]
                        currency = body.get("currency", "usd").upper()
                        context.estimated_cost = amount / 100  # Stripe uses cents
                        context.currency = currency
                        context.metadata["amount"] = f"{amount / 100:.2f} {currency}"

                    # Check for live mode
                    auth = headers.get("Authorization", "")
                    if "sk_live" in auth:
                        context.affects_production = True
                        context.warnings.append("LIVE MODE - Real money transaction")
                    elif "sk_test" in auth:
                        context.metadata["mode"] = "test"

                    # Mark destructive operations
                    if op_name in ["delete_customer", "delete_account", "void_invoice"]:
                        context.is_destructive = True

                    if op_name in [
                        "create_payout",
                        "create_transfer",
                        "confirm_payment",
                    ]:
                        context.is_irreversible = True

                    return context

        # Default for unrecognized Stripe calls
        return ExtractedContext(
            service="stripe",
            operation="unknown",
            description=f"Stripe API call: {method} {url}",
            risk_level=RiskLevel.MEDIUM.value,
        )


class AWSExtractor(SaaSExtractor):
    """Extract context from AWS API calls."""

    @property
    def service_name(self) -> str:
        return "aws"

    @property
    def url_patterns(self) -> List[Pattern]:
        return [
            re.compile(r"\.amazonaws\.com"),
            re.compile(r"aws\.amazon\.com"),
        ]

    # High-risk AWS services and operations
    HIGH_RISK_SERVICES = {
        "iam",
        "kms",
        "organizations",
        "sts",
        "secretsmanager",
    }

    DESTRUCTIVE_OPERATIONS = {
        "Delete",
        "Remove",
        "Terminate",
        "Destroy",
        "Deregister",
        "Disable",
        "Revoke",
        "Purge",
    }

    CRITICAL_OPERATIONS = {
        # IAM
        ("iam", "CreateUser"): ("create_iam_user", "Create IAM user"),
        ("iam", "DeleteUser"): ("delete_iam_user", "Delete IAM user"),
        ("iam", "CreateAccessKey"): ("create_access_key", "Create access key"),
        ("iam", "AttachUserPolicy"): ("attach_policy", "Attach policy to user"),
        ("iam", "CreateRole"): ("create_role", "Create IAM role"),
        # EC2
        ("ec2", "TerminateInstances"): (
            "terminate_instances",
            "Terminate EC2 instances",
        ),
        ("ec2", "DeleteSecurityGroup"): ("delete_sg", "Delete security group"),
        ("ec2", "AuthorizeSecurityGroupIngress"): (
            "open_sg_ingress",
            "Open security group ingress",
        ),
        ("ec2", "DeleteVolume"): ("delete_volume", "Delete EBS volume"),
        # S3
        ("s3", "DeleteBucket"): ("delete_bucket", "Delete S3 bucket"),
        ("s3", "PutBucketPolicy"): ("set_bucket_policy", "Set bucket policy"),
        ("s3", "DeleteObject"): ("delete_object", "Delete S3 object"),
        # RDS
        ("rds", "DeleteDBInstance"): ("delete_db", "Delete RDS instance"),
        ("rds", "DeleteDBCluster"): ("delete_cluster", "Delete RDS cluster"),
        ("rds", "ModifyDBInstance"): ("modify_db", "Modify RDS instance"),
        # Lambda
        ("lambda", "DeleteFunction"): ("delete_lambda", "Delete Lambda function"),
        ("lambda", "UpdateFunctionCode"): ("update_lambda", "Update Lambda code"),
        # CloudFormation
        ("cloudformation", "DeleteStack"): (
            "delete_stack",
            "Delete CloudFormation stack",
        ),
        ("cloudformation", "CreateStack"): (
            "create_stack",
            "Create CloudFormation stack",
        ),
        # Secrets Manager
        ("secretsmanager", "DeleteSecret"): ("delete_secret", "Delete secret"),
        ("secretsmanager", "PutSecretValue"): ("update_secret", "Update secret value"),
        # KMS
        ("kms", "ScheduleKeyDeletion"): (
            "schedule_key_delete",
            "Schedule KMS key deletion",
        ),
        ("kms", "DisableKey"): ("disable_key", "Disable KMS key"),
    }

    def extract(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[Dict[str, Any]],
    ) -> Optional[ExtractedContext]:
        """Extract context from AWS API call."""
        body = body or {}

        # Extract service from URL
        service_match = re.search(r"([a-z0-9-]+)\.([a-z0-9-]+)?\.?amazonaws\.com", url)
        if not service_match:
            return None

        service = service_match.group(1)
        region = service_match.group(2) if service_match.group(2) else "global"

        # Extract action from headers or body
        action = None
        if "x-amz-target" in headers:
            target = headers["x-amz-target"]
            action = target.split(".")[-1] if "." in target else target
        elif "Action" in body:
            action = body["Action"]

        # Check for known critical operations
        if action:
            key = (service, action)
            if key in self.CRITICAL_OPERATIONS:
                op_name, desc = self.CRITICAL_OPERATIONS[key]

                risk = (
                    RiskLevel.CRITICAL
                    if service in self.HIGH_RISK_SERVICES
                    else RiskLevel.HIGH
                )

                context = ExtractedContext(
                    service="aws",
                    operation=op_name,
                    description=f"{desc} ({service})",
                    risk_level=risk.value,
                    resource_type=service,
                    metadata={
                        "aws_service": service,
                        "aws_action": action,
                        "region": region,
                    },
                )

                # Check for destructive
                if any(d in action for d in self.DESTRUCTIVE_OPERATIONS):
                    context.is_destructive = True

                # Extract resource IDs from body
                for key, value in body.items():
                    if "Id" in key or "Name" in key or "Arn" in key:
                        context.resource_id = str(value)
                        break

                # Production warning
                if region not in ["us-east-1-test", "local"]:
                    context.affects_production = True
                    context.warnings.append(f"Production region: {region}")

                return context

        # Default for unrecognized AWS calls
        risk = (
            RiskLevel.HIGH if service in self.HIGH_RISK_SERVICES else RiskLevel.MEDIUM
        )

        return ExtractedContext(
            service="aws",
            operation=f"{service}:{action or 'unknown'}",
            description=f"AWS {service} API call",
            risk_level=risk.value,
            resource_type=service,
            metadata={
                "aws_service": service,
                "aws_action": action,
                "region": region,
            },
        )


class GitHubExtractor(SaaSExtractor):
    """Extract context from GitHub API calls."""

    @property
    def service_name(self) -> str:
        return "github"

    @property
    def url_patterns(self) -> List[Pattern]:
        return [
            re.compile(r"api\.github\.com"),
        ]

    # Operation patterns
    OPERATIONS = {
        # Repositories
        (r"/repos/([^/]+)/([^/]+)$", "DELETE"): (
            "delete_repo",
            "Delete repository",
            RiskLevel.CRITICAL,
        ),
        (r"/repos/([^/]+)/([^/]+)$", "PATCH"): (
            "update_repo",
            "Update repository settings",
            RiskLevel.MEDIUM,
        ),
        (r"/repos/([^/]+)/([^/]+)/transfer", "POST"): (
            "transfer_repo",
            "Transfer repository",
            RiskLevel.CRITICAL,
        ),
        # Branches
        (r"/repos/([^/]+)/([^/]+)/git/refs/heads/", "DELETE"): (
            "delete_branch",
            "Delete branch",
            RiskLevel.HIGH,
        ),
        (r"/repos/([^/]+)/([^/]+)/branches/([^/]+)/protection", "DELETE"): (
            "remove_protection",
            "Remove branch protection",
            RiskLevel.CRITICAL,
        ),
        (r"/repos/([^/]+)/([^/]+)/branches/([^/]+)/protection", "PUT"): (
            "set_protection",
            "Set branch protection",
            RiskLevel.MEDIUM,
        ),
        # Collaborators
        (r"/repos/([^/]+)/([^/]+)/collaborators/([^/]+)", "PUT"): (
            "add_collaborator",
            "Add collaborator",
            RiskLevel.HIGH,
        ),
        (r"/repos/([^/]+)/([^/]+)/collaborators/([^/]+)", "DELETE"): (
            "remove_collaborator",
            "Remove collaborator",
            RiskLevel.MEDIUM,
        ),
        # Secrets
        (r"/repos/([^/]+)/([^/]+)/actions/secrets/", "PUT"): (
            "set_secret",
            "Set repository secret",
            RiskLevel.HIGH,
        ),
        (r"/repos/([^/]+)/([^/]+)/actions/secrets/", "DELETE"): (
            "delete_secret",
            "Delete repository secret",
            RiskLevel.MEDIUM,
        ),
        # Deployments
        (r"/repos/([^/]+)/([^/]+)/deployments$", "POST"): (
            "create_deployment",
            "Create deployment",
            RiskLevel.HIGH,
        ),
        # Webhooks
        (r"/repos/([^/]+)/([^/]+)/hooks$", "POST"): (
            "create_webhook",
            "Create webhook",
            RiskLevel.MEDIUM,
        ),
        (r"/repos/([^/]+)/([^/]+)/hooks/", "DELETE"): (
            "delete_webhook",
            "Delete webhook",
            RiskLevel.LOW,
        ),
        # Releases
        (r"/repos/([^/]+)/([^/]+)/releases$", "POST"): (
            "create_release",
            "Create release",
            RiskLevel.MEDIUM,
        ),
        (r"/repos/([^/]+)/([^/]+)/releases/", "DELETE"): (
            "delete_release",
            "Delete release",
            RiskLevel.MEDIUM,
        ),
        # Organization
        (r"/orgs/([^/]+)/members/([^/]+)", "DELETE"): (
            "remove_org_member",
            "Remove organization member",
            RiskLevel.HIGH,
        ),
        (r"/orgs/([^/]+)/teams$", "POST"): (
            "create_team",
            "Create team",
            RiskLevel.MEDIUM,
        ),
        (r"/orgs/([^/]+)/teams/([^/]+)", "DELETE"): (
            "delete_team",
            "Delete team",
            RiskLevel.HIGH,
        ),
        # User
        (r"/user/keys$", "POST"): ("add_ssh_key", "Add SSH key", RiskLevel.HIGH),
        (r"/user/keys/", "DELETE"): (
            "delete_ssh_key",
            "Delete SSH key",
            RiskLevel.MEDIUM,
        ),
    }

    def extract(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[Dict[str, Any]],
    ) -> Optional[ExtractedContext]:
        """Extract context from GitHub API call."""
        body = body or {}

        for (pattern, op_method), (op_name, desc, risk) in self.OPERATIONS.items():
            if method.upper() == op_method:
                match = re.search(pattern, url)
                if match:
                    context = ExtractedContext(
                        service="github",
                        operation=op_name,
                        description=desc,
                        risk_level=risk.value,
                    )

                    # Extract org/repo from captures
                    groups = match.groups()
                    if len(groups) >= 2:
                        context.metadata["owner"] = groups[0]
                        context.metadata["repo"] = groups[1]
                        context.resource_name = f"{groups[0]}/{groups[1]}"
                    if len(groups) >= 3:
                        context.resource_id = groups[2]

                    # Mark destructive
                    if "delete" in op_name or op_name in [
                        "remove_protection",
                        "transfer_repo",
                    ]:
                        context.is_destructive = True

                    # Check for main/master branch operations
                    if "main" in url or "master" in url:
                        context.warnings.append("Operation on main/master branch")
                        context.affects_production = True

                    return context

        # Default for unrecognized GitHub calls
        return ExtractedContext(
            service="github",
            operation="unknown",
            description=f"GitHub API call: {method} {url}",
            risk_level=RiskLevel.LOW.value,
        )


class SaaSExtractorRegistry:
    """
    Registry of SaaS extractors.

    Manages all extractors and routes API calls to the appropriate one.
    """

    def __init__(self):
        self._extractors: List[SaaSExtractor] = []
        self._init_default_extractors()

        logger.info("SaaSExtractorRegistry initialized")

    def _init_default_extractors(self):
        """Initialize default extractors."""
        self._extractors = [
            StripeExtractor(),
            AWSExtractor(),
            GitHubExtractor(),
        ]

    def register(self, extractor: SaaSExtractor):
        """Register a custom extractor."""
        self._extractors.append(extractor)

    def extract(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[Dict[str, Any]] = None,
    ) -> Optional[ExtractedContext]:
        """
        Extract context from an API call.

        Routes to the appropriate extractor based on URL.
        """
        for extractor in self._extractors:
            if extractor.matches_url(url):
                return extractor.extract(method, url, headers, body)

        return None

    def get_supported_services(self) -> List[str]:
        """Get list of supported services."""
        return [e.service_name for e in self._extractors]


# Singleton
_registry: Optional[SaaSExtractorRegistry] = None


def get_saas_extractor_registry() -> SaaSExtractorRegistry:
    global _registry
    if _registry is None:
        _registry = SaaSExtractorRegistry()
    return _registry


def create_extractor_routes():
    """Create FastAPI routes for SaaS extraction."""
    from fastapi import APIRouter
    from pydantic import BaseModel
    from typing import Optional, Dict, Any

    router = APIRouter(prefix="/api/v1/guard/extract", tags=["extractors"])

    class ExtractRequest(BaseModel):
        method: str
        url: str
        headers: Dict[str, str] = {}
        body: Optional[Dict[str, Any]] = None

    @router.post("/context")
    async def extract_context(request: ExtractRequest):
        """Extract context from SaaS API call."""
        registry = get_saas_extractor_registry()

        context = registry.extract(
            method=request.method,
            url=request.url,
            headers=request.headers,
            body=request.body,
        )

        if context:
            from dataclasses import asdict

            return {
                "extracted": True,
                "context": asdict(context),
            }

        return {"extracted": False}

    @router.get("/services")
    async def list_services():
        """List supported SaaS services."""
        registry = get_saas_extractor_registry()
        return {"services": registry.get_supported_services()}

    return router
