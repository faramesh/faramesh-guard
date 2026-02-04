"""
SaaS Extractors module for Faramesh Guard.

Extract meaningful context from SaaS API calls (Stripe, AWS, GitHub).
"""

from .saas import (
    SaaSExtractor,
    SaaSExtractorRegistry,
    StripeExtractor,
    AWSExtractor,
    GitHubExtractor,
    ExtractedContext,
    RiskLevel,
    get_saas_extractor_registry,
    create_extractor_routes,
)

__all__ = [
    "SaaSExtractor",
    "SaaSExtractorRegistry",
    "StripeExtractor",
    "AWSExtractor",
    "GitHubExtractor",
    "ExtractedContext",
    "RiskLevel",
    "get_saas_extractor_registry",
    "create_extractor_routes",
]
