"""
Integration Layer - Connects Wow-Level Features to Main Daemon

This module provides a clean integration point for all new enterprise features:
- OPA/Rego Policy Engine
- Macaroons-Style Capability Permits
- Zanzibar Authorization Graph
- ML Risk Scorer with Abstention
- TUF Secure Updates
- Rekor Transparency Log
- Behavioral Learning

The integration is designed to be non-breaking and backward-compatible.
"""

import logging
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger("guard.integration")


class IntegrationMode(Enum):
    """Mode for integrating new features."""
    DISABLED = "disabled"  # Use legacy only
    SHADOW = "shadow"  # Run both, log differences
    ENABLED = "enabled"  # Use new features


@dataclass
class IntegratedDecision:
    """Result from integrated decision pipeline."""
    allowed: bool
    needs_approval: bool
    reason: str
    risk_level: str
    risk_score: float
    confidence: float

    # Source attribution
    policy_source: str  # "rego", "legacy", "shadow"
    signals_used: List[str]

    # Additional context
    permit_type: str  # "macaroon", "legacy"
    learned_pattern_match: Optional[str] = None
    zanzibar_check: Optional[bool] = None
    abstained: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "needs_approval": self.needs_approval,
            "reason": self.reason,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "policy_source": self.policy_source,
            "signals_used": self.signals_used,
            "permit_type": self.permit_type,
            "learned_pattern_match": self.learned_pattern_match,
            "zanzibar_check": self.zanzibar_check,
            "abstained": self.abstained
        }


class GuardIntegration:
    """
    Main integration class that orchestrates all wow-level features.

    This can be used in shadow mode to compare new vs legacy decisions,
    or in enabled mode to use the new features directly.
    """

    def __init__(self, mode: IntegrationMode = IntegrationMode.SHADOW):
        self.mode = mode

        # Lazily loaded components
        self._rego_engine = None
        self._macaroon_minter = None
        self._macaroon_validator = None
        self._zanzibar = None
        self._risk_scorer = None
        self._tuf_client = None
        self._transparency_logger = None
        self._behavioral_learner = None

        self._initialized = False

    def initialize(self) -> bool:
        """Initialize all components. Returns True if successful."""
        if self._initialized:
            return True

        try:
            # Import and initialize components
            from service.policy.rego_engine import get_opa_engine
            from service.capability.macaroons import get_macaroon_minter, get_macaroon_validator
            from service.auth.zanzibar import get_zanzibar_authorizer
            from service.ml.risk_scorer import get_ml_risk_scorer
            from service.update.tuf_client import get_tuf_client
            from service.transparency.rekor import get_transparency_logger
            from service.learning.behavioral import get_behavioral_learner

            self._rego_engine = get_opa_engine()
            self._macaroon_minter = get_macaroon_minter()
            self._macaroon_validator = get_macaroon_validator()
            self._zanzibar = get_zanzibar_authorizer()
            self._risk_scorer = get_ml_risk_scorer()
            self._tuf_client = get_tuf_client()
            self._transparency_logger = get_transparency_logger()
            self._behavioral_learner = get_behavioral_learner()

            self._initialized = True
            logger.info("GuardIntegration initialized successfully")
            return True

        except Exception as e:
            logger.warning(f"GuardIntegration initialization failed: {e}")
            self._initialized = False
            return False

    def evaluate(
        self,
        tool_name: str,
        args: Dict[str, Any],
        agent_id: str,
        car_hash: str,
        context: Optional[Dict[str, Any]] = None
    ) -> IntegratedDecision:
        """
        Evaluate using integrated pipeline.

        Pipeline:
        1. Check learned patterns (behavioral)
        2. Zanzibar authorization check
        3. OPA/Rego policy evaluation
        4. ML risk scoring with abstention
        5. Final decision
        """
        if not self._initialized:
            if not self.initialize():
                # Fallback to basic decision
                return IntegratedDecision(
                    allowed=False,
                    needs_approval=True,
                    reason="integration_not_initialized",
                    risk_level="medium",
                    risk_score=0.5,
                    confidence=0.5,
                    policy_source="fallback",
                    signals_used=[],
                    permit_type="legacy"
                )

        signals_used = []
        now = datetime.utcnow().isoformat() + "Z"

        # Build CAR for pattern matching
        car = {
            "tool": tool_name,
            "args": args,
            "agent_id": agent_id,
            "car_hash": car_hash,
            "context": context or {},
            "destination": args.get("url", args.get("recipient", "")),
            "target": args.get("path", args.get("file", "")),
            "operation": args.get("operation", "execute"),
            "timestamp": now
        }

        # 1. Check learned patterns
        learned_match = None
        if self._behavioral_learner:
            pattern = self._behavioral_learner.check_learned_patterns(car)
            if pattern and pattern.auto_apply:
                learned_match = pattern.pattern_id
                signals_used.append("learned_pattern")
                logger.debug(f"Matched learned pattern: {pattern.pattern_id}")

        # 2. Zanzibar authorization check
        zanzibar_allowed = None
        if self._zanzibar:
            try:
                result = self._zanzibar.check(
                    subject=f"agent:{agent_id}",
                    relation="can_execute",
                    object=f"tool:{tool_name}"
                )
                zanzibar_allowed = result.allowed
                signals_used.append("zanzibar")
            except Exception as e:
                logger.debug(f"Zanzibar check failed: {e}")

        # 3. OPA/Rego policy evaluation
        rego_allowed = None
        rego_reason = ""
        if self._rego_engine:
            try:
                rego_input = {
                    "car": car,
                    "agent": {"id": agent_id},
                    "context": context or {}
                }
                result = self._rego_engine.evaluate(rego_input)
                rego_allowed = result.allowed
                rego_reason = result.reason
                signals_used.append("rego_policy")
            except Exception as e:
                logger.debug(f"Rego evaluation failed: {e}")

        # 4. ML risk scoring with abstention
        risk_score = 0.5
        risk_confidence = 0.5
        abstained = False
        if self._risk_scorer:
            try:
                features = {
                    "tool": tool_name,
                    "args": args,
                    "agent_id": agent_id,
                    "context": context or {}
                }
                result = self._risk_scorer.score(features)
                risk_score = result.risk_score
                risk_confidence = result.confidence
                abstained = result.abstained
                signals_used.append("ml_risk")
            except Exception as e:
                logger.debug(f"ML risk scoring failed: {e}")

        # 5. Combine signals for final decision
        # Priority: Learned patterns > Zanzibar > Rego > Risk

        allowed = False
        needs_approval = False
        reason = ""

        # If learned pattern matches with auto-apply, allow
        if learned_match:
            allowed = True
            reason = f"learned_pattern:{learned_match}"
        # If Zanzibar explicitly denies, deny
        elif zanzibar_allowed is False:
            allowed = False
            reason = "zanzibar_denied"
        # If Rego has a decision, use it
        elif rego_allowed is not None:
            allowed = rego_allowed
            reason = rego_reason or ("rego_allowed" if rego_allowed else "rego_denied")
        # If ML abstained, need approval
        elif abstained:
            allowed = False
            needs_approval = True
            reason = f"ml_abstained:score={risk_score:.2f}"
        # High risk -> need approval
        elif risk_score > 0.7:
            allowed = False
            needs_approval = True
            reason = f"high_risk:score={risk_score:.2f}"
        # Default: allow with monitoring
        else:
            allowed = True
            reason = "allowed_with_monitoring"

        # Determine risk level from score
        if risk_score > 0.8:
            risk_level = "critical"
        elif risk_score > 0.6:
            risk_level = "high"
        elif risk_score > 0.3:
            risk_level = "medium"
        else:
            risk_level = "low"

        return IntegratedDecision(
            allowed=allowed,
            needs_approval=needs_approval,
            reason=reason,
            risk_level=risk_level,
            risk_score=risk_score,
            confidence=risk_confidence,
            policy_source="rego" if rego_allowed is not None else "integrated",
            signals_used=signals_used,
            permit_type="macaroon" if self._macaroon_minter else "legacy",
            learned_pattern_match=learned_match,
            zanzibar_check=zanzibar_allowed,
            abstained=abstained
        )

    def mint_permit(
        self,
        car_hash: str,
        agent_id: str,
        tool: str,
        operation: str,
        caveats: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 120
    ) -> Dict[str, Any]:
        """
        Mint a capability permit using Macaroons if available.
        Falls back to legacy permit otherwise.
        """
        if self._macaroon_minter and self._initialized:
            try:
                from service.capability.macaroons import Caveat, CaveatOperator

                caveat_list = []
                if caveats:
                    if caveats.get("tool"):
                        caveat_list.append(Caveat(
                            key="tool",
                            operator=CaveatOperator.EQUALS,
                            value=caveats["tool"]
                        ))
                    if caveats.get("max_uses"):
                        caveat_list.append(Caveat(
                            key="use_count",
                            operator=CaveatOperator.LESS_THAN_OR_EQUAL,
                            value=caveats["max_uses"]
                        ))

                permit = self._macaroon_minter.mint(
                    holder_id=agent_id,
                    resource=f"tool:{tool}",
                    action=operation,
                    caveats=caveat_list,
                    ttl_seconds=ttl_seconds,
                    metadata={"car_hash": car_hash}
                )

                return {
                    "permit_type": "macaroon",
                    "permit_id": permit.permit_id,
                    "signature": permit.signature,
                    "serialized": permit.serialize(),
                    "car_hash": car_hash,
                    "ttl": ttl_seconds,
                    "issued_at": permit.issued_at
                }
            except Exception as e:
                logger.warning(f"Macaroon minting failed, falling back: {e}")

        # Fallback to returning info for legacy minting
        return {
            "permit_type": "legacy",
            "car_hash": car_hash,
            "ttl": ttl_seconds,
            "issued_at": datetime.utcnow().isoformat() + "Z"
        }

    def validate_permit(self, permit_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate a capability permit.

        Returns: (valid, reason)
        """
        if permit_data.get("permit_type") == "macaroon":
            if self._macaroon_validator and self._initialized:
                try:
                    from service.capability.macaroons import MacaroonPermit

                    # Deserialize and validate
                    if "serialized" in permit_data:
                        permit = MacaroonPermit.deserialize(permit_data["serialized"])
                        result = self._macaroon_validator.validate(permit, {})
                        return result.valid, result.reason
                except Exception as e:
                    return False, f"macaroon_validation_error: {e}"

        # Legacy validation should be handled by caller
        return True, "legacy_permit"

    def log_transparency(
        self,
        action_id: str,
        event_type: str,
        decision: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        Log to transparency log for cryptographic audit.

        Returns: Entry ID if logged, None otherwise
        """
        if self._transparency_logger and self._initialized:
            try:
                entry = self._transparency_logger.log(
                    action_id=action_id,
                    event_type=event_type,
                    decision=decision,
                    metadata=metadata or {}
                )
                return entry.entry_id
            except Exception as e:
                logger.warning(f"Transparency logging failed: {e}")
        return None

    def on_approval(self, car: Dict[str, Any], decision: str) -> None:
        """
        Process approval for behavioral learning.

        Called when user approves/denies an action.
        """
        if self._behavioral_learner and self._initialized:
            try:
                self._behavioral_learner.on_approval(car, decision)
            except Exception as e:
                logger.warning(f"Behavioral learning failed: {e}")

    def check_for_updates(self) -> Dict[str, Any]:
        """
        Check for secure updates using TUF.

        Returns update status and available updates.
        """
        if self._tuf_client and self._initialized:
            try:
                return self._tuf_client.check_for_updates()
            except Exception as e:
                logger.warning(f"TUF update check failed: {e}")

        return {"updates_available": False, "error": "tuf_not_available"}

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics from all integrated components."""
        stats = {
            "mode": self.mode.value,
            "initialized": self._initialized,
            "components": {}
        }

        if self._behavioral_learner:
            try:
                stats["components"]["learning"] = self._behavioral_learner.get_stats()
            except:
                pass

        if self._risk_scorer:
            try:
                stats["components"]["risk_scorer"] = self._risk_scorer.get_stats()
            except:
                pass

        if self._zanzibar:
            try:
                stats["components"]["zanzibar"] = self._zanzibar.get_stats()
            except:
                pass

        return stats


# Singleton instance
_integration: Optional[GuardIntegration] = None


def get_integration(mode: IntegrationMode = IntegrationMode.SHADOW) -> GuardIntegration:
    """Get singleton integration instance."""
    global _integration
    if _integration is None:
        _integration = GuardIntegration(mode=mode)
    return _integration
