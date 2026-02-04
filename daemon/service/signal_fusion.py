"""
Signal Fusion Engine

Combines multiple security signals into a unified decision:
1. ML Risk Score (from ML models)
2. Policy Evaluation (OPA/Rego or YAML rules)
3. Adversarial Detection (prompt injection, obfuscation)
4. Behavioral Anomaly (from anomaly detector)

Following plan-farameshGuardV1Enhanced.prompt.md:
- Weighted signal combination
- Priority-based override logic
- Confidence scoring
- Explainable decisions
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class SignalSource(Enum):
    """Sources of security signals"""

    ML_RISK = "ml_risk"
    POLICY = "policy"
    ADVERSARIAL = "adversarial"
    BEHAVIORAL = "behavioral"
    HUMAN_OVERRIDE = "human_override"


class Decision(Enum):
    """Final decision outcomes"""

    ALLOW = "ALLOW"
    DENY = "DENY"
    ABSTAIN = "ABSTAIN"  # Needs human approval


@dataclass
class SecuritySignal:
    """A single security signal"""

    source: SignalSource
    score: float  # 0.0 (safe) to 1.0 (dangerous)
    confidence: float  # 0.0 to 1.0
    reason: str
    evidence: Dict[str, Any]
    timestamp: Optional[datetime] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

    @property
    def weighted_score(self) -> float:
        """Score weighted by confidence"""
        return self.score * self.confidence


@dataclass
class FusedDecision:
    """Result of signal fusion"""

    decision: Decision
    final_score: float  # Combined risk score 0.0-1.0
    confidence: float  # Decision confidence 0.0-1.0
    reason: str
    reason_code: str
    contributing_signals: List[SecuritySignal]
    explanation: Dict[str, Any]
    timestamp: Optional[datetime] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class SignalFusionEngine:
    """
    Combines multiple security signals into a unified decision.

    Uses weighted averaging with priority overrides:
    - High-confidence DENY from any source → DENY
    - High-confidence ALLOW from all sources → ALLOW
    - Mixed signals or low confidence → ABSTAIN
    """

    def __init__(
        self,
        weights: Optional[Dict[SignalSource, float]] = None,
        deny_threshold: float = 0.7,
        allow_threshold: float = 0.3,
        confidence_threshold: float = 0.6,
    ):
        # Default weights (must sum to 1.0)
        self.weights = weights or {
            SignalSource.ML_RISK: 0.3,
            SignalSource.POLICY: 0.4,
            SignalSource.ADVERSARIAL: 0.2,
            SignalSource.BEHAVIORAL: 0.1,
            SignalSource.HUMAN_OVERRIDE: 1.0,  # Always override
        }

        self.deny_threshold = deny_threshold
        self.allow_threshold = allow_threshold
        self.confidence_threshold = confidence_threshold

        # Statistics
        self._decision_count = 0
        self._decision_breakdown = {
            Decision.ALLOW: 0,
            Decision.DENY: 0,
            Decision.ABSTAIN: 0,
        }

    def fuse_signals(self, signals: List[SecuritySignal]) -> FusedDecision:
        """
        Fuse multiple signals into a single decision.

        Args:
            signals: List of security signals from different sources

        Returns:
            Unified decision with explanation
        """
        if not signals:
            return FusedDecision(
                decision=Decision.DENY,
                final_score=1.0,
                confidence=1.0,
                reason="No security signals provided - fail closed",
                reason_code="NO_SIGNALS_FAIL_CLOSED",
                contributing_signals=[],
                explanation={"error": "No signals"},
            )

        # Check for human override first
        human_override = self._check_human_override(signals)
        if human_override:
            return human_override

        # Check for high-confidence deny (any source)
        high_conf_deny = self._check_high_confidence_deny(signals)
        if high_conf_deny:
            return high_conf_deny

        # Compute weighted average
        final_score, avg_confidence = self._compute_weighted_average(signals)

        # Make decision based on thresholds
        decision = self._threshold_decision(final_score, avg_confidence)

        # Generate explanation
        explanation = self._generate_explanation(signals, final_score, avg_confidence)

        # Create result
        result = FusedDecision(
            decision=decision,
            final_score=final_score,
            confidence=avg_confidence,
            reason=explanation["reason"],
            reason_code=explanation["reason_code"],
            contributing_signals=signals,
            explanation=explanation,
        )

        # Update stats
        self._decision_count += 1
        self._decision_breakdown[decision] += 1

        logger.info(
            f"Signal fusion: {decision.value} "
            f"(score: {final_score:.2f}, confidence: {avg_confidence:.2f})"
        )

        return result

    def _check_human_override(
        self, signals: List[SecuritySignal]
    ) -> Optional[FusedDecision]:
        """Check for human override signal"""
        for signal in signals:
            if signal.source == SignalSource.HUMAN_OVERRIDE:
                decision = Decision.ALLOW if signal.score < 0.5 else Decision.DENY

                return FusedDecision(
                    decision=decision,
                    final_score=signal.score,
                    confidence=1.0,
                    reason=f"Human override: {signal.reason}",
                    reason_code="HUMAN_OVERRIDE",
                    contributing_signals=[signal],
                    explanation={
                        "override": True,
                        "approver": signal.evidence.get("approver", "unknown"),
                    },
                )

        return None

    def _check_high_confidence_deny(
        self, signals: List[SecuritySignal]
    ) -> Optional[FusedDecision]:
        """Check for any high-confidence deny signal"""
        for signal in signals:
            if (
                signal.score >= self.deny_threshold
                and signal.confidence >= self.confidence_threshold
            ):
                return FusedDecision(
                    decision=Decision.DENY,
                    final_score=signal.score,
                    confidence=signal.confidence,
                    reason=f"High-confidence risk detected: {signal.reason}",
                    reason_code=f"HIGH_RISK_{signal.source.value.upper()}",
                    contributing_signals=[signal],
                    explanation={
                        "trigger_source": signal.source.value,
                        "trigger_score": signal.score,
                        "trigger_confidence": signal.confidence,
                    },
                )

        return None

    def _compute_weighted_average(
        self, signals: List[SecuritySignal]
    ) -> Tuple[float, float]:
        """Compute weighted average of signals"""
        total_weight = 0.0
        weighted_sum = 0.0
        confidence_sum = 0.0
        count = 0

        for signal in signals:
            if signal.source == SignalSource.HUMAN_OVERRIDE:
                continue  # Already handled

            weight = self.weights.get(signal.source, 0.1)
            weighted_sum += signal.weighted_score * weight
            total_weight += weight
            confidence_sum += signal.confidence
            count += 1

        if total_weight == 0 or count == 0:
            return 0.5, 0.5  # Neutral

        final_score = weighted_sum / total_weight
        avg_confidence = confidence_sum / count

        return final_score, avg_confidence

    def _threshold_decision(self, score: float, confidence: float) -> Decision:
        """Apply thresholds to make decision"""

        # Low confidence → ABSTAIN
        if confidence < self.confidence_threshold:
            return Decision.ABSTAIN

        # High score → DENY
        if score >= self.deny_threshold:
            return Decision.DENY

        # Low score → ALLOW
        if score <= self.allow_threshold:
            return Decision.ALLOW

        # Middle ground → ABSTAIN
        return Decision.ABSTAIN

    def _generate_explanation(
        self, signals: List[SecuritySignal], final_score: float, confidence: float
    ) -> Dict[str, Any]:
        """Generate human-readable explanation"""

        # Determine decision
        if confidence < self.confidence_threshold:
            reason = f"Low confidence ({confidence:.2f}) - human review recommended"
            reason_code = "LOW_CONFIDENCE_ABSTAIN"
        elif final_score >= self.deny_threshold:
            reason = f"High risk score ({final_score:.2f}) - action denied"
            reason_code = "HIGH_RISK_DENY"
        elif final_score <= self.allow_threshold:
            reason = f"Low risk score ({final_score:.2f}) - action allowed"
            reason_code = "LOW_RISK_ALLOW"
        else:
            reason = f"Moderate risk ({final_score:.2f}) - human review recommended"
            reason_code = "MODERATE_RISK_ABSTAIN"

        # Break down by source
        signal_breakdown = {}
        for signal in signals:
            signal_breakdown[signal.source.value] = {
                "score": signal.score,
                "confidence": signal.confidence,
                "weighted_score": signal.weighted_score,
                "reason": signal.reason,
            }

        return {
            "reason": reason,
            "reason_code": reason_code,
            "final_score": final_score,
            "confidence": confidence,
            "thresholds": {
                "deny": self.deny_threshold,
                "allow": self.allow_threshold,
                "confidence": self.confidence_threshold,
            },
            "signal_breakdown": signal_breakdown,
            "signal_count": len(signals),
        }

    def add_ml_risk_signal(
        self,
        risk_score: float,
        confidence: float,
        model_name: str,
        features: Dict[str, Any],
    ) -> SecuritySignal:
        """Helper to create ML risk signal"""
        return SecuritySignal(
            source=SignalSource.ML_RISK,
            score=risk_score,
            confidence=confidence,
            reason=f"ML model '{model_name}' risk assessment",
            evidence={"model": model_name, "features": features},
        )

    def add_policy_signal(
        self, allowed: bool, confidence: float, policy_name: str, rule: str
    ) -> SecuritySignal:
        """Helper to create policy signal"""
        return SecuritySignal(
            source=SignalSource.POLICY,
            score=0.0 if allowed else 1.0,
            confidence=confidence,
            reason=f"Policy '{policy_name}' rule: {rule}",
            evidence={"policy": policy_name, "rule": rule, "allowed": allowed},
        )

    def add_adversarial_signal(
        self,
        is_adversarial: bool,
        confidence: float,
        attack_type: str,
        indicators: List[str],
    ) -> SecuritySignal:
        """Helper to create adversarial signal"""
        return SecuritySignal(
            source=SignalSource.ADVERSARIAL,
            score=1.0 if is_adversarial else 0.0,
            confidence=confidence,
            reason=f"Adversarial detection: {attack_type}",
            evidence={"attack_type": attack_type, "indicators": indicators},
        )

    def add_behavioral_signal(
        self, anomaly_score: float, confidence: float, anomalies: List[str]
    ) -> SecuritySignal:
        """Helper to create behavioral signal"""
        return SecuritySignal(
            source=SignalSource.BEHAVIORAL,
            score=anomaly_score,
            confidence=confidence,
            reason=f"Behavioral anomalies detected: {', '.join(anomalies)}",
            evidence={"anomalies": anomalies},
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get fusion engine statistics"""
        return {
            "total_decisions": self._decision_count,
            "decisions_by_outcome": {
                k.value: v for k, v in self._decision_breakdown.items()
            },
            "weights": {k.value: v for k, v in self.weights.items()},
            "thresholds": {
                "deny": self.deny_threshold,
                "allow": self.allow_threshold,
                "confidence": self.confidence_threshold,
            },
        }

    def update_weights(self, new_weights: Dict[SignalSource, float]):
        """Update signal weights"""
        self.weights.update(new_weights)
        logger.info(f"Updated signal weights: {self.weights}")


# Global fusion engine
_global_engine: Optional[SignalFusionEngine] = None


def get_fusion_engine() -> SignalFusionEngine:
    """Get or create the global signal fusion engine"""
    global _global_engine
    if _global_engine is None:
        _global_engine = SignalFusionEngine()
    return _global_engine
