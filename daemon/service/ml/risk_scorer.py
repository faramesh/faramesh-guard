"""
ML Risk Scorer with Calibrated Abstention

Implements machine learning-based risk scoring with uncertainty quantification.
Key innovation: The model can ABSTAIN when uncertain, forcing human review.

Features:
- Structured CAR input (not raw text)
- Multi-label risk classification
- Calibrated probability estimates
- Abstention when uncertain (p ∈ [0.35, 0.65] or low confidence)
- Explainable risk factors
- Online learning from approvals

Reference: guard-plan-v1.md ML Risk Scoring section
"""

import json
import math
import pickle
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
from datetime import datetime
import re

logger = logging.getLogger("guard.ml.risk_scorer")


class RiskLabel(Enum):
    """Risk categories detected by the ML model."""
    DESTRUCTIVE = "destructive"
    EXFILTRATION = "exfil"
    FINANCIAL = "financial"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    EXTERNAL_COMMUNICATION = "external_communication"
    UNKNOWN_RECIPIENT = "unknown_recipient"
    DATA_MODIFICATION = "data_modification"
    SYSTEM_MODIFICATION = "system_modification"
    NETWORK_ACCESS = "network_access"
    SENSITIVE_DATA = "sensitive_data"


class RiskSeverity(Enum):
    """Risk severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskSignal:
    """Individual risk signal detected by the model."""
    label: RiskLabel
    probability: float  # 0.0 - 1.0
    confidence: float  # Model's confidence in this prediction
    evidence: List[str]  # Features that triggered this signal

    @property
    def should_abstain(self) -> bool:
        """Check if model should abstain on this signal."""
        # Abstain if probability is in uncertain range
        if 0.35 <= self.probability <= 0.65:
            return True
        # Abstain if confidence is too low
        if self.confidence < 0.7:
            return True
        return False


@dataclass
class RiskScoreResult:
    """Complete result from the ML risk scorer."""
    # Risk signals
    risk_labels: List[RiskLabel]
    risk_signals: List[RiskSignal]

    # Overall assessment
    overall_probability: float  # Probability of HIGH or CRITICAL risk
    overall_confidence: float  # Model's overall confidence

    # Severity classification
    severity: RiskSeverity

    # Abstention
    abstained: bool
    abstention_reason: Optional[str]

    # Explainability
    reasons: List[str]
    feature_contributions: Dict[str, float]

    # Recommendation
    recommended_decision: str  # "ALLOW", "DENY", "NEEDS_APPROVAL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_labels": [l.value for l in self.risk_labels],
            "overall_probability": self.overall_probability,
            "overall_confidence": self.overall_confidence,
            "severity": self.severity.value,
            "abstained": self.abstained,
            "abstention_reason": self.abstention_reason,
            "reasons": self.reasons,
            "recommended_decision": self.recommended_decision
        }


class FeatureExtractor:
    """
    Extract ML features from structured CAR.
    Converts CAR fields into numerical/categorical features.
    """

    # Known dangerous patterns
    DESTRUCTIVE_PATTERNS = [
        r"rm\s+-rf", r"rm\s+-r\s+/", r"del\s+/s", r"format\s+",
        r"mkfs", r"dd\s+if=", r">\s*/dev/", r"shred\s+"
    ]

    PRIVILEGE_PATTERNS = [
        r"sudo\s+", r"su\s+-", r"chmod\s+777", r"chmod\s+\+s",
        r"chown\s+root", r"setuid", r"doas\s+"
    ]

    EXFIL_PATTERNS = [
        r"curl\s+.*-d", r"wget\s+--post", r"nc\s+-e",
        r"base64.*\|.*curl", r"cat.*\|.*nc"
    ]

    CREDENTIAL_PATTERNS = [
        r"\.env", r"\.pem", r"\.key", r"id_rsa", r"\.ssh/",
        r"password", r"secret", r"api_key", r"token", r"credential"
    ]

    FINANCIAL_KEYWORDS = [
        "refund", "payment", "transfer", "invoice", "credit",
        "debit", "transaction", "stripe", "paypal", "money"
    ]

    def extract(self, car: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from CAR."""
        features = {}

        # Basic categorical features
        features["tool"] = car.get("tool", "unknown")
        features["operation"] = car.get("operation", "unknown")
        features["target_kind"] = car.get("target_kind", "unknown")

        # Binary flags
        features["destination_external"] = 1 if car.get("destination_external") else 0
        features["has_sudo"] = 1 if car.get("has_sudo") else 0

        # Sensitivity features
        sensitivity = car.get("sensitivity", {})
        features["contains_pii"] = 1 if sensitivity.get("contains_pii") else 0
        features["contains_secrets"] = 1 if sensitivity.get("contains_secrets") else 0
        features["contains_financial_ref"] = 1 if sensitivity.get("contains_financial_ref") else 0
        features["money_amount"] = sensitivity.get("money_amount", 0)
        features["sensitivity_confidence"] = sensitivity.get("confidence", 0.5)

        # Context features
        context = car.get("context", {})
        features["prior_relationship"] = 1 if context.get("prior_relationship") else 0
        features["is_production"] = 1 if context.get("environment") == "production" else 0

        # Extraction confidence
        features["extraction_confidence"] = car.get("extraction_confidence", 0.5)

        # Command/args analysis (for exec tools)
        args_string = self._get_args_string(car)
        features["args_length"] = len(args_string)

        # Pattern-based features
        features["has_destructive_pattern"] = self._match_patterns(args_string, self.DESTRUCTIVE_PATTERNS)
        features["has_privilege_pattern"] = self._match_patterns(args_string, self.PRIVILEGE_PATTERNS)
        features["has_exfil_pattern"] = self._match_patterns(args_string, self.EXFIL_PATTERNS)
        features["has_credential_pattern"] = self._match_patterns(
            args_string + " " + car.get("target", ""),
            self.CREDENTIAL_PATTERNS
        )
        features["has_financial_keywords"] = any(
            kw in args_string.lower() or kw in str(car.get("description", "")).lower()
            for kw in self.FINANCIAL_KEYWORDS
        )

        # Path-based features
        target = car.get("target", "")
        features["targets_system_path"] = 1 if self._is_system_path(target) else 0
        features["targets_home_dir"] = 1 if self._is_home_path(target) else 0
        features["path_depth"] = target.count("/") if target else 0

        # Destination analysis
        destination = car.get("destination", "")
        features["destination_is_ip"] = 1 if self._is_ip_address(destination) else 0
        features["destination_has_port"] = 1 if ":" in destination and self._is_ip_address(destination.split(":")[0]) else 0

        # Risk tags count
        risk_tags = car.get("risk_tags", [])
        features["risk_tag_count"] = len(risk_tags)
        features["has_irreversible_tag"] = 1 if "irreversible" in risk_tags else 0
        features["has_external_tag"] = 1 if "external_communication" in risk_tags else 0

        return features

    def _get_args_string(self, car: Dict[str, Any]) -> str:
        """Get string representation of args."""
        args = car.get("args", {})
        if isinstance(args, dict):
            return " ".join(str(v) for v in args.values())
        return str(args)

    def _match_patterns(self, text: str, patterns: List[str]) -> int:
        """Check if any pattern matches."""
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return 1
        return 0

    def _is_system_path(self, path: str) -> bool:
        """Check if path is a system-critical path."""
        system_prefixes = [
            "/etc", "/usr", "/bin", "/sbin", "/lib", "/boot",
            "/System", "/Library", "/var/root",
            "C:\\Windows", "C:\\Program Files"
        ]
        return any(path.startswith(p) for p in system_prefixes)

    def _is_home_path(self, path: str) -> bool:
        """Check if path is in home directory."""
        import os
        home = os.path.expanduser("~")
        return path.startswith(home) or path.startswith("~") or "/home/" in path

    def _is_ip_address(self, s: str) -> bool:
        """Check if string is an IP address."""
        parts = s.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False


class RuleBasedRiskScorer:
    """
    Rule-based fallback scorer when ML model is not available.
    Uses heuristics derived from the feature patterns.
    """

    def __init__(self):
        self.feature_extractor = FeatureExtractor()

    def score(self, car: Dict[str, Any]) -> RiskScoreResult:
        """Score risk using rule-based heuristics."""
        features = self.feature_extractor.extract(car)

        signals = []
        reasons = []

        # Destructive patterns
        if features["has_destructive_pattern"]:
            signals.append(RiskSignal(
                label=RiskLabel.DESTRUCTIVE,
                probability=0.95,
                confidence=0.9,
                evidence=["destructive_command_pattern"]
            ))
            reasons.append("Destructive command pattern detected")

        # Privilege escalation
        if features["has_privilege_pattern"]:
            signals.append(RiskSignal(
                label=RiskLabel.PRIVILEGE_ESCALATION,
                probability=0.9,
                confidence=0.85,
                evidence=["privilege_escalation_pattern"]
            ))
            reasons.append("Privilege escalation attempt detected")

        # Data exfiltration
        if features["has_exfil_pattern"]:
            signals.append(RiskSignal(
                label=RiskLabel.EXFILTRATION,
                probability=0.85,
                confidence=0.8,
                evidence=["data_exfiltration_pattern"]
            ))
            reasons.append("Potential data exfiltration pattern")

        # Credential access
        if features["has_credential_pattern"]:
            signals.append(RiskSignal(
                label=RiskLabel.CREDENTIAL_ACCESS,
                probability=0.8,
                confidence=0.85,
                evidence=["credential_file_access"]
            ))
            reasons.append("Credential or secret file access")

        # Financial operations
        if features["contains_financial_ref"] or features["has_financial_keywords"]:
            prob = 0.7 if features["money_amount"] < 100 else 0.9
            signals.append(RiskSignal(
                label=RiskLabel.FINANCIAL,
                probability=prob,
                confidence=0.8,
                evidence=["financial_operation"]
            ))
            reasons.append(f"Financial operation (amount: ${features['money_amount']})")

        # External communication
        if features["destination_external"]:
            prob = 0.5  # Uncertain by default
            if features["contains_pii"] or features["contains_secrets"]:
                prob = 0.85
            elif not features["prior_relationship"]:
                prob = 0.7

            signals.append(RiskSignal(
                label=RiskLabel.EXTERNAL_COMMUNICATION,
                probability=prob,
                confidence=0.75 if features["prior_relationship"] else 0.85,
                evidence=["external_destination"]
            ))
            reasons.append("External communication detected")

        # Unknown recipient
        if features["destination_external"] and not features["prior_relationship"]:
            signals.append(RiskSignal(
                label=RiskLabel.UNKNOWN_RECIPIENT,
                probability=0.75,
                confidence=0.8,
                evidence=["no_prior_relationship"]
            ))
            reasons.append("Unknown recipient (not in CRM)")

        # System modification
        if features["targets_system_path"] and features["operation"] != "read":
            signals.append(RiskSignal(
                label=RiskLabel.SYSTEM_MODIFICATION,
                probability=0.9,
                confidence=0.9,
                evidence=["system_path_write"]
            ))
            reasons.append("System path modification attempt")

        # Sensitive data
        if features["contains_pii"] or features["contains_secrets"]:
            signals.append(RiskSignal(
                label=RiskLabel.SENSITIVE_DATA,
                probability=0.8,
                confidence=features["sensitivity_confidence"],
                evidence=["sensitive_data_detected"]
            ))
            reasons.append("Sensitive data involved")

        # Calculate overall assessment
        if signals:
            overall_prob = max(s.probability for s in signals)
            overall_conf = sum(s.confidence for s in signals) / len(signals)
            risk_labels = list(set(s.label for s in signals))
        else:
            overall_prob = 0.1
            overall_conf = 0.9
            risk_labels = []

        # Determine severity
        if overall_prob >= 0.85:
            severity = RiskSeverity.CRITICAL
        elif overall_prob >= 0.7:
            severity = RiskSeverity.HIGH
        elif overall_prob >= 0.4:
            severity = RiskSeverity.MEDIUM
        else:
            severity = RiskSeverity.LOW

        # Check for abstention
        abstained = False
        abstention_reason = None

        # Abstain if low extraction confidence
        if features["extraction_confidence"] < 0.7:
            abstained = True
            abstention_reason = f"Low CAR extraction confidence: {features['extraction_confidence']:.2f}"

        # Abstain if probability in uncertain range AND high impact
        if not abstained and 0.35 <= overall_prob <= 0.65:
            if any(s.label in [RiskLabel.FINANCIAL, RiskLabel.DESTRUCTIVE, RiskLabel.EXFILTRATION]
                   for s in signals):
                abstained = True
                abstention_reason = "Uncertain probability for high-impact action"

        # Abstain if any signal wants to abstain
        if not abstained and any(s.should_abstain for s in signals):
            abstained = True
            abstaining_signals = [s for s in signals if s.should_abstain]
            abstention_reason = f"Uncertain on: {[s.label.value for s in abstaining_signals]}"

        # Determine recommendation
        if abstained:
            recommended_decision = "NEEDS_APPROVAL"
        elif severity == RiskSeverity.CRITICAL:
            recommended_decision = "DENY"
        elif severity == RiskSeverity.HIGH:
            recommended_decision = "NEEDS_APPROVAL"
        elif severity == RiskSeverity.MEDIUM and overall_conf < 0.8:
            recommended_decision = "NEEDS_APPROVAL"
        else:
            recommended_decision = "ALLOW"

        # Feature contributions (for explainability)
        feature_contributions = {}
        for signal in signals:
            for evidence in signal.evidence:
                feature_contributions[evidence] = signal.probability

        return RiskScoreResult(
            risk_labels=risk_labels,
            risk_signals=signals,
            overall_probability=overall_prob,
            overall_confidence=overall_conf,
            severity=severity,
            abstained=abstained,
            abstention_reason=abstention_reason,
            reasons=reasons,
            feature_contributions=feature_contributions,
            recommended_decision=recommended_decision
        )


class MLRiskScorer:
    """
    Machine learning-based risk scorer.
    Uses a trained model with calibrated abstention.
    Falls back to rule-based scoring if no model available.
    """

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or Path.home() / ".faramesh-guard" / "models" / "risk_scorer.pkl"
        self.model_path.parent.mkdir(parents=True, exist_ok=True)

        self.feature_extractor = FeatureExtractor()
        self.rule_based_scorer = RuleBasedRiskScorer()

        self.model = None
        self._load_model()

        # Calibration parameters
        self.abstention_low = 0.35
        self.abstention_high = 0.65
        self.min_confidence = 0.7

        # Online learning buffer
        self.training_buffer: List[Tuple[Dict[str, Any], str]] = []
        self.buffer_max_size = 1000

    def _load_model(self) -> None:
        """Load trained model if available."""
        if self.model_path.exists():
            try:
                with open(self.model_path, "rb") as f:
                    self.model = pickle.load(f)
                logger.info(f"Loaded ML model from {self.model_path}")
            except Exception as e:
                logger.warning(f"Failed to load ML model: {e}")
                self.model = None
        else:
            logger.info("No ML model found, using rule-based scoring")

    def score(self, car: Dict[str, Any]) -> RiskScoreResult:
        """
        Score the risk of a CAR.

        Uses ML model if available, otherwise falls back to rule-based.
        """
        if self.model is None:
            return self.rule_based_scorer.score(car)

        try:
            return self._score_with_model(car)
        except Exception as e:
            logger.warning(f"ML scoring failed, using fallback: {e}")
            return self.rule_based_scorer.score(car)

    def _score_with_model(self, car: Dict[str, Any]) -> RiskScoreResult:
        """Score using the trained ML model."""
        features = self.feature_extractor.extract(car)

        # Convert to feature vector
        feature_vector = self._features_to_vector(features)

        # Get model predictions
        try:
            # Multi-label prediction
            predictions = self.model.predict_proba([feature_vector])[0]

            # Build signals from predictions
            signals = []
            risk_labels = []

            label_names = list(RiskLabel)
            for i, prob in enumerate(predictions):
                if i >= len(label_names):
                    break

                label = label_names[i]
                if prob > 0.3:  # Threshold for including as signal
                    # Estimate confidence using prediction entropy
                    confidence = 1.0 - min(1.0, abs(prob - 0.5) * 2)

                    signals.append(RiskSignal(
                        label=label,
                        probability=prob,
                        confidence=confidence,
                        evidence=self._get_feature_evidence(features, label)
                    ))

                    if prob > 0.5:
                        risk_labels.append(label)

            # Overall probability (max of signals)
            overall_prob = max([s.probability for s in signals], default=0.1)
            overall_conf = sum(s.confidence for s in signals) / len(signals) if signals else 0.9

            # Calibration check for abstention
            abstained = False
            abstention_reason = None

            if self.abstention_low <= overall_prob <= self.abstention_high:
                abstained = True
                abstention_reason = f"Probability {overall_prob:.2f} in uncertain range [{self.abstention_low}, {self.abstention_high}]"

            if overall_conf < self.min_confidence:
                abstained = True
                abstention_reason = f"Low confidence: {overall_conf:.2f} < {self.min_confidence}"

            if features["extraction_confidence"] < 0.7:
                abstained = True
                abstention_reason = f"Low CAR extraction confidence: {features['extraction_confidence']:.2f}"

            # Severity
            if overall_prob >= 0.85:
                severity = RiskSeverity.CRITICAL
            elif overall_prob >= 0.7:
                severity = RiskSeverity.HIGH
            elif overall_prob >= 0.4:
                severity = RiskSeverity.MEDIUM
            else:
                severity = RiskSeverity.LOW

            # Recommendation
            if abstained:
                recommended = "NEEDS_APPROVAL"
            elif severity == RiskSeverity.CRITICAL:
                recommended = "DENY"
            elif severity == RiskSeverity.HIGH:
                recommended = "NEEDS_APPROVAL"
            else:
                recommended = "ALLOW"

            return RiskScoreResult(
                risk_labels=risk_labels,
                risk_signals=signals,
                overall_probability=overall_prob,
                overall_confidence=overall_conf,
                severity=severity,
                abstained=abstained,
                abstention_reason=abstention_reason,
                reasons=[s.evidence[0] if s.evidence else s.label.value for s in signals],
                feature_contributions={},
                recommended_decision=recommended
            )

        except Exception as e:
            logger.error(f"Model prediction failed: {e}")
            raise

    def _features_to_vector(self, features: Dict[str, Any]) -> List[float]:
        """Convert feature dict to numeric vector."""
        # Define feature order
        numeric_features = [
            "destination_external", "has_sudo", "contains_pii", "contains_secrets",
            "contains_financial_ref", "money_amount", "sensitivity_confidence",
            "prior_relationship", "is_production", "extraction_confidence",
            "args_length", "has_destructive_pattern", "has_privilege_pattern",
            "has_exfil_pattern", "has_credential_pattern", "has_financial_keywords",
            "targets_system_path", "targets_home_dir", "path_depth",
            "destination_is_ip", "destination_has_port", "risk_tag_count",
            "has_irreversible_tag", "has_external_tag"
        ]

        vector = []
        for feat in numeric_features:
            val = features.get(feat, 0)
            if isinstance(val, bool):
                val = 1 if val else 0
            vector.append(float(val))

        return vector

    def _get_feature_evidence(self, features: Dict[str, Any], label: RiskLabel) -> List[str]:
        """Get feature evidence for a risk label."""
        evidence = []

        if label == RiskLabel.DESTRUCTIVE and features.get("has_destructive_pattern"):
            evidence.append("destructive_command_pattern")
        if label == RiskLabel.PRIVILEGE_ESCALATION and features.get("has_privilege_pattern"):
            evidence.append("privilege_escalation_pattern")
        if label == RiskLabel.EXFILTRATION and features.get("has_exfil_pattern"):
            evidence.append("exfiltration_pattern")
        if label == RiskLabel.CREDENTIAL_ACCESS and features.get("has_credential_pattern"):
            evidence.append("credential_access")
        if label == RiskLabel.FINANCIAL and features.get("contains_financial_ref"):
            evidence.append("financial_operation")
        if label == RiskLabel.EXTERNAL_COMMUNICATION and features.get("destination_external"):
            evidence.append("external_destination")

        return evidence if evidence else [label.value]

    def record_feedback(self, car: Dict[str, Any], actual_decision: str) -> None:
        """
        Record human feedback for online learning.

        Args:
            car: The CAR that was evaluated
            actual_decision: What decision was actually made (ALLOW/DENY)
        """
        self.training_buffer.append((car, actual_decision))

        if len(self.training_buffer) >= self.buffer_max_size:
            self._trigger_retraining()

    def _trigger_retraining(self) -> None:
        """Trigger model retraining with buffered examples."""
        # Save training data
        training_data_path = self.model_path.parent / "training_buffer.json"
        with open(training_data_path, "w") as f:
            json.dump([
                {"car": car, "decision": decision}
                for car, decision in self.training_buffer
            ], f)

        logger.info(f"Saved {len(self.training_buffer)} training examples for retraining")
        self.training_buffer.clear()


# Singleton instance
_scorer: Optional[MLRiskScorer] = None


def get_ml_risk_scorer() -> MLRiskScorer:
    """Get singleton ML risk scorer."""
    global _scorer
    if _scorer is None:
        _scorer = MLRiskScorer()
    return _scorer
