"""
Risk Score Calibration for Faramesh Guard.

Provides dynamic risk scoring with calibration based on historical data.
"""

import asyncio
import hashlib
import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import aiofiles

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    """Risk levels."""

    CRITICAL = "critical"  # 0.9 - 1.0
    HIGH = "high"  # 0.7 - 0.9
    MEDIUM = "medium"  # 0.4 - 0.7
    LOW = "low"  # 0.1 - 0.4
    MINIMAL = "minimal"  # 0.0 - 0.1


@dataclass
class RiskFactor:
    """A risk factor and its weight."""

    name: str
    description: str
    base_weight: float
    calibrated_weight: float = 0.0

    # Calibration data
    samples: int = 0
    positive_outcomes: int = 0  # Outcomes where risk materialized
    last_calibrated: Optional[str] = None


@dataclass
class RiskScore:
    """Calculated risk score."""

    score: float  # 0.0 - 1.0
    level: str

    # Breakdown
    factors: Dict[str, float] = field(default_factory=dict)
    primary_factor: Optional[str] = None

    # Context
    action_type: str = ""
    resource: str = ""
    agent_id: str = ""

    # Confidence
    confidence: float = 1.0
    calibrated: bool = False


class RiskScoreCalibrator:
    """
    Calibrates risk scores based on historical outcomes.

    Features:
    - Multiple risk factors
    - Bayesian calibration
    - Action-type specific weights
    - Resource pattern analysis
    - Agent-specific adjustments
    """

    def __init__(
        self,
        data_dir: str = "/var/lib/faramesh-guard/risk",
        min_samples_for_calibration: int = 100,
    ):
        self.data_dir = Path(data_dir)
        self.min_samples = min_samples_for_calibration

        # Risk factors
        self._factors: Dict[str, RiskFactor] = {}
        self._action_weights: Dict[str, Dict[str, float]] = {}

        # Outcome history for calibration
        self._outcomes: List[Dict[str, Any]] = []
        self._max_outcomes = 10000

        self._lock = asyncio.Lock()

        # Initialize default factors
        self._initialize_factors()

        logger.info("RiskScoreCalibrator initialized")

    def _initialize_factors(self):
        """Initialize default risk factors."""
        defaults = [
            ("system_path", "Access to system paths", 0.8),
            ("sensitive_data", "Access to sensitive data patterns", 0.9),
            ("destructive_action", "Destructive or irreversible action", 0.85),
            ("external_network", "External network access", 0.6),
            ("privilege_escalation", "Potential privilege escalation", 0.95),
            ("code_execution", "Arbitrary code execution", 0.7),
            ("bulk_operation", "Bulk/batch operations", 0.5),
            ("first_time_pattern", "First time seeing this pattern", 0.4),
            ("unusual_time", "Unusual time of day", 0.3),
            ("unknown_agent", "Unknown or new agent", 0.6),
        ]

        for name, desc, weight in defaults:
            self._factors[name] = RiskFactor(
                name=name,
                description=desc,
                base_weight=weight,
                calibrated_weight=weight,
            )

        # Action-specific weights
        self._action_weights = {
            "write_file": {"system_path": 1.2, "sensitive_data": 1.3},
            "delete_file": {"destructive_action": 1.5, "system_path": 1.4},
            "exec_command": {"code_execution": 1.3, "privilege_escalation": 1.4},
            "api_call": {"external_network": 1.2, "sensitive_data": 1.1},
        }

    async def start(self):
        """Start the calibrator."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        await self._load_calibration_data()

    async def stop(self):
        """Stop and save calibration data."""
        await self._save_calibration_data()

    async def calculate_risk(
        self,
        action_type: str,
        resource: str,
        agent_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> RiskScore:
        """
        Calculate risk score for an action.

        Args:
            action_type: Type of action
            resource: Resource being accessed
            agent_id: Agent making request
            context: Additional context

        Returns:
            RiskScore with breakdown
        """
        context = context or {}

        # Calculate factor scores
        factor_scores = {}

        # System path check
        system_paths = [
            "/etc",
            "/var",
            "/usr",
            "/bin",
            "/sbin",
            "/root",
            "/sys",
            "/proc",
        ]
        if any(resource.startswith(p) for p in system_paths):
            factor_scores["system_path"] = 1.0
        elif resource.startswith("/tmp"):
            factor_scores["system_path"] = 0.2

        # Sensitive data patterns
        sensitive_patterns = [
            ".key",
            ".pem",
            "password",
            "secret",
            "token",
            "credential",
        ]
        if any(p in resource.lower() for p in sensitive_patterns):
            factor_scores["sensitive_data"] = 1.0

        # Destructive actions
        if action_type in ["delete_file", "rm", "truncate"]:
            factor_scores["destructive_action"] = 1.0
        elif "delete" in action_type.lower():
            factor_scores["destructive_action"] = 0.7

        # External network
        if action_type == "api_call":
            if not any(x in resource for x in ["localhost", "127.0.0.1", "internal"]):
                factor_scores["external_network"] = 1.0

        # Privilege escalation
        priv_keywords = ["sudo", "su ", "chmod 777", "chown root", "setuid"]
        if any(k in resource.lower() for k in priv_keywords):
            factor_scores["privilege_escalation"] = 1.0

        # Code execution
        if action_type == "exec_command":
            factor_scores["code_execution"] = 0.5  # Base risk for any command
            dangerous_cmds = ["eval", "exec", "curl | sh", "wget | bash"]
            if any(c in resource for c in dangerous_cmds):
                factor_scores["code_execution"] = 1.0

        # Unusual time
        hour = datetime.now().hour
        if hour < 6 or hour > 22:
            factor_scores["unusual_time"] = 0.7

        # Apply action-specific weight adjustments
        action_mods = self._action_weights.get(action_type, {})

        # Calculate weighted score
        total_score = 0.0
        total_weight = 0.0

        for factor_name, factor_value in factor_scores.items():
            factor = self._factors.get(factor_name)
            if not factor:
                continue

            # Use calibrated weight
            weight = factor.calibrated_weight

            # Apply action modifier
            if factor_name in action_mods:
                weight *= action_mods[factor_name]

            total_score += factor_value * weight
            total_weight += weight

        # Normalize
        if total_weight > 0:
            final_score = min(1.0, total_score / max(total_weight, 1.0))
        else:
            final_score = 0.1  # Default minimal risk

        # Determine level
        if final_score >= 0.9:
            level = RiskLevel.CRITICAL
        elif final_score >= 0.7:
            level = RiskLevel.HIGH
        elif final_score >= 0.4:
            level = RiskLevel.MEDIUM
        elif final_score >= 0.1:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.MINIMAL

        # Find primary factor
        primary_factor = None
        if factor_scores:
            primary_factor = max(factor_scores.keys(), key=lambda k: factor_scores[k])

        return RiskScore(
            score=final_score,
            level=level.value,
            factors=factor_scores,
            primary_factor=primary_factor,
            action_type=action_type,
            resource=resource,
            agent_id=agent_id,
            calibrated=any(
                f.samples >= self.min_samples for f in self._factors.values()
            ),
        )

    async def record_outcome(
        self,
        action_type: str,
        resource: str,
        agent_id: str,
        risk_score: float,
        factors_triggered: Dict[str, float],
        outcome_negative: bool,
    ):
        """
        Record outcome for calibration.

        Args:
            action_type: Type of action
            resource: Resource accessed
            agent_id: Agent ID
            risk_score: Risk score that was calculated
            factors_triggered: Factors that were triggered
            outcome_negative: Whether the outcome was negative (risk materialized)
        """
        outcome = {
            "action_type": action_type,
            "resource": resource,
            "agent_id": agent_id,
            "risk_score": risk_score,
            "factors": factors_triggered,
            "negative": outcome_negative,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        async with self._lock:
            self._outcomes.append(outcome)

            if len(self._outcomes) > self._max_outcomes:
                self._outcomes = self._outcomes[-self._max_outcomes :]

            # Update factor samples
            for factor_name in factors_triggered:
                if factor_name in self._factors:
                    factor = self._factors[factor_name]
                    factor.samples += 1
                    if outcome_negative:
                        factor.positive_outcomes += 1

        # Trigger calibration if enough samples
        if len(self._outcomes) % 100 == 0:
            await self._calibrate()

    async def _calibrate(self):
        """Calibrate factor weights based on outcomes."""
        async with self._lock:
            for factor_name, factor in self._factors.items():
                if factor.samples < self.min_samples:
                    continue

                # Calculate precision (ratio of negative outcomes)
                if factor.samples > 0:
                    precision = factor.positive_outcomes / factor.samples
                else:
                    precision = 0.5

                # Bayesian update: blend base weight with observed precision
                # More samples = more weight to observed precision
                blend_factor = min(factor.samples / 1000, 0.8)
                factor.calibrated_weight = (
                    1 - blend_factor
                ) * factor.base_weight + blend_factor * precision

                factor.last_calibrated = datetime.now(timezone.utc).isoformat()

        logger.info("Risk factor calibration completed")
        await self._save_calibration_data()

    def get_factors(self) -> List[RiskFactor]:
        """Get all risk factors."""
        return list(self._factors.values())

    async def _load_calibration_data(self):
        """Load calibration data from disk."""
        cal_file = self.data_dir / "calibration.json"

        if cal_file.exists():
            try:
                async with aiofiles.open(cal_file, "r") as f:
                    content = await f.read()

                data = json.loads(content)

                for factor_data in data.get("factors", []):
                    name = factor_data["name"]
                    if name in self._factors:
                        self._factors[name].calibrated_weight = factor_data.get(
                            "calibrated_weight", self._factors[name].base_weight
                        )
                        self._factors[name].samples = factor_data.get("samples", 0)
                        self._factors[name].positive_outcomes = factor_data.get(
                            "positive_outcomes", 0
                        )

                logger.info("Loaded calibration data")

            except Exception as e:
                logger.error(f"Error loading calibration data: {e}")

    async def _save_calibration_data(self):
        """Save calibration data to disk."""
        cal_file = self.data_dir / "calibration.json"

        try:
            from dataclasses import asdict

            data = {
                "factors": [asdict(f) for f in self._factors.values()],
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }

            async with aiofiles.open(cal_file, "w") as f:
                await f.write(json.dumps(data, indent=2))

        except Exception as e:
            logger.error(f"Error saving calibration data: {e}")


# Singleton
_calibrator: Optional[RiskScoreCalibrator] = None


def get_risk_calibrator() -> RiskScoreCalibrator:
    global _calibrator
    if _calibrator is None:
        _calibrator = RiskScoreCalibrator()
    return _calibrator


def create_risk_routes():
    """Create FastAPI routes for risk scoring."""
    from fastapi import APIRouter
    from pydantic import BaseModel
    from typing import Optional, Dict

    router = APIRouter(prefix="/api/v1/guard/risk", tags=["risk"])

    class CalculateRiskRequest(BaseModel):
        action_type: str
        resource: str
        agent_id: str
        context: Optional[Dict[str, Any]] = None

    class RecordOutcomeRequest(BaseModel):
        action_type: str
        resource: str
        agent_id: str
        risk_score: float
        factors_triggered: Dict[str, float]
        outcome_negative: bool

    @router.post("/calculate")
    async def calculate_risk(request: CalculateRiskRequest):
        """Calculate risk score for an action."""
        calibrator = get_risk_calibrator()
        score = await calibrator.calculate_risk(
            action_type=request.action_type,
            resource=request.resource,
            agent_id=request.agent_id,
            context=request.context,
        )
        return {
            "score": score.score,
            "level": score.level,
            "factors": score.factors,
            "primary_factor": score.primary_factor,
            "calibrated": score.calibrated,
        }

    @router.post("/outcome")
    async def record_outcome(request: RecordOutcomeRequest):
        """Record outcome for calibration."""
        calibrator = get_risk_calibrator()
        await calibrator.record_outcome(
            action_type=request.action_type,
            resource=request.resource,
            agent_id=request.agent_id,
            risk_score=request.risk_score,
            factors_triggered=request.factors_triggered,
            outcome_negative=request.outcome_negative,
        )
        return {"recorded": True}

    @router.get("/factors")
    async def get_factors():
        """Get risk factors and their weights."""
        calibrator = get_risk_calibrator()
        factors = calibrator.get_factors()
        return {
            "factors": [
                {
                    "name": f.name,
                    "description": f.description,
                    "base_weight": f.base_weight,
                    "calibrated_weight": f.calibrated_weight,
                    "samples": f.samples,
                }
                for f in factors
            ]
        }

    return router
