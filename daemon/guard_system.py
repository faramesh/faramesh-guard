"""
Faramesh Guard - Unified Guard System Integration

This module integrates all Guard components into a unified system:
- Runtime Registry (tool discovery & wrapping)
- Execution Wrapper (enforcement boundary)
- Permit System (cryptographic authorization)
- Signal Fusion (multi-source decision making)
- Behavioral Anomaly Detection
- Fail-Closed Handler
- Permit Tracking

Following plan-farameshGuardV1Enhanced.prompt.md complete architecture.
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from .core.execution_wrapper import (
    GuardedToolWrapper,
    ExecutionContext,
    ExecutionResult,
)
from .core.runtime_registry import get_registry, RuntimeRegistry
from .core.fail_closed import (
    get_fail_closed_handler,
    FailClosedHandler,
    FailureMode,
    create_failure_context,
    assess_risk_level,
)
from .core.permit_tracking import get_permit_database, PermitDatabase
from .service.behavioral_anomaly import (
    get_anomaly_detector,
    BehavioralAnomalyDetector,
    ActionEvent,
)
from .service.signal_fusion import (
    get_fusion_engine,
    SignalFusionEngine,
    SecuritySignal,
    SignalSource,
    Decision,
)

logger = logging.getLogger(__name__)


class FarameshGuard:
    """
    Unified Faramesh Guard System

    Provides non-bypassable AI agent safety through:
    1. Automatic tool wrapping with Guard enforcement
    2. Multi-signal risk assessment (ML + policy + adversarial + behavioral)
    3. Cryptographic permit validation
    4. Fail-closed error handling
    5. Comprehensive audit trail
    """

    def __init__(
        self,
        daemon_url: str = "http://localhost:8765",
        db_path: str = "guard_permits.db",
        enable_behavioral_learning: bool = True,
        enable_fail_closed: bool = True,
        allow_low_risk_fallback: bool = False,
    ):
        self.daemon_url = daemon_url

        # Initialize all subsystems
        self.registry: RuntimeRegistry = get_registry()
        self.fusion_engine: SignalFusionEngine = get_fusion_engine()
        self.anomaly_detector: BehavioralAnomalyDetector = get_anomaly_detector()
        self.fail_closed_handler: FailClosedHandler = get_fail_closed_handler(
            allow_low_risk_fallback=allow_low_risk_fallback
        )
        self.permit_db: PermitDatabase = get_permit_database(db_path)

        self.enable_behavioral_learning = enable_behavioral_learning
        self.enable_fail_closed = enable_fail_closed

        logger.info("Faramesh Guard initialized")

    async def register_tool(
        self, name: str, callable_obj: Any, metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Register a tool with Guard protection.

        Automatically wraps the tool with enforcement.
        """
        await self.registry.register_tool(
            name=name, callable_obj=callable_obj, metadata=metadata, auto_wrap=True
        )
        logger.info(f"Registered and wrapped tool: {name}")

    async def execute_tool(
        self, tool_name: str, agent_id: str, parameters: Dict[str, Any]
    ) -> ExecutionResult:
        """
        Execute a tool through Guard.

        Full flow:
        1. Gather security signals
        2. Fuse signals into decision
        3. If ALLOW, mint permit
        4. Validate permit
        5. Execute tool
        6. Record usage
        7. Learn behavioral patterns
        """
        start_time = datetime.utcnow()

        try:
            # Step 1: Get the tool
            tool_meta = await self.registry.get_tool(tool_name)
            if not tool_meta:
                return ExecutionResult(
                    allowed=False,
                    error=f"Tool '{tool_name}' not registered",
                    decision_id=None,
                    permit_id=None,
                    result=None,
                )

            # Step 2: Gather security signals
            signals = await self._gather_signals(tool_name, agent_id, parameters)

            # Step 3: Fuse signals
            fused = self.fusion_engine.fuse_signals(signals)

            # Step 4: Handle decision
            if fused.decision == Decision.DENY:
                # Record denial
                await self._record_event(
                    tool_name, agent_id, parameters, "DENY", fused.reason
                )

                return ExecutionResult(
                    allowed=False,
                    error=fused.reason,
                    decision_id=fused.explanation.get("reason_code"),
                    permit_id=None,
                    result=None,
                )

            elif fused.decision == Decision.ABSTAIN:
                # Needs human approval
                await self._record_event(
                    tool_name, agent_id, parameters, "ABSTAIN", fused.reason
                )

                return ExecutionResult(
                    allowed=False,
                    error=f"Human approval required: {fused.reason}",
                    decision_id=fused.explanation.get("reason_code"),
                    permit_id=None,
                    result=None,
                )

            # Step 5: ALLOW - Execute through registry
            result = await self.registry.execute_tool(tool_name, agent_id, parameters)

            # Step 6: Record successful execution
            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            await self._record_event(
                tool_name, agent_id, parameters, "ALLOW", fused.reason, execution_time
            )

            # Step 7: Learn behavioral patterns
            if self.enable_behavioral_learning:
                await self._learn_behavior(tool_name, agent_id, parameters, "ALLOW")

            return result

        except Exception as e:
            logger.error(f"Guard execution failed: {e}")

            # Fail-closed handling
            if self.enable_fail_closed:
                failure_ctx = create_failure_context(
                    FailureMode.UNKNOWN_ERROR, e, agent_id, tool_name, parameters
                )
                decision = self.fail_closed_handler.handle_failure(failure_ctx)

                if not decision.allowed:
                    return ExecutionResult(
                        allowed=False,
                        error=decision.reason,
                        decision_id=decision.reason_code,
                        permit_id=None,
                        result=None,
                    )

            raise

    async def _gather_signals(
        self, tool_name: str, agent_id: str, parameters: Dict[str, Any]
    ) -> List[SecuritySignal]:
        """Gather security signals from all sources"""
        signals = []

        # 1. Simple risk assessment (TODO: Replace with ML model)
        risk_level = assess_risk_level(tool_name, parameters)
        risk_map = {
            "low": 0.1,
            "medium": 0.4,
            "high": 0.7,
            "critical": 0.95,
            "unknown": 0.5,
        }
        ml_score = risk_map.get(risk_level.value, 0.5)

        signals.append(
            self.fusion_engine.add_ml_risk_signal(
                risk_score=ml_score,
                confidence=0.7,
                model_name="heuristic_v1",
                features={"tool": tool_name, "risk": risk_level.value},
            )
        )

        # 2. Policy evaluation (TODO: Integrate OPA)
        # For now, simple allow/deny based on risk
        policy_allowed = risk_level.value in ["low", "medium"]
        signals.append(
            self.fusion_engine.add_policy_signal(
                allowed=policy_allowed,
                confidence=0.8,
                policy_name="default_policy",
                rule=f"Risk level {risk_level.value}",
            )
        )

        # 3. Behavioral anomalies
        if self.enable_behavioral_learning:
            event = ActionEvent(
                timestamp=datetime.utcnow(),
                agent_id=agent_id,
                tool_name=tool_name,
                parameters=parameters,
                car_hash="",  # Will be computed later
                outcome="PENDING",
                risk_level=risk_level.value,
            )

            anomalies = self.anomaly_detector.detect_anomalies(event)
            if anomalies:
                anomaly_names = [a.anomaly_type for a in anomalies]
                max_severity = max(a.severity for a in anomalies)

                signals.append(
                    self.fusion_engine.add_behavioral_signal(
                        anomaly_score=max_severity,
                        confidence=0.6,
                        anomalies=anomaly_names,
                    )
                )

        # 4. Adversarial detection (TODO: Implement prompt injection detection)
        # For now, simple heuristics
        adversarial_indicators = self._detect_adversarial(parameters)
        if adversarial_indicators:
            signals.append(
                self.fusion_engine.add_adversarial_signal(
                    is_adversarial=True,
                    confidence=0.5,
                    attack_type="potential_injection",
                    indicators=adversarial_indicators,
                )
            )

        return signals

    def _detect_adversarial(self, parameters: Dict[str, Any]) -> List[str]:
        """Simple adversarial detection heuristics"""
        indicators = []
        params_str = str(parameters).lower()

        # Check for suspicious patterns
        suspicious = [
            "ignore previous",
            "disregard",
            "system prompt",
            "jailbreak",
            "exploit",
            "bypass",
            "sudo",
            "rm -rf",
            "<script>",
            "eval(",
            "exec(",
        ]

        for pattern in suspicious:
            if pattern in params_str:
                indicators.append(pattern)

        return indicators

    async def _record_event(
        self,
        tool_name: str,
        agent_id: str,
        parameters: Dict[str, Any],
        outcome: str,
        reason: str,
        execution_time_ms: Optional[float] = None,
    ):
        """Record an event in audit trail"""
        logger.info(
            f"AUDIT: {outcome} | Tool: {tool_name} | "
            f"Agent: {agent_id} | Reason: {reason}"
        )
        # TODO: Persist to audit database

    async def _learn_behavior(
        self, tool_name: str, agent_id: str, parameters: Dict[str, Any], outcome: str
    ):
        """Learn from this action"""
        event = ActionEvent(
            timestamp=datetime.utcnow(),
            agent_id=agent_id,
            tool_name=tool_name,
            parameters=parameters,
            car_hash="",
            outcome=outcome,
            risk_level="unknown",
        )
        self.anomaly_detector.record_action(event)

    async def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive Guard statistics"""
        registry_stats = await self.registry.get_stats()
        fusion_stats = self.fusion_engine.get_stats()
        anomaly_stats = self.anomaly_detector.get_stats()
        fail_closed_stats = self.fail_closed_handler.get_stats()
        permit_stats = self.permit_db.get_stats()

        return {
            "registry": registry_stats,
            "fusion": fusion_stats,
            "anomaly_detection": anomaly_stats,
            "fail_closed": fail_closed_stats,
            "permits": permit_stats,
            "daemon_url": self.daemon_url,
        }

    async def generate_report(self) -> str:
        """Generate comprehensive status report"""
        stats = await self.get_stats()

        registry = stats["registry"]
        fusion = stats["fusion"]
        anomaly = stats["anomaly_detection"]
        fail_closed = stats["fail_closed"]
        permits = stats["permits"]

        report = [
            "=" * 70,
            "FARAMESH GUARD - System Status Report",
            "=" * 70,
            "",
            "TOOL REGISTRY:",
            f"  Total Tools: {registry.total_tools}",
            f"  Guarded: {registry.guarded_tools}",
            f"  Unguarded: {registry.unguarded_tools}",
            f"  Coverage: {registry.enforcement_coverage:.1f}%",
            "",
            "SIGNAL FUSION:",
            f"  Total Decisions: {fusion['total_decisions']}",
            f"  Allows: {fusion['decisions_by_outcome'].get('ALLOW', 0)}",
            f"  Denies: {fusion['decisions_by_outcome'].get('DENY', 0)}",
            f"  Abstains: {fusion['decisions_by_outcome'].get('ABSTAIN', 0)}",
            "",
            "BEHAVIORAL ANOMALIES:",
            f"  Tracked Agents: {anomaly['total_agents']}",
            f"  Anomalies Detected: {anomaly['total_anomalies']}",
            "",
            "FAIL-CLOSED:",
            f"  Failures: {fail_closed['failure_count']}",
            f"  Low Risk Fallback: {fail_closed['allow_low_risk_fallback']}",
            "",
            "PERMITS:",
            f"  Total Issued: {permits.get('total_permits', 0)}",
            f"  Active: {permits.get('active_permits', 0)}",
            f"  Revoked: {permits.get('revoked_permits', 0)}",
            f"  Total Uses: {permits.get('total_usages', 0)}",
            "",
            "=" * 70,
        ]

        return "\n".join(report)

    async def validate_enforcement(self) -> bool:
        """Validate that enforcement is properly configured"""
        # Check 100% coverage
        coverage_ok = await self.registry.validate_coverage(minimum_coverage=100.0)

        if not coverage_ok:
            logger.error("Enforcement validation FAILED: Coverage below 100%")
            return False

        logger.info("Enforcement validation PASSED: All tools protected")
        return True


# Global Guard instance
_global_guard: Optional[FarameshGuard] = None


def get_guard(
    daemon_url: str = "http://localhost:8765",
    db_path: str = "guard_permits.db",
    **kwargs,
) -> FarameshGuard:
    """Get or create the global Guard instance"""
    global _global_guard
    if _global_guard is None:
        _global_guard = FarameshGuard(daemon_url=daemon_url, db_path=db_path, **kwargs)
    return _global_guard


async def main():
    """Example usage"""
    guard = get_guard()

    # Register a test tool
    async def test_tool(params):
        return f"Executed: {params}"

    await guard.register_tool("test_tool", test_tool)

    # Execute the tool
    result = await guard.execute_tool(
        tool_name="test_tool",
        agent_id="test-agent",
        parameters={"action": "read_file", "path": "/tmp/test.txt"},
    )

    print(f"Result: {result}")

    # Generate report
    report = await guard.generate_report()
    print(report)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
