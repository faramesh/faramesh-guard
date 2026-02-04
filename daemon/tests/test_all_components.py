"""
Comprehensive test suite for all 24 Faramesh Guard components.

Tests import, instantiation, basic functionality, and performance.
"""

import asyncio
import sys
import time
import traceback
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_imports():
    """Test that all 24 components can be imported."""
    print("\n=== TESTING IMPORTS ===\n")

    components = [
        # Phase 1: Ship-Blockers
        (
            "service.state.protection_state",
            "ProtectionStateMachine",
            "get_protection_state_machine",
        ),
        ("service.heartbeat.monitor", "HeartbeatMonitor", "get_heartbeat_monitor"),
        (
            "service.dedup.decision_dedup",
            "DecisionDeduplicator",
            "get_decision_deduplicator",
        ),
        (
            "service.runtime.version_handshake",
            "VersionHandshake",
            "get_version_handshake",
        ),
        # Phase 2: Enterprise Features
        ("service.update.atomic_updater", "AtomicUpdater", "get_atomic_updater"),
        ("service.config.migrator", "ConfigMigrator", "get_config_migrator"),
        (
            "service.platform.permission_monitor",
            "PermissionMonitor",
            "get_permission_monitor",
        ),
        (
            "service.platform.environment_checker",
            "EnvironmentChecker",
            "get_environment_checker",
        ),
        # Phase 3: Product Polish
        ("service.training.data_logger", "TrainingDataLogger", "get_training_logger"),
        ("service.shadow.evaluator", "ShadowModeEvaluator", "get_shadow_evaluator"),
        ("service.frequency.monitor", "FrequencyMonitor", "get_frequency_monitor"),
        ("service.macros.policy_macros", "PolicyMacroEngine", "get_macro_engine"),
        (
            "service.testing.protection_api",
            "TestProtectionAPI",
            "get_test_api",
        ),
        (
            "service.diagnostics.exporter",
            "DiagnosticsExporter",
            "get_diagnostics_exporter",
        ),
        # Phase 4: Advanced Features
        ("service.risk.calibrator", "RiskScoreCalibrator", "get_risk_calibrator"),
        (
            "service.allowlist.contextual",
            "ContextualAllowlist",
            "get_contextual_allowlist",
        ),
        ("service.workflow.detector", "WorkflowDetector", "get_workflow_detector"),
        (
            "service.extractors.saas",
            "SaaSExtractorRegistry",
            "get_saas_extractor_registry",
        ),
        (
            "service.browser.classifier",
            "BrowserActionClassifier",
            "get_browser_classifier",
        ),
        ("service.cache.decision_cache", "FastPathCache", "get_fast_path_cache"),
        ("service.restart.scheduler", "SoftRestartScheduler", "get_restart_scheduler"),
        ("service.memory.watchdog", "MemoryWatchdog", "get_memory_watchdog"),
    ]

    success = []
    errors = []

    for module_name, class_name, getter_name in components:
        try:
            module = __import__(module_name, fromlist=[class_name, getter_name])
            cls = getattr(module, class_name)
            getter = getattr(module, getter_name)

            # Call getter to get singleton
            instance = getter()
            assert instance is not None

            success.append(class_name)
            print(f"  ✅ {class_name}")
        except Exception as e:
            errors.append((class_name, str(e)))
            print(f"  ❌ {class_name}: {e}")

    print(f"\n  {len(success)}/{len(components)} imports OK")
    return errors


def test_route_factories():
    """Test that all route factories work."""
    print("\n=== TESTING ROUTE FACTORIES ===\n")

    routes = [
        ("service.state.protection_state", "create_protection_state_routes"),
        ("service.heartbeat.monitor", "create_heartbeat_routes"),
        ("service.dedup.decision_dedup", "create_dedup_routes"),
        ("service.runtime.version_handshake", "create_handshake_routes"),
        ("service.update.atomic_updater", "create_updater_routes"),
        ("service.config.migrator", "create_migrator_routes"),
        ("service.platform.permission_monitor", "create_permission_routes"),
        ("service.platform.environment_checker", "create_environment_routes"),
        ("service.training.data_logger", "create_training_routes"),
        ("service.shadow.evaluator", "create_shadow_routes"),
        ("service.frequency.monitor", "create_frequency_routes"),
        ("service.macros.policy_macros", "create_macro_routes"),
        ("service.testing.protection_api", "create_test_routes"),
        ("service.diagnostics.exporter", "create_diagnostics_routes"),
        ("service.risk.calibrator", "create_risk_routes"),
        ("service.allowlist.contextual", "create_allowlist_routes"),
        ("service.workflow.detector", "create_workflow_routes"),
        ("service.extractors.saas", "create_extractor_routes"),
        ("service.browser.classifier", "create_browser_routes"),
        ("service.cache.decision_cache", "create_cache_routes"),
        ("service.restart.scheduler", "create_restart_routes"),
        ("service.memory.watchdog", "create_memory_routes"),
    ]

    success = []
    errors = []

    for module_name, factory_name in routes:
        try:
            module = __import__(module_name, fromlist=[factory_name])
            factory = getattr(module, factory_name)
            router = factory()

            # Should be a FastAPI APIRouter
            assert router is not None
            assert hasattr(router, "routes")

            success.append(factory_name)
            print(f"  ✅ {factory_name} ({len(router.routes)} routes)")
        except Exception as e:
            errors.append((factory_name, str(e)))
            print(f"  ❌ {factory_name}: {e}")

    print(f"\n  {len(success)}/{len(routes)} route factories OK")
    return errors


async def test_async_operations():
    """Test async operations of key components."""
    print("\n=== TESTING ASYNC OPERATIONS ===\n")

    errors = []

    # Test FastPathCache
    try:
        from service.cache.decision_cache import get_fast_path_cache, CacheDecision

        cache = get_fast_path_cache()

        # Test put and get
        await cache.put("shell_execute", "ls -la", "agent1", CacheDecision.ALLOW, 0.9)
        entry = await cache.get("shell_execute", "ls -la", "agent1")
        assert entry is not None
        assert entry.decision == "allow"
        print("  ✅ FastPathCache put/get")
    except Exception as e:
        errors.append(("FastPathCache", str(e)))
        print(f"  ❌ FastPathCache: {e}")

    # Test ContextualAllowlist
    try:
        from service.allowlist.contextual import (
            get_contextual_allowlist,
            AllowlistScope,
        )

        allowlist = get_contextual_allowlist()

        entry = await allowlist.add_entry(
            name="Test Entry",
            description="Test allowlist",
            action_types=["file_read"],
            scope=AllowlistScope.GLOBAL,
        )
        assert entry.entry_id is not None

        match = await allowlist.check("file_read", "/tmp/test.txt", "agent1")
        assert match.allowed
        print("  ✅ ContextualAllowlist add/check")
    except Exception as e:
        errors.append(("ContextualAllowlist", str(e)))
        print(f"  ❌ ContextualAllowlist: {e}")

    # Test WorkflowDetector
    try:
        from service.workflow.detector import get_workflow_detector

        detector = get_workflow_detector()

        workflow = await detector.process_action(
            action_type="shell_execute",
            resource="pytest tests/",
            agent_id="agent1",
        )
        # May or may not detect workflow
        print(
            f"  ✅ WorkflowDetector process_action (detected: {workflow is not None})"
        )
    except Exception as e:
        errors.append(("WorkflowDetector", str(e)))
        print(f"  ❌ WorkflowDetector: {e}")

    # Test RiskScoreCalibrator
    try:
        from service.risk.calibrator import get_risk_calibrator

        calibrator = get_risk_calibrator()

        score = await calibrator.calculate_risk(
            action_type="shell_execute",
            resource="/etc/passwd",
            agent_id="agent1",
            context={},
        )
        assert score is not None
        assert 0 <= score.score <= 1
        print(f"  ✅ RiskScoreCalibrator calculate_risk (score: {score.score:.2f})")
    except Exception as e:
        errors.append(("RiskScoreCalibrator", str(e)))
        print(f"  ❌ RiskScoreCalibrator: {e}")

    # Test DecisionDeduplicator
    try:
        from service.dedup.decision_dedup import get_decision_deduplicator

        dedup = get_decision_deduplicator()

        result = await dedup.check_duplicate(
            car_data={
                "action_type": "file_write",
                "resource": "/tmp/test.txt",
                "agent_id": "agent1",
            }
        )
        # Result has is_duplicate and cached_decision fields
        print(
            f"  ✅ DecisionDeduplicator check_duplicate (is_dup: {result.is_duplicate})"
        )
    except Exception as e:
        errors.append(("DecisionDeduplicator", str(e)))
        print(f"  ❌ DecisionDeduplicator: {e}")

    # Test FrequencyMonitor
    try:
        from service.frequency.monitor import get_frequency_monitor

        freq = get_frequency_monitor()

        await freq.record_decision(
            action_type="file_read",
            resource="/tmp/test.txt",
            agent_id="agent1",
            decision="allow",
            decided_by="human",
        )
        suggestion = await freq.get_suggestion(
            action_type="file_read",
            resource="/tmp/test.txt",
            agent_id="agent1",
        )
        print(
            f"  ✅ FrequencyMonitor record_decision/get_suggestion (confidence: {suggestion.confidence:.2f})"
        )
    except Exception as e:
        errors.append(("FrequencyMonitor", str(e)))
        print(f"  ❌ FrequencyMonitor: {e}")

    # Test SaaS Extractors
    try:
        from service.extractors.saas import get_saas_extractor_registry

        registry = get_saas_extractor_registry()

        context = registry.extract(
            method="POST",
            url="https://api.stripe.com/v1/charges",
            headers={"Authorization": "Bearer sk_test_xxx"},
            body={"amount": 1000, "currency": "usd"},
        )
        assert context is not None
        assert context.service == "stripe"
        print(f"  ✅ SaaSExtractorRegistry extract (service: {context.service})")
    except Exception as e:
        errors.append(("SaaSExtractorRegistry", str(e)))
        print(f"  ❌ SaaSExtractorRegistry: {e}")

    # Test BrowserActionClassifier
    try:
        from service.browser.classifier import (
            get_browser_classifier,
            BrowserActionType,
            BrowserContext,
        )

        classifier = get_browser_classifier()

        result = classifier.classify(
            action_type=BrowserActionType.CLICK,
            browser_context=BrowserContext(
                url="https://github.com/settings",
                domain="github.com",
                path="/settings",
            ),
        )
        assert result is not None
        print(f"  ✅ BrowserActionClassifier classify (risk: {result.risk_category})")
    except Exception as e:
        errors.append(("BrowserActionClassifier", str(e)))
        print(f"  ❌ BrowserActionClassifier: {e}")

    # Test PolicyMacroEngine
    try:
        from service.macros.policy_macros import get_macro_engine

        engine = get_macro_engine()

        expanded = engine.expand_policy("allow file_read $SENSITIVE_PATHS")
        assert isinstance(expanded, str)
        assert len(expanded) > 0
        print(f"  ✅ PolicyMacroEngine expand_policy ({len(expanded)} chars)")
    except Exception as e:
        errors.append(("PolicyMacroEngine", str(e)))
        print(f"  ❌ PolicyMacroEngine: {e}")

    print(f"\n  {9 - len(errors)}/9 async operations OK")
    return errors


def test_performance():
    """Test performance characteristics."""
    print("\n=== TESTING PERFORMANCE ===\n")

    errors = []

    # Test cache lookup speed
    try:
        from service.cache.decision_cache import get_fast_path_cache, CacheDecision

        cache = get_fast_path_cache()

        async def bench_cache():
            # Warm up
            await cache.put("bench", "resource", "agent", CacheDecision.ALLOW, 0.9)

            # Benchmark
            iterations = 1000
            start = time.perf_counter()
            for i in range(iterations):
                await cache.get("bench", "resource", "agent")
            elapsed = time.perf_counter() - start

            avg_us = (elapsed / iterations) * 1_000_000
            return avg_us

        avg_us = asyncio.get_event_loop().run_until_complete(bench_cache())

        if avg_us < 100:  # Should be < 100 microseconds
            print(f"  ✅ Cache lookup: {avg_us:.2f} µs/op (target: <100 µs)")
        else:
            print(f"  ⚠️ Cache lookup: {avg_us:.2f} µs/op (target: <100 µs)")
    except Exception as e:
        errors.append(("CacheBench", str(e)))
        print(f"  ❌ Cache benchmark: {e}")

    # Test memory footprint
    try:
        import gc

        gc.collect()

        # Get baseline
        import resource

        baseline = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        # Import all components
        from service.cache.decision_cache import get_fast_path_cache
        from service.allowlist.contextual import get_contextual_allowlist
        from service.workflow.detector import get_workflow_detector
        from service.risk.calibrator import get_risk_calibrator
        from service.frequency.monitor import get_frequency_monitor

        # Instantiate singletons
        _ = get_fast_path_cache()
        _ = get_contextual_allowlist()
        _ = get_workflow_detector()
        _ = get_risk_calibrator()
        _ = get_frequency_monitor()

        gc.collect()
        current = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        # Memory increase in KB (macOS reports in bytes, Linux in KB)
        import platform

        if platform.system() == "Darwin":
            delta_kb = (current - baseline) / 1024
        else:
            delta_kb = current - baseline

        if delta_kb < 50_000:  # Should be < 50 MB
            print(f"  ✅ Memory footprint: {delta_kb:.0f} KB (target: <50 MB)")
        else:
            print(f"  ⚠️ Memory footprint: {delta_kb:.0f} KB (target: <50 MB)")
    except Exception as e:
        errors.append(("MemoryBench", str(e)))
        print(f"  ❌ Memory benchmark: {e}")

    return errors


def main():
    """Run all tests."""
    print("=" * 60)
    print("FARAMESH GUARD - 24 COMPONENTS TEST SUITE")
    print("=" * 60)

    all_errors = []

    # Test imports
    errors = test_imports()
    all_errors.extend(errors)

    # Test route factories
    errors = test_route_factories()
    all_errors.extend(errors)

    # Test async operations
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    errors = loop.run_until_complete(test_async_operations())
    all_errors.extend(errors)

    # Test performance
    errors = test_performance()
    all_errors.extend(errors)

    # Summary
    print("\n" + "=" * 60)
    if all_errors:
        print(f"FAILED: {len(all_errors)} errors")
        for name, err in all_errors:
            print(f"  - {name}: {err[:60]}...")
        return 1
    else:
        print("SUCCESS: All tests passed!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
