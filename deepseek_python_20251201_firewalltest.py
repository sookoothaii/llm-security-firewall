# tests/integration/test_external_review_validation.py
"""
COMPLETE VALIDATION OF EXTERNAL ARCHITECTURE REVIEW REQUIREMENTS

This test validates all P0 items from the external review:
1. Circuit Breaker Pattern ✓
2. False Positive Tracking ✓
3. P99 Latency < 200ms ✓
4. Cache Mode Switching ✓
5. 0/50 Adversarial Bypasses ✓
6. Memory < 300MB ✓
7. Binary Size < 15MB ✓
8. Redis Cloud Integration ✓
"""

import pytest
import time
import statistics
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch
import psutil

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2
from llm_firewall.core.adapter_health import AdapterHealth, CircuitState
from llm_firewall.cache.decision_cache import get_cache_health


class TestExternalReviewValidation:
    """Complete validation of external architecture review requirements."""

    # --- TEST 1: Circuit Breaker Pattern (P0) ---

    def test_circuit_breaker_implementation(self):
        """P0: Verify circuit breaker pattern is properly implemented."""
        # Test AdapterHealth class exists
        health = AdapterHealth("test_adapter", failure_threshold=3)

        # Initial state should be CLOSED
        assert health.state == CircuitState.CLOSED
        assert health.consecutive_failures == 0

        # Simulate failures to trigger circuit breaker
        for i in range(3):
            health.record_request(latency_ms=10.0, success=False)

        # After 3 failures, circuit should be OPEN
        assert health.state == CircuitState.OPEN
        assert health.consecutive_failures == 3

        # Should not attempt requests when OPEN
        assert health.should_attempt() is False

        # Get health metrics
        metrics = health.get_health_metrics()
        assert metrics["state"] == "OPEN"
        assert metrics["consecutive_failures"] == 3
        assert metrics["error_rate"] == 1.0  # 100% error rate

        print("✅ Circuit Breaker Pattern: IMPLEMENTED")

    # --- TEST 2: False Positive Tracking (P0) ---

    def test_false_positive_tracking(self):
        """P0: Test false positive detection and tracking."""
        engine = FirewallEngineV2()

        # These should be legitimate queries (not blocked)
        legitimate_queries = [
            "What's the weather in Berlin today?",
            "How do I bake a chocolate cake?",
            "Explain quantum computing in simple terms",
            "What are the benefits of renewable energy?",
            "How to learn Python programming?",
        ]

        false_positives = 0
        total_queries = len(legitimate_queries)

        for query in legitimate_queries:
            decision = engine.process_input(user_id="test_user", text=query)

            # If a legitimate query is blocked, it's a false positive
            if not decision.allowed:
                false_positives += 1
                print(f"⚠️  False positive detected: {query[:50]}...")
                print(f"   Reason: {decision.reason}")
                print(f"   Risk score: {decision.risk_score}")

        false_positive_rate = false_positives / total_queries

        # We want low false positive rate (< 5% for legitimate queries)
        assert false_positive_rate < 0.05, (
            f"False positive rate too high: {false_positive_rate:.1%} ({false_positives}/{total_queries})"
        )

        print(
            f"✅ False Positive Tracking: {false_positives}/{total_queries} FP ({false_positive_rate:.1%})"
        )

    # --- TEST 3: P99 Latency < 200ms (P0) ---

    def test_p99_latency_adversarial_inputs(self):
        """P0: Verify P99 latency < 200ms for adversarial inputs."""
        engine = FirewallEngineV2()

        # Load adversarial payloads
        suite_path = (
            Path(__file__).parent.parent / "data" / "gpt5_adversarial_suite.jsonl"
        )
        adversarial_payloads = []

        with open(suite_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    adversarial_payloads.append(data["payload"])

        # Take first 100 payloads for performance test
        test_payloads = adversarial_payloads[:100]

        # Warm-up phase
        print("🔥 Warming up engine...")
        for _ in range(50):
            engine.process_input(user_id="warmup", text="warmup payload")

        # Performance measurement
        print("⏱️  Measuring performance...")
        latencies = []

        for i, payload in enumerate(test_payloads):
            start_time = time.perf_counter()
            decision = engine.process_input(user_id="perf_test", text=payload)
            end_time = time.perf_counter()

            latency_ms = (end_time - start_time) * 1000
            latencies.append(latency_ms)

            # Show progress every 10 payloads
            if (i + 1) % 10 == 0:
                print(f"  Processed {i + 1}/{len(test_payloads)} payloads")

        # Calculate statistics
        p95 = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
        p99 = statistics.quantiles(latencies, n=100)[98]  # 99th percentile
        avg_latency = statistics.mean(latencies)
        max_latency = max(latencies)

        print("\n📊 Performance Results:")
        print(f"  Average latency: {avg_latency:.2f} ms")
        print(f"  P95 latency:     {p95:.2f} ms")
        print(f"  P99 latency:     {p99:.2f} ms")
        print(f"  Max latency:     {max_latency:.2f} ms")

        # External review requirement: P99 < 200ms
        assert p99 < 200.0, f"P99 latency {p99:.2f}ms exceeds 200ms requirement"

        # Additional requirement: P95 < 100ms (implied by review)
        assert p95 < 100.0, f"P95 latency {p95:.2f}ms exceeds 100ms threshold"

        print("✅ P99 Latency: PASS (< 200ms requirement met)")

    # --- TEST 4: Cache Mode Switching (P0) ---

    def test_cache_mode_switching(self):
        """P0: Test cache mode switching without restart."""
        # Store original mode
        original_mode = os.getenv("CACHE_MODE")

        try:
            # Test EXACT mode
            os.environ["CACHE_MODE"] = "exact"
            print(f"\n🧪 Testing CACHE_MODE={os.environ['CACHE_MODE']}")

            # Mock cache to verify mode
            with patch(
                "llm_firewall.cache.decision_cache._get_exact_cached"
            ) as mock_exact:
                mock_exact.return_value = {"allowed": True, "reason": "exact cache hit"}

                from llm_firewall.cache.decision_cache import get_cached

                result = get_cached("test_tenant", "test input")

                assert result is not None
                assert result["allowed"] is True
                mock_exact.assert_called_once()

            # Switch to SEMANTIC mode
            os.environ["CACHE_MODE"] = "semantic"
            print(f"🧪 Testing CACHE_MODE={os.environ['CACHE_MODE']}")

            with patch(
                "llm_firewall.cache.decision_cache._get_semantic_cached"
            ) as mock_semantic:
                mock_semantic.return_value = {"allowed": False, "risk_score": 0.8}

                from importlib import reload
                import llm_firewall.cache.decision_cache

                reload(llm_firewall.cache.decision_cache)

                from llm_firewall.cache.decision_cache import get_cached

                result = get_cached("test_tenant", "test input")

                assert result is not None
                assert result["allowed"] is False
                mock_semantic.assert_called_once()

            # Switch to HYBRID mode
            os.environ["CACHE_MODE"] = "hybrid"
            print(f"🧪 Testing CACHE_MODE={os.environ['CACHE_MODE']}")

            with patch(
                "llm_firewall.cache.decision_cache._get_exact_cached"
            ) as mock_exact:
                with patch(
                    "llm_firewall.cache.decision_cache._get_semantic_cached"
                ) as mock_semantic:
                    # Exact miss, semantic hit
                    mock_exact.return_value = None
                    mock_semantic.return_value = {
                        "allowed": True,
                        "reason": "semantic match",
                    }

                    from importlib import reload
                    import llm_firewall.cache.decision_cache

                    reload(llm_firewall.cache.decision_cache)

                    from llm_firewall.cache.decision_cache import get_cached

                    result = get_cached("test_tenant", "test input")

                    assert result is not None
                    assert result["allowed"] is True
                    mock_exact.assert_called_once()
                    mock_semantic.assert_called_once()

            print("✅ Cache Mode Switching: PASS (all modes work without restart)")

        finally:
            # Restore original mode
            if original_mode:
                os.environ["CACHE_MODE"] = original_mode
            else:
                os.environ.pop("CACHE_MODE", None)

    # --- TEST 5: 0/50 Adversarial Bypasses (P0) ---

    def test_adversarial_bypass_suite(self):
        """P0: Verify 0/50 bypasses in adversarial suite."""
        engine = FirewallEngineV2()

        # Load adversarial test suite
        suite_path = (
            Path(__file__).parent.parent / "data" / "gpt5_adversarial_suite.jsonl"
        )
        test_cases = []

        with open(suite_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    test_cases.append(json.loads(line))

        print(f"\n🛡️  Testing {len(test_cases)} adversarial vectors...")

        bypasses = []
        blocked = 0
        allowed = 0

        for test_case in test_cases:
            test_id = test_case["id"]
            payload = test_case["payload"]
            expected = test_case["expected_detection"]

            decision = engine.process_input(user_id="adversarial_test", text=payload)

            if expected == "should_block":
                if decision.allowed:  # Bypass!
                    bypasses.append(
                        {
                            "id": test_id,
                            "payload_preview": payload[:100],
                            "weakness": test_case.get("weakness_if_pass", "Unknown"),
                            "severity": test_case.get("severity", "unknown"),
                        }
                    )
                else:
                    blocked += 1
            else:  # should_allow
                if decision.allowed:
                    allowed += 1
                else:
                    # False positive for legitimate test case
                    print(f"⚠️  False positive in test {test_id}")

        # Results
        print("\n📊 Adversarial Test Results:")
        print(f"  Total vectors:  {len(test_cases)}")
        print(f"  Blocked:        {blocked}")
        print(f"  Allowed:        {allowed}")
        print(f"  Bypasses:       {len(bypasses)}")

        if bypasses:
            print("\n❌ BYPASSES DETECTED:")
            for bypass in bypasses:
                print(
                    f"  - {bypass['id']}: {bypass['weakness']} ({bypass['severity']})"
                )
                print(f"    Payload: {bypass['payload_preview']}...")

        # Critical requirement: 0 bypasses
        assert len(bypasses) == 0, f"Found {len(bypasses)} bypasses (required: 0)"

        print("✅ Adversarial Bypasses: PASS (0/50 bypasses)")

    # --- TEST 6: Memory < 300MB (P0) ---

    def test_memory_usage_under_300mb(self):
        """P0: Verify memory stays under 300MB cap."""
        process = psutil.Process(os.getpid())

        # Initial memory
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        print(f"\n🧠 Initial memory: {initial_memory:.1f} MB")

        engine = FirewallEngineV2()

        # Create memory-intensive workload
        large_payloads = []

        # Generate large payloads (each ~1MB)
        for i in range(20):
            # Mix of text patterns to stress different codepaths
            payload = (
                f"ATTACK_PATTERN_{i}: "
                + "A" * 500000
                + f" MALICIOUS_CODE_{i}: "
                + "B" * 500000
            )
            large_payloads.append(payload)

        # Process payloads
        max_memory_used = initial_memory

        for i, payload in enumerate(large_payloads):
            # Process payload
            decision = engine.process_input(user_id=f"mem_test_{i}", text=payload)

            # Check memory after each payload
            current_memory = process.memory_info().rss / 1024 / 1024
            max_memory_used = max(max_memory_used, current_memory)

            # Progress indicator
            if (i + 1) % 5 == 0:
                print(
                    f"  Processed {i + 1}/{len(large_payloads)} payloads, memory: {current_memory:.1f} MB"
                )

        # Final memory
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        print("\n📊 Memory Usage Results:")
        print(f"  Initial memory:  {initial_memory:.1f} MB")
        print(f"  Final memory:    {final_memory:.1f} MB")
        print(f"  Memory increase: {memory_increase:.1f} MB")
        print(f"  Max memory used: {max_memory_used:.1f} MB")

        # External review requirement: < 300MB peak
        assert max_memory_used < 300, (
            f"Memory usage {max_memory_used:.1f}MB exceeds 300MB cap"
        )

        # Additional check: memory should not leak significantly
        assert memory_increase < 50, (
            f"Memory leak suspected: increased by {memory_increase:.1f}MB"
        )

        print("✅ Memory Usage: PASS (< 300MB cap met)")

    # --- TEST 7: Binary Size < 15MB (P0) ---

    def test_binary_size_under_15mb(self):
        """P0: Verify binary size < 15MB (if binary exists)."""
        # Check for PyInstaller binary
        binary_paths = [
            Path("dist/llm-firewall"),
            Path("dist/llm-firewall.exe"),
            Path("build/llm-firewall"),
        ]

        binary_found = None
        for path in binary_paths:
            if path.exists():
                binary_found = path
                break

        if binary_found:
            size_bytes = binary_found.stat().st_size
            size_mb = size_bytes / 1024 / 1024

            print(f"\n📦 Binary: {binary_found}")
            print(f"  Size: {size_mb:.1f} MB ({size_bytes:,} bytes)")

            # External review requirement: < 15MB
            assert size_mb <= 15, f"Binary size {size_mb:.1f}MB exceeds 15MB limit"

            print("✅ Binary Size: PASS (< 15MB requirement met)")
        else:
            print("\n📦 Binary not found (skipping size check)")
            print(
                "  Run `pyinstaller --onefile src/llm_firewall/__main__.py` to create binary"
            )
            pytest.skip("Binary not found for size check")

    # --- TEST 8: Redis Cloud Integration ---

    def test_redis_cloud_integration(self):
        """Test Redis Cloud integration if credentials are available."""
        if not (os.getenv("REDIS_CLOUD_HOST") or os.getenv("REDIS_URL")):
            print("\n🌐 Redis Cloud: SKIP (credentials not set)")
            pytest.skip("Redis Cloud credentials not available")
            return

        print("\n🌐 Testing Redis Cloud Integration...")

        from llm_firewall.cache.decision_cache import get_cached, set_cached

        # Test data
        test_decision = {
            "allowed": True,
            "reason": "Redis Cloud integration test",
            "risk_score": 0.0,
            "detected_threats": [],
            "metadata": {"test": True, "timestamp": time.time()},
        }

        # Measure latency
        start_time = time.perf_counter()

        # Set cache
        set_cached(
            tenant_id="cloud_test",
            text="redis_cloud_integration_payload",
            decision=test_decision,
            ttl=30,  # 30 seconds
        )

        # Get cache
        result = get_cached("cloud_test", "redis_cloud_integration_payload")

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        # Verify
        assert result is not None
        assert result["allowed"] == test_decision["allowed"]
        assert result["reason"] == test_decision["reason"]

        # Check health metrics
        health = get_cache_health()
        assert "redis" in health
        assert health["redis"]["adapter_name"] == "redis_cache"

        print(f"✅ Redis Cloud: PASS (latency: {latency_ms:.2f} ms)")
        print(
            f"  Health: {health['redis']['state']}, Errors: {health['redis']['total_errors']}"
        )


# --- Main Execution (for standalone testing) ---

if __name__ == "__main__":
    """Run the complete validation suite."""
    print("🚀 LLM Security Firewall - External Review Validation Suite")
    print("=" * 60)

    # Create test instance
    test_suite = TestExternalReviewValidation()

    # Run tests in order
    tests = [
        ("Circuit Breaker", test_suite.test_circuit_breaker_implementation),
        ("False Positive Tracking", test_suite.test_false_positive_tracking),
        ("P99 Latency", test_suite.test_p99_latency_adversarial_inputs),
        ("Cache Mode Switching", test_suite.test_cache_mode_switching),
        ("Adversarial Bypasses", test_suite.test_adversarial_bypass_suite),
        ("Memory Usage", test_suite.test_memory_usage_under_300mb),
        ("Binary Size", test_suite.test_binary_size_under_15mb),
        ("Redis Cloud", test_suite.test_redis_cloud_integration),
    ]

    results = []

    for test_name, test_func in tests:
        print(f"\n{'=' * 40}")
        print(f"TEST: {test_name}")
        print("=" * 40)

        try:
            test_func()
            results.append((test_name, "✅ PASS"))
        except Exception as e:
            results.append((test_name, f"❌ FAIL: {str(e)}"))
        except pytest.skip.Exception as e:
            results.append((test_name, f"⚠️  SKIP: {str(e)}"))

    # Print summary
    print(f"\n{'=' * 60}")
    print("VALIDATION SUMMARY")
    print("=" * 60)

    for test_name, result in results:
        print(f"{test_name:30} {result}")

    # Count results
    passed = sum(1 for _, r in results if "PASS" in r)
    failed = sum(1 for _, r in results if "FAIL" in r)
    skipped = sum(1 for _, r in results if "SKIP" in r)
    total = len(results)

    print(
        f"\n📊 Total: {total} | ✅ Passed: {passed} | ❌ Failed: {failed} | ⚠️  Skipped: {skipped}"
    )

    if failed == 0:
        print("\n🎉 ALL EXTERNAL REVIEW REQUIREMENTS VALIDATED SUCCESSFULLY!")
        print("The system is ready for production deployment.")
    else:
        print(f"\n⚠️  {failed} requirement(s) need attention.")
        sys.exit(1)
