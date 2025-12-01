"""
P99 latency tests for adversarial inputs - P0 Item from external review.

This test suite validates the P0 requirement: P99 latency must be < 200ms for adversarial inputs.
"""

import time
import statistics
import pytest

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


@pytest.mark.performance
@pytest.mark.slow
class TestP99LatencyAdversarial:
    """Test P99 latency requirements from external review."""

    @pytest.fixture(autouse=True)
    def setup(self, adversarial_suite, firewall_engine):
        """Setup test fixtures."""
        self.adversarial_payloads = [
            p["payload"] for p in adversarial_suite[:50] if "payload" in p
        ]
        self.engine = firewall_engine

        if not self.adversarial_payloads:
            pytest.skip("No adversarial payloads available")

    def test_p99_latency_under_200ms(self):
        """P0: P99 latency must be < 200ms for adversarial inputs."""
        latencies = []
        warmup_iterations = 100
        test_iterations = 1000

        # Warm-up phase
        print(f"Warming up with {warmup_iterations} iterations...")
        for i in range(warmup_iterations):
            payload = self.adversarial_payloads[i % len(self.adversarial_payloads)]
            self.engine.process_input(user_id="test", text=payload)

        # Measure adversarial payloads
        print(f"Measuring {test_iterations} iterations...")
        for i in range(test_iterations):
            payload = self.adversarial_payloads[i % len(self.adversarial_payloads)]
            start = time.perf_counter()
            self.engine.process_input(user_id="test", text=payload)
            end = time.perf_counter()
            latencies.append((end - start) * 1000)  # Convert to ms

        # Calculate percentiles
        sorted_latencies = sorted(latencies)
        p99_index = int(0.99 * (len(sorted_latencies) - 1))
        p95_index = int(0.95 * (len(sorted_latencies) - 1))
        p50_index = int(0.50 * (len(sorted_latencies) - 1))

        p99 = sorted_latencies[p99_index]
        p95 = sorted_latencies[p95_index]
        p50 = sorted_latencies[p50_index]

        print(f"P50: {p50:.2f}ms, P95: {p95:.2f}ms, P99: {p99:.2f}ms")
        print(
            f"Min: {min(latencies):.2f}ms, Max: {max(latencies):.2f}ms, Mean: {statistics.mean(latencies):.2f}ms"
        )

        # P0 Requirements
        assert p99 < 200.0, f"P99 latency {p99:.2f}ms exceeds 200ms requirement"
        assert p95 < 100.0, f"P95 latency {p95:.2f}ms exceeds 100ms requirement"

    @pytest.mark.skipif(not HAS_PSUTIL, reason="psutil not installed")
    def test_worst_case_memory_under_300mb(self):
        """P0: Memory must stay under 300MB cap."""
        import os

        process = psutil.Process(os.getpid())

        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        print(f"Initial memory: {initial_memory:.2f}MB")

        # Process large adversarial payloads
        iterations = len(self.adversarial_payloads) * 10  # 500 payloads
        for i, payload in enumerate(self.adversarial_payloads * 10):
            self.engine.process_input(user_id="test", text=payload)
            if i % 100 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024
                print(f"After {i} iterations: {current_memory:.2f}MB")

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        print(f"Final memory: {final_memory:.2f}MB")
        print(f"Memory increase: {memory_increase:.2f}MB")

        assert memory_increase < 300, (
            f"Memory increased by {memory_increase:.0f}MB, exceeds 300MB cap"
        )

    def test_8mb_streaming_buffer_limit(self):
        """Test 8MB streaming buffer limit (mentioned in review)."""
        from tests.utils.helpers import create_large_payload

        # Create payload > 8MB
        large_payload = create_large_payload(9.0)  # 9MB

        start = time.perf_counter()
        decision = self.engine.process_input(user_id="test", text=large_payload)
        end = time.perf_counter()

        processing_time_ms = (end - start) * 1000

        # Should complete within reasonable time despite large payload
        assert processing_time_ms < 2000, (
            f"Processing time {processing_time_ms:.2f}ms exceeds 2s limit for 9MB payload"
        )
        assert decision.reason, "Should have a decision reason"

    def test_recursive_decode_performance(self):
        """Test recursive decode performance (5 layers max)."""
        from tests.utils.helpers import create_encoded_payload

        # Create double-encoded payload (tests normalization layer)
        original = "'; DROP TABLE users; --"
        encoded = create_encoded_payload(original, encoding="double_url")

        latencies = []
        for _ in range(100):
            start = time.perf_counter()
            decision = self.engine.process_input(user_id="test", text=encoded)
            end = time.perf_counter()
            latencies.append((end - start) * 1000)

        p99 = (
            statistics.quantiles(latencies, n=100)[98]
            if len(latencies) >= 100
            else max(latencies)
        )

        # Recursive decode should be fast (< 50ms P99)
        assert p99 < 50.0, (
            f"Recursive decode P99 latency {p99:.2f}ms exceeds 50ms requirement"
        )
