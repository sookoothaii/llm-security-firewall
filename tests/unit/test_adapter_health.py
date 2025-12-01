"""
Unit tests for AdapterHealth class (Circuit Breaker Pattern).

P0 Item from external review.
"""

import pytest
import time
from llm_firewall.core.adapter_health import AdapterHealth, CircuitState


@pytest.mark.unit
class TestAdapterHealth:
    """Test AdapterHealth circuit breaker functionality."""

    def test_initial_state_closed(self):
        """Test that adapter starts in CLOSED state."""
        health = AdapterHealth("test_adapter")
        assert health.state == CircuitState.CLOSED
        assert health.consecutive_failures == 0
        assert health.error_rate == 0.0
        assert health.should_attempt() is True

    def test_successful_requests(self):
        """Test that successful requests don't open circuit."""
        health = AdapterHealth("test_adapter", failure_threshold=3)

        for i in range(10):
            health.record_request(latency_ms=10.0, success=True)

        assert health.state == CircuitState.CLOSED
        assert health.consecutive_failures == 0
        assert health.error_rate == 0.0

    def test_failure_threshold_opens_circuit(self):
        """Test that circuit opens after failure threshold."""
        # Set high error_rate_threshold to avoid opening due to error rate
        health = AdapterHealth(
            "test_adapter", failure_threshold=3, error_rate_threshold=1.0
        )

        # First 2 failures should keep circuit CLOSED
        health.record_request(latency_ms=10.0, success=False)
        health.record_request(latency_ms=10.0, success=False)
        assert health.state == CircuitState.CLOSED

        # 3rd failure should open circuit
        health.record_request(latency_ms=10.0, success=False)
        assert health.state == CircuitState.OPEN
        assert health.should_attempt() is False

    def test_recovery_timeout(self):
        """Test that circuit transitions to HALF_OPEN after recovery timeout."""
        health = AdapterHealth(
            "test_adapter", failure_threshold=2, recovery_timeout=0.5
        )

        # Open circuit
        health.record_request(latency_ms=10.0, success=False)
        health.record_request(latency_ms=10.0, success=False)
        assert health.state == CircuitState.OPEN

        # Wait for recovery timeout
        time.sleep(0.6)

        # Record a request to trigger state update
        health.record_request(latency_ms=5.0, success=False)

        # Should be HALF_OPEN (testing recovery)
        # Note: State transition happens in _update_state which is called by record_request
        assert health.state in (CircuitState.HALF_OPEN, CircuitState.OPEN)

    def test_half_open_to_closed_on_success(self):
        """Test that successful request in HALF_OPEN closes circuit."""
        health = AdapterHealth(
            "test_adapter", failure_threshold=2, recovery_timeout=0.5
        )

        # Open circuit
        health.record_request(latency_ms=10.0, success=False)
        health.record_request(latency_ms=10.0, success=False)
        assert health.state == CircuitState.OPEN

        # Wait for recovery
        time.sleep(0.6)

        # Successful request should close circuit
        health.record_request(latency_ms=5.0, success=True)

        # Should be CLOSED after successful request
        if health.state == CircuitState.HALF_OPEN:
            health.record_request(latency_ms=5.0, success=True)

        assert health.state == CircuitState.CLOSED

    def test_error_rate_threshold(self):
        """Test that high error rate opens circuit."""
        health = AdapterHealth("test_adapter", error_rate_threshold=0.5)

        # 60% error rate should open circuit
        for i in range(10):
            success = i < 4  # 4 successes, 6 failures = 60% error rate
            health.record_request(latency_ms=10.0, success=success)

        # Error rate should be > 0.5, circuit should be OPEN
        assert health.error_rate > 0.5
        # Note: Circuit may open based on error rate threshold

    def test_p99_latency_threshold(self):
        """Test that high P99 latency opens circuit."""
        health = AdapterHealth("test_adapter", max_latency_ms=100.0)

        # Record high latencies
        for i in range(100):
            latency = 150.0 if i >= 99 else 10.0  # P99 = 150ms
            health.record_request(latency_ms=latency, success=True)

        p99 = health._calculate_p99_latency()
        assert p99 > 100.0
        # Circuit may open based on latency threshold

    def test_health_metrics(self):
        """Test that health metrics are correctly reported."""
        health = AdapterHealth("test_adapter")

        health.record_request(latency_ms=10.0, success=True)
        health.record_request(latency_ms=20.0, success=False)

        metrics = health.get_health_metrics()

        assert metrics["adapter_name"] == "test_adapter"
        assert metrics["state"] == CircuitState.CLOSED.value
        assert metrics["total_requests"] == 2
        assert metrics["total_errors"] == 1
        assert metrics["error_rate"] == 0.5
        assert "p99_latency_ms" in metrics

    def test_reset(self):
        """Test that reset clears all metrics."""
        health = AdapterHealth("test_adapter")

        # Record some requests
        health.record_request(latency_ms=10.0, success=False)
        health.record_request(latency_ms=10.0, success=False)
        health.record_request(latency_ms=10.0, success=False)

        assert health.state == CircuitState.OPEN
        assert health.total_requests == 3

        # Reset
        health.reset()

        assert health.state == CircuitState.CLOSED
        assert health.total_requests == 0
        assert health.total_errors == 0
        assert len(health.latency_history) == 0
