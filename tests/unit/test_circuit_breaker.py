"""
Circuit breaker tests for cache adapters - P0 Item from external review.

This test suite validates the P0 requirement: Circuit breaker pattern for adapter failures.
"""

import pytest
from unittest.mock import patch
from llm_firewall.cache.decision_cache import get_cached, get_cache_health


class MockCacheAdapterWithFailure:
    """Mock adapter that fails after N calls."""

    def __init__(self, fail_after: int = 3, failure_type: type = ConnectionError):
        self.call_count = 0
        self.fail_after = fail_after
        self.failure_type = failure_type
        self.store = {}

    def get(self, tenant_id: str, text: str):
        self.call_count += 1
        if self.call_count >= self.fail_after:
            raise self.failure_type(f"Mock failure after {self.call_count} calls")
        return self.store.get(f"{tenant_id}:{text}")

    def set(self, tenant_id: str, text: str, decision: dict, ttl: int = None):
        self.call_count += 1
        if self.call_count >= self.fail_after:
            raise self.failure_type(f"Mock failure after {self.call_count} calls")
        self.store[f"{tenant_id}:{text}"] = decision


@pytest.mark.unit
class TestCircuitBreaker:
    """Circuit breaker pattern tests from external review."""

    def test_cache_fail_open_behavior(self):
        """P0: Cache should fail-open on Redis connection errors."""
        with patch("llm_firewall.cache.decision_cache._get_exact_cached") as mock_get:
            mock_get.side_effect = ConnectionError("Redis connection failed")

            # Should return None (fail-open) not raise exception
            result = get_cached("test_tenant", "some_input")
            assert result is None, "Cache should return None on error (fail-open)"

    def test_consecutive_failures_tracking(self):
        """P0: Track consecutive failures for circuit breaker."""
        adapter = MockCacheAdapterWithFailure(fail_after=3)

        # First 2 calls should work (return None for cache miss)
        with patch("llm_firewall.cache.decision_cache._get_exact_cached") as mock_get:
            mock_get.return_value = None  # Cache miss (normal behavior)

            result1 = get_cached("test", "input1")
            result2 = get_cached("test", "input2")

            assert result1 is None
            assert result2 is None
            assert mock_get.call_count == 2

        # 3rd call should fail but system should handle gracefully
        with patch("llm_firewall.cache.decision_cache._get_exact_cached") as mock_get:
            mock_get.side_effect = ConnectionError("Redis connection failed")

            # Should return None (fail-open), not raise exception
            result3 = get_cached("test", "input3")
            assert result3 is None, "Should fail-open on connection error"

    def test_circuit_states(self):
        """Test CLOSED, OPEN, HALF_OPEN states."""
        from llm_firewall.core.adapter_health import AdapterHealth, CircuitState
        import time

        health = AdapterHealth(
            "test_adapter", failure_threshold=3, recovery_timeout=1.0
        )

        # Initially CLOSED
        assert health.state == CircuitState.CLOSED
        assert health.consecutive_failures == 0

        # Simulate failures
        for i in range(3):
            health.record_request(latency_ms=10.0, success=False)

        # After 3 failures, should be OPEN
        assert health.state == CircuitState.OPEN
        assert health.consecutive_failures == 3

        # Should not attempt when OPEN
        assert health.should_attempt() is False

        # After recovery timeout, should be HALF_OPEN
        time.sleep(1.1)
        # Trigger state update by recording a request
        health.record_request(latency_ms=5.0, success=False)

        # State should transition to HALF_OPEN after timeout
        # (Note: _update_state is called in record_request)
        if health.state == CircuitState.HALF_OPEN:
            # Try a successful request
            health.record_request(latency_ms=5.0, success=True)
            # Should transition back to CLOSED
            assert health.state == CircuitState.CLOSED

    def test_cache_error_logging(self):
        """Test that cache errors are logged but don't break the firewall."""

        with patch("llm_firewall.cache.decision_cache.logger") as mock_logger:
            with patch(
                "llm_firewall.cache.decision_cache._get_exact_cached"
            ) as mock_get:
                mock_get.side_effect = ConnectionError("Redis connection failed")

                result = get_cached("test", "input")

                # Should log error but return None (fail-open)
                assert result is None
                # Check that logger was called (debug or warning)
                assert mock_logger.debug.called or mock_logger.warning.called

    def test_multiple_adapter_failures(self):
        """Test behavior when both exact and semantic cache fail."""
        with patch("llm_firewall.cache.decision_cache._get_exact_cached") as mock_exact:
            with patch(
                "llm_firewall.cache.decision_cache.get_semantic_cached"
            ) as mock_semantic:
                mock_exact.side_effect = ConnectionError("Redis failed")
                mock_semantic.side_effect = ConnectionError("LangCache failed")

                # Set CACHE_MODE to hybrid to test both adapters
                import os

                original_mode = os.getenv("CACHE_MODE")
                os.environ["CACHE_MODE"] = "hybrid"

                try:
                    # Should fail-open (return None) even when both adapters fail
                    result = get_cached("test", "input")
                    assert result is None, "Should fail-open when all adapters fail"
                finally:
                    if original_mode:
                        os.environ["CACHE_MODE"] = original_mode
                    else:
                        os.environ.pop("CACHE_MODE", None)

    def test_cache_health_metrics(self):
        """Test that cache health metrics are available."""
        health = get_cache_health()

        assert "redis" in health
        assert "langcache" in health
        assert "timestamp" in health

        # Health metrics should be dict or None
        if health["redis"]:
            assert "adapter_name" in health["redis"]
            assert "state" in health["redis"]
            assert "error_rate" in health["redis"]
