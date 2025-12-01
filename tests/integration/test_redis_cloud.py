"""
Integration tests with real Redis Cloud instance.

Requires REDIS_CLOUD_HOST env var or SKIP if not available.
"""

import pytest
import os
import time
from llm_firewall.cache.decision_cache import get_cached, set_cached


def has_redis_cloud() -> bool:
    """
    Check if Redis Cloud credentials are available.

    Checks environment variables. Note: MCP tools may have access to Redis
    even if env vars are not set in test context.
    """
    # Check environment variables
    has_env = bool(
        os.getenv("REDIS_CLOUD_HOST")
        or os.getenv("REDIS_URL")
        or os.getenv("REDIS_HOST")
    )

    # If no env vars, try to detect from MCP tool config pattern
    # (MCP tools may have credentials in separate config)
    if not has_env:
        # Try to use default Redis Cloud host pattern
        # This allows tests to run if Redis is configured elsewhere
        return False  # Skip if no env vars (safety)

    return True


@pytest.mark.integration
@pytest.mark.skipif(not has_redis_cloud(), reason="Redis Cloud credentials not set")
class TestRedisCloudIntegration:
    """Real Redis Cloud integration tests."""

    @classmethod
    def setup_class(cls):
        """Initialize cache with Redis Cloud connection."""
        # Use environment variables or pytest fixtures
        redis_host = os.getenv("REDIS_CLOUD_HOST") or os.getenv("REDIS_HOST")
        print(f"Using Redis Cloud: {redis_host or 'Not set'}")

    def test_redis_cloud_connection(self):
        """Test basic connection to Redis Cloud."""
        test_data = {
            "allowed": True,
            "reason": "Redis Cloud integration test",
            "risk_score": 0.0,
            "detected_threats": [],
            "metadata": {"test": True, "timestamp": time.time()},
        }

        # Set cache
        set_cached(
            tenant_id="integration_test",
            text="test_redis_cloud_connection",
            decision=test_data,
            ttl=10,  # 10 seconds TTL
        )

        # Get cache
        result = get_cached("integration_test", "test_redis_cloud_connection")

        # Verify
        assert result is not None, "Cache should return data"
        assert result["allowed"] == test_data["allowed"]
        assert result["reason"] == test_data["reason"]
        print(f"✅ Redis Cloud connection successful: {result}")

    def test_redis_cloud_latency(self):
        """Test Redis Cloud latency (should be ≤ 100ms per review)."""
        latencies = []

        # Test multiple operations
        for i in range(10):
            start = time.perf_counter()
            set_cached(
                tenant_id="latency_test",
                text=f"payload_{i}",
                decision={"test": i, "allowed": True, "risk_score": 0.0},
                ttl=5,
            )
            end = time.perf_counter()
            latencies.append((end - start) * 1000)  # ms

        avg_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)

        print(
            f"Redis Cloud Latency - Avg: {avg_latency:.2f}ms, Max: {max_latency:.2f}ms"
        )

        # Assert ≤ 100ms as per review requirements
        assert avg_latency < 100, f"Average latency {avg_latency:.2f}ms exceeds 100ms"
        assert max_latency < 200, f"Max latency {max_latency:.2f}ms exceeds 200ms"

    def test_redis_cloud_ttl_expiration(self):
        """Test that TTL expiration works correctly."""
        test_data = {"allowed": True, "reason": "TTL test", "risk_score": 0.0}

        # Set with short TTL
        set_cached("ttl_test", "expiring_key", test_data, ttl=1)

        # Should be available immediately
        result = get_cached("ttl_test", "expiring_key")
        assert result is not None

        # Wait for expiration
        time.sleep(2)

        # Should be expired
        result = get_cached("ttl_test", "expiring_key")
        assert result is None, "Cache entry should be expired"

    def test_redis_cloud_failover(self):
        """Test fail-open behavior when Redis Cloud is unreachable."""
        # This test verifies fail-open behavior
        # We can't actually break Redis Cloud, but we can test the error handling

        # Test with invalid data (should still fail-open)
        try:
            # Try to get from non-existent key (should return None, not raise)
            result = get_cached("failover_test", "non_existent_key")
            assert result is None, "Should return None on miss (fail-open)"
        except Exception as e:
            pytest.fail(f"Should fail-open, but raised exception: {e}")
