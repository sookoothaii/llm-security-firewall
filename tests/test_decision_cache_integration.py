"""
Integration Tests for Decision Cache with Real Redis.

Requires Redis Cloud connection (REDIS_URL or REDIS_CLOUD_* env vars).
"""

import pytest
import os
from llm_firewall.cache.decision_cache import get_cached, set_cached


@pytest.mark.skipif(
    not os.getenv("REDIS_URL") and not os.getenv("REDIS_CLOUD_HOST"),
    reason="Redis connection not configured (set REDIS_URL or REDIS_CLOUD_*)",
)
def test_real_redis_connection():
    """Test basic Redis connection."""
    # This test verifies Redis is accessible
    # Actual connection test happens in get_cached/set_cached
    decision = {
        "allowed": True,
        "reason": "Integration test",
        "sanitized_text": "test",
        "risk_score": 0.0,
        "detected_threats": [],
        "metadata": {},
    }

    # Set cache
    set_cached("test_tenant", "integration_test_input", decision, ttl=60)

    # Get cache
    result = get_cached("test_tenant", "integration_test_input")

    # Verify
    assert result is not None
    assert result["allowed"]
    assert result["reason"] == "Integration test"


@pytest.mark.skipif(
    not os.getenv("REDIS_URL") and not os.getenv("REDIS_CLOUD_HOST"),
    reason="Redis connection not configured",
)
def test_cache_ttl_expiration():
    """Test that TTL works correctly (requires manual time check)."""
    decision = {
        "allowed": True,
        "reason": "TTL test",
        "sanitized_text": "test",
        "risk_score": 0.0,
        "detected_threats": [],
        "metadata": {},
    }

    # Set with short TTL
    set_cached("test_tenant", "ttl_test_input", decision, ttl=1)

    # Should be available immediately
    result = get_cached("test_tenant", "ttl_test_input")
    assert result is not None

    # Note: Actual expiration test would require waiting 1+ second
    # This is a basic smoke test
