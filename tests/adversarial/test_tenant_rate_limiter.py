"""
HAK_GAL v2.3.3: Per-Tenant Redis Sliding Window Rate Limiter Tests

Tests to prove tenant isolation and sliding window accuracy.

Creator: Joerg Bollwahn
Date: 2025-01-15
Status: P1 Test Suite (v2.3.3)
License: MIT
"""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock

# Try to import redis, but make tests work without it
try:
    import redis.asyncio as redis

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None

from hak_gal.utils.tenant_rate_limiter import TenantRateLimiter
from hak_gal.core.exceptions import SecurityException


@pytest.mark.asyncio
async def test_cross_tenant_rate_limit_isolation():
    """
    Ensure tenant A cannot consume tenant B's quota.

    CRITICAL TEST (P1): This proves tenant isolation.
    """
    # Mock Redis client
    mock_redis = AsyncMock()
    mock_redis.script_load = AsyncMock(return_value="abc123")
    mock_redis.evalsha = AsyncMock()

    # Setup: Tenant A exhausts quota
    def evalsha_side_effect(sha, num_keys, key, now_ms, window_ms, max_req):
        # Extract tenant_id from key
        if "tenant:tenant_a" in key:
            # First 5 requests allowed
            if evalsha_side_effect.tenant_a_count < 5:
                evalsha_side_effect.tenant_a_count += 1
                return [1, evalsha_side_effect.tenant_a_count]  # allowed
            else:
                return [0, 5]  # blocked
        elif "tenant:tenant_b" in key:
            # Tenant B always allowed (not affected by A)
            evalsha_side_effect.tenant_b_count += 1
            return [1, evalsha_side_effect.tenant_b_count]
        return [0, 0]

    evalsha_side_effect.tenant_a_count = 0
    evalsha_side_effect.tenant_b_count = 0
    mock_redis.evalsha.side_effect = evalsha_side_effect

    limiter = TenantRateLimiter(redis_client=mock_redis, window_ms=1000, max_requests=5)

    await limiter.initialize()

    # Tenant A exhausts quota
    for i in range(5):
        allowed, count = await limiter.is_allowed("tenant_a", "test_guard")
        assert allowed is True, f"Tenant A request {i + 1} should be allowed"
        assert count == i + 1

    # Tenant A gets blocked
    allowed, count = await limiter.is_allowed("tenant_a", "test_guard")
    assert allowed is False, "Tenant A should be blocked after 5 requests"
    assert count == 5

    # Tenant B is NOT affected (CRITICAL TEST)
    allowed, count = await limiter.is_allowed("tenant_b", "test_guard")
    assert allowed is True, "Tenant B must NOT be affected by Tenant A's quota"
    assert count == 1, "Tenant B should have its own counter"


@pytest.mark.asyncio
async def test_sliding_window_accuracy():
    """
    Ensure window actually slides (not fixed bucket).

    CRITICAL TEST: Sliding window must allow requests after window expires.
    """
    mock_redis = AsyncMock()
    mock_redis.script_load = AsyncMock(return_value="abc123")

    # Track timestamps
    request_timestamps = []

    def evalsha_side_effect(sha, num_keys, key, now_ms, window_ms, max_req):
        request_timestamps.append(now_ms)

        # Simulate sliding window: remove entries older than window
        current_time = now_ms
        window_start = current_time - window_ms

        # Count entries in window
        in_window = [ts for ts in request_timestamps if ts >= window_start]

        if len(in_window) >= max_req:
            return [0, len(in_window)]  # blocked
        else:
            return [1, len(in_window)]  # allowed

    mock_redis.evalsha.side_effect = evalsha_side_effect

    limiter = TenantRateLimiter(
        redis_client=mock_redis,
        window_ms=1000,  # 1 second window
        max_requests=2,
    )

    await limiter.initialize()

    # 2 requests allowed
    allowed, _ = await limiter.is_allowed("tenant", "test")
    assert allowed is True

    allowed, _ = await limiter.is_allowed("tenant", "test")
    assert allowed is True

    # 3rd blocked
    allowed, _ = await limiter.is_allowed("tenant", "test")
    assert allowed is False

    # Wait 1.1 seconds (window should slide)
    await asyncio.sleep(1.1)

    # Mock time advancement
    original_time = time.time
    time.time = lambda: original_time() + 1.1

    # Now allowed again (window slid)
    allowed, _ = await limiter.is_allowed("tenant", "test")
    assert allowed is True, "Sliding window should allow request after window expires"

    # Restore time
    time.time = original_time


@pytest.mark.asyncio
async def test_redis_failure_fail_closed():
    """
    Ensure Redis failure blocks requests (fail-closed).
    """
    mock_redis = AsyncMock()
    mock_redis.script_load = AsyncMock(return_value="abc123")
    mock_redis.evalsha = AsyncMock(side_effect=Exception("Redis connection failed"))

    limiter = TenantRateLimiter(
        redis_client=mock_redis, window_ms=1000, max_requests=10
    )

    await limiter.initialize()

    # Redis failure should raise SecurityException (fail-closed)
    with pytest.raises(SecurityException) as exc_info:
        await limiter.is_allowed("tenant", "test")

    assert "Rate limiter unavailable" in str(exc_info.value)
    assert exc_info.value.code == "RATE_LIMITER_ERROR"


@pytest.mark.asyncio
async def test_noscript_error_recovery():
    """
    Ensure NoScriptError triggers script reload.
    """
    mock_redis = AsyncMock()
    mock_redis.script_load = AsyncMock(return_value="abc123")

    call_count = 0

    def evalsha_side_effect(sha, num_keys, key, now_ms, window_ms, max_req):
        nonlocal call_count
        call_count += 1

        if call_count == 1:
            # First call: NoScriptError
            raise Exception("NOSCRIPT")
        else:
            # Second call: Success
            return [1, 1]

    mock_redis.evalsha.side_effect = evalsha_side_effect

    limiter = TenantRateLimiter(
        redis_client=mock_redis, window_ms=1000, max_requests=10
    )

    await limiter.initialize()

    # First call should trigger reload and retry
    allowed, count = await limiter.is_allowed("tenant", "test")
    assert allowed is True
    assert call_count == 2, "Should retry after NoScriptError"


@pytest.mark.asyncio
async def test_tenant_id_validation():
    """
    Ensure empty tenant_id raises ValueError.
    """
    mock_redis = AsyncMock()
    mock_redis.script_load = AsyncMock(return_value="abc123")

    limiter = TenantRateLimiter(
        redis_client=mock_redis, window_ms=1000, max_requests=10
    )

    await limiter.initialize()

    # Empty tenant_id should raise ValueError
    with pytest.raises(ValueError) as exc_info:
        await limiter.is_allowed("", "test")

    assert "tenant_id is required" in str(exc_info.value)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
