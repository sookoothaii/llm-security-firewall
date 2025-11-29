"""
HAK_GAL v2.3.3: Chaos Test - Pod Death Resilience

CRITICAL TEST (P0): Validates that session state survives pod death.
This test is MANDATORY before production deployment (Kimi K2 Security Audit).

Scenario:
- User has active session in Pod-1
- Pod-1 dies (simulated by clearing in-memory cache)
- User lands on Pod-2
- Expected: Session state is intact, no data loss, no security incident

Creator: Joerg Bollwahn
Date: 2025-01-15
Status: P0 Mandatory Test (v2.3.3)
License: MIT
"""

import pytest

# Import Redis async client
try:
    import redis.asyncio as redis

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None

from hak_gal.core.redis_session_manager import RedisSessionManager


@pytest.mark.asyncio
@pytest.mark.skipif(not HAS_REDIS, reason="Redis not available")
async def test_session_state_survives_pod_death():
    """
    CRITICAL CHAOS TEST (P0): Session state survives pod death.

    Simulates:
    - User has session in Pod-1
    - Pod-1 dies (cache cleared)
    - User lands on Pod-2
    - Expected: Session is intact, no data loss, no security incident

    This test is MANDATORY before production deployment.
    """
    # Setup: Create Redis client (use localhost for testing)
    redis_client = redis.Redis(
        host="localhost",
        port=6379,
        db=0,
        decode_responses=False,
    )

    # Test: Create session manager with Redis persistence
    session_manager = RedisSessionManager(redis_client=redis_client)

    tenant_id = "alpha"
    user_id = "user_123"

    try:
        # Step 1: Create session in Pod-1
        session_1 = await session_manager.async_get_or_create_session(
            tenant_id=tenant_id, raw_user_id=user_id
        )
        session_key_1 = session_manager.crypto.hash_session_id(user_id, tenant_id)

        # Step 2: Add state (e.g., tx_count_1h=5)
        await session_manager.async_update_context(
            raw_user_id=user_id, key="tx_count_1h", value=5, tenant_id=tenant_id
        )

        # Verify state is set
        session_1_reloaded = await session_manager.async_get_or_create_session(
            tenant_id=tenant_id, raw_user_id=user_id
        )
        assert session_1_reloaded.context_data.get("tx_count_1h") == 5

        # Step 3: Simulate Pod-Death - Clear in-memory cache (NOT Redis)
        session_manager.clear_cache()

        # Verify cache is empty (RedisSessionManager uses _sessions from base class)
        assert len(session_manager._sessions) == 0

        # Step 4: Create new session manager instance (Pod-2)
        session_manager_pod2 = RedisSessionManager(redis_client=redis_client)

        # Step 5: Load session from Redis (Pod-2 recovery)
        session_2 = await session_manager_pod2.load_session_from_redis(
            raw_user_id=user_id, tenant_id=tenant_id
        )

        # Step 6: Assert - State is preserved
        assert session_2 is not None, "Session should be recoverable from Redis"
        assert session_2.context_data.get("tx_count_1h") == 5, (
            f"Expected tx_count_1h=5, got {session_2.context_data.get('tx_count_1h')}"
        )

        # Step 7: Assert - Session is still valid (no token expiry)
        # (In this implementation, validity is based on Redis TTL, not explicit token)
        assert session_2.created_at is not None, (
            "Session should have creation timestamp"
        )

        # Step 8: Assert - Can continue using session (no security incident)
        await session_manager_pod2.async_update_context(
            raw_user_id=user_id, key="tx_count_1h", value=6, tenant_id=tenant_id
        )
        session_2_updated = await session_manager_pod2.async_get_or_create_session(
            tenant_id=tenant_id, raw_user_id=user_id
        )
        assert session_2_updated.context_data.get("tx_count_1h") == 6

        print("✅ CHAOS TEST PASSED: Session state survives pod death")

    finally:
        # Cleanup: Delete test session from Redis
        try:
            session_key = session_manager.crypto.hash_session_id(user_id, tenant_id)
            redis_key = f"hakgal:tenant:{tenant_id}:session:{session_key}"
            await redis_client.delete(redis_key)
        except Exception:
            pass
        await redis_client.aclose()


@pytest.mark.asyncio
@pytest.mark.skipif(not HAS_REDIS, reason="Redis not available")
async def test_multiple_sessions_survive_pod_death():
    """
    CHAOS TEST: Multiple sessions survive pod death.

    Simulates: 10,000 active sessions, pod dies, all sessions recoverable.
    """
    redis_client = redis.Redis(
        host="localhost",
        port=6379,
        db=0,
        decode_responses=False,
    )

    session_manager = RedisSessionManager(redis_client=redis_client)
    tenant_id = "alpha"

    # Create 100 sessions (simulating 10,000 in production)
    num_sessions = 100
    user_ids = [f"user_{i}" for i in range(num_sessions)]

    try:
        # Step 1: Create sessions in Pod-1
        for user_id in user_ids:
            await session_manager.async_get_or_create_session(
                tenant_id=tenant_id, raw_user_id=user_id
            )
            await session_manager.async_update_context(
                raw_user_id=user_id,
                key="request_count",
                value=42,
                tenant_id=tenant_id,
            )

        # Step 2: Simulate Pod-Death
        session_manager.clear_cache()

        # Step 3: Recover all sessions in Pod-2
        session_manager_pod2 = RedisSessionManager(redis_client=redis_client)
        recovered_count = 0

        for user_id in user_ids:
            session = await session_manager_pod2.load_session_from_redis(
                raw_user_id=user_id, tenant_id=tenant_id
            )
            if session and session.context_data.get("request_count") == 42:
                recovered_count += 1

        # Step 4: Assert - All sessions recovered
        assert recovered_count == num_sessions, (
            f"Expected {num_sessions} sessions recovered, got {recovered_count}"
        )

        print(
            f"✅ CHAOS TEST PASSED: {recovered_count}/{num_sessions} sessions recovered"
        )

    finally:
        # Cleanup
        for user_id in user_ids:
            try:
                session_key = session_manager.crypto.hash_session_id(user_id, tenant_id)
                redis_key = f"hakgal:tenant:{tenant_id}:session:{session_key}"
                await redis_client.delete(redis_key)
            except Exception:
                pass
        await redis_client.aclose()


@pytest.mark.asyncio
@pytest.mark.skipif(not HAS_REDIS, reason="Redis not available")
async def test_session_trajectory_survives_pod_death():
    """
    CHAOS TEST: Session trajectory (embedding vectors) survive pod death.

    Simulates: User has trajectory buffer with 10 vectors, pod dies, trajectory intact.
    """
    redis_client = redis.Redis(
        host="localhost",
        port=6379,
        db=0,
        decode_responses=False,
    )

    session_manager = RedisSessionManager(redis_client=redis_client)
    tenant_id = "alpha"
    user_id = "user_trajectory_test"

    try:
        # Step 1: Create session and add trajectory vectors
        session_1 = await session_manager.async_get_or_create_session(
            tenant_id=tenant_id, raw_user_id=user_id
        )

        # Add 10 embedding vectors
        for i in range(10):
            vector = [0.1 * i, 0.2 * i, 0.3 * i]  # Dummy embedding
            session_1.trajectory_buffer.append(vector)

        # Persist to Redis (via update_context to trigger save)
        await session_manager.async_update_context(
            raw_user_id=user_id,
            key="trajectory_updated",
            value=True,
            tenant_id=tenant_id,
        )

        # Step 2: Simulate Pod-Death
        session_manager.clear_cache()

        # Step 3: Recover in Pod-2
        session_manager_pod2 = RedisSessionManager(redis_client=redis_client)
        session_2 = await session_manager_pod2.load_session_from_redis(
            raw_user_id=user_id, tenant_id=tenant_id
        )

        # Step 4: Assert - Trajectory is intact
        assert session_2 is not None, "Session should be recoverable"
        assert len(session_2.trajectory_buffer) == 10, (
            f"Expected 10 vectors, got {len(session_2.trajectory_buffer)}"
        )
        assert session_2.trajectory_buffer[0] == [0.0, 0.0, 0.0], (
            "First vector should match"
        )
        assert session_2.trajectory_buffer[9] == [0.9, 1.8, 2.7], (
            "Last vector should match"
        )

        print("✅ CHAOS TEST PASSED: Session trajectory survives pod death")

    finally:
        # Cleanup
        try:
            session_key = session_manager.crypto.hash_session_id(user_id, tenant_id)
            redis_key = f"hakgal:tenant:{tenant_id}:session:{session_key}"
            await redis_client.delete(redis_key)
        except Exception:
            pass
        await redis_client.aclose()
