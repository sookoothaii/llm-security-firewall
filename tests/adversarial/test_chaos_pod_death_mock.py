"""
HAK_GAL v2.3.3: Chaos Test - Pod Death Resilience (Mock Version)

MOCK TEST: Validates test structure without Redis dependency.
This test uses an in-memory mock Redis to validate the chaos test logic.

Creator: Joerg Bollwahn
Date: 2025-01-15
Status: P0 Mandatory Test (v2.3.3) - Mock Version
License: MIT
"""

import pytest
import asyncio
from typing import Dict, Optional

from hak_gal.core.redis_session_manager import RedisSessionManager
from hak_gal.utils.crypto import CryptoUtils


class MockRedisClient:
    """Mock Redis client for testing without Redis server."""

    def __init__(self):
        self.data: Dict[str, str] = {}  # Store as string for compatibility
        self.ttl: Dict[str, float] = {}

    async def get(self, key: str) -> Optional[bytes]:
        """Get value from mock Redis (returns bytes for compatibility)."""
        if key in self.data:
            # Return as bytes (like real Redis)
            return self.data[key].encode("utf-8")
        return None

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        """Set value with TTL in mock Redis."""
        # Store as string (value is already a string from JSON)
        self.data[key] = value
        self.ttl[key] = asyncio.get_event_loop().time() + ttl
        return True

    async def delete(self, key: str) -> int:
        """Delete key from mock Redis."""
        if key in self.data:
            del self.data[key]
        if key in self.ttl:
            del self.ttl[key]
        return 1

    async def ping(self) -> bool:
        """Ping mock Redis."""
        return True

    async def aclose(self) -> None:
        """Close mock Redis connection."""
        self.data.clear()
        self.ttl.clear()


@pytest.mark.asyncio
async def test_session_state_survives_pod_death_mock():
    """
    MOCK CHAOS TEST (P0): Session state survives pod death (without Redis server).

    Simulates:
    - User has session in Pod-1
    - Pod-1 dies (cache cleared)
    - User lands on Pod-2
    - Expected: Session state is intact, no data loss, no security incident

    This test validates the test structure and logic without requiring Redis.
    """
    # Setup: Create mock Redis client
    mock_redis = MockRedisClient()

    # CRITICAL: Use same CryptoUtils instance for both Pod-1 and Pod-2
    # This ensures same hash IDs (simulating same secret key in production)
    crypto_utils = CryptoUtils()

    # Test: Create session manager with mock Redis
    session_manager = RedisSessionManager(
        redis_client=mock_redis, crypto_utils=crypto_utils
    )

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

        # Manually ensure session is saved to Redis (for testing)
        hashed_id = session_manager.crypto.hash_session_id(user_id, tenant_id)
        session_to_save = await session_manager.async_get_or_create_session(
            tenant_id=tenant_id, raw_user_id=user_id
        )
        await session_manager._save_session_to_redis(
            hashed_id, tenant_id, session_to_save
        )

        # Debug: Verify session was saved to mock Redis
        redis_key = session_manager._get_redis_key(hashed_id, tenant_id)
        saved_data = await mock_redis.get(redis_key)
        assert saved_data is not None, (
            f"Session should be saved to Redis at key {redis_key}"
        )

        # Verify state is set
        session_1_reloaded = await session_manager.async_get_or_create_session(
            tenant_id=tenant_id, raw_user_id=user_id
        )
        assert session_1_reloaded.context_data.get("tx_count_1h") == 5

        # Step 3: Simulate Pod-Death - Clear in-memory cache (NOT Redis)
        session_manager.clear_cache()

        # Verify cache is empty
        assert len(session_manager._sessions) == 0

        # Step 4: Create new session manager instance (Pod-2)
        # CRITICAL: Use same CryptoUtils to ensure same hash IDs
        session_manager_pod2 = RedisSessionManager(
            redis_client=mock_redis, crypto_utils=crypto_utils
        )

        # Step 5: Load session from Redis (Pod-2 recovery)
        # Debug: Check if session exists in Redis before loading
        hashed_id_pod2 = session_manager_pod2.crypto.hash_session_id(user_id, tenant_id)
        redis_key_pod2 = session_manager_pod2._get_redis_key(hashed_id_pod2, tenant_id)
        saved_data_pod2 = await mock_redis.get(redis_key_pod2)
        assert saved_data_pod2 is not None, (
            f"Session should exist in Redis at key {redis_key_pod2} (hashed_id: {hashed_id_pod2[:16]}...)"
        )

        session_2 = await session_manager_pod2.load_session_from_redis(
            raw_user_id=user_id, tenant_id=tenant_id
        )

        # Step 6: Assert - State is preserved
        assert session_2 is not None, (
            f"Session should be recoverable from Redis (key: {redis_key_pod2})"
        )
        assert session_2.context_data.get("tx_count_1h") == 5, (
            f"Expected tx_count_1h=5, got {session_2.context_data.get('tx_count_1h')}"
        )

        # Step 7: Assert - Session is still valid (no token expiry)
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

        print("✅ MOCK CHAOS TEST PASSED: Session state survives pod death")

    finally:
        # Cleanup: Delete test session from mock Redis
        try:
            session_key = session_manager.crypto.hash_session_id(user_id, tenant_id)
            redis_key = f"hakgal:tenant:{tenant_id}:session:{session_key}"
            await mock_redis.delete(redis_key)
        except Exception:
            pass


@pytest.mark.asyncio
async def test_multiple_sessions_survive_pod_death_mock():
    """
    MOCK CHAOS TEST: Multiple sessions survive pod death (without Redis server).

    Simulates: 100 active sessions, pod dies, all sessions recoverable.
    """
    mock_redis = MockRedisClient()

    # CRITICAL: Use same CryptoUtils instance for both Pod-1 and Pod-2
    crypto_utils = CryptoUtils()

    session_manager = RedisSessionManager(
        redis_client=mock_redis, crypto_utils=crypto_utils
    )
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
            # Manually ensure session is saved to Redis (for testing)
            hashed_id = session_manager.crypto.hash_session_id(user_id, tenant_id)
            session_to_save = await session_manager.async_get_or_create_session(
                tenant_id=tenant_id, raw_user_id=user_id
            )
            await session_manager._save_session_to_redis(
                hashed_id, tenant_id, session_to_save
            )

        # Step 2: Simulate Pod-Death
        session_manager.clear_cache()

        # Step 3: Recover all sessions in Pod-2
        # CRITICAL: Use same CryptoUtils to ensure same hash IDs
        session_manager_pod2 = RedisSessionManager(
            redis_client=mock_redis, crypto_utils=crypto_utils
        )
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
            f"✅ MOCK CHAOS TEST PASSED: {recovered_count}/{num_sessions} sessions recovered"
        )

    finally:
        # Cleanup
        for user_id in user_ids:
            try:
                session_key = session_manager.crypto.hash_session_id(user_id, tenant_id)
                redis_key = f"hakgal:tenant:{tenant_id}:session:{session_key}"
                await mock_redis.delete(redis_key)
            except Exception:
                pass


@pytest.mark.asyncio
async def test_session_trajectory_survives_pod_death_mock():
    """
    MOCK CHAOS TEST: Session trajectory (embedding vectors) survive pod death.

    Simulates: User has trajectory buffer with 10 vectors, pod dies, trajectory intact.
    """
    mock_redis = MockRedisClient()

    # CRITICAL: Use same CryptoUtils instance for both Pod-1 and Pod-2
    crypto_utils = CryptoUtils()

    session_manager = RedisSessionManager(
        redis_client=mock_redis, crypto_utils=crypto_utils
    )
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

        # Manually save trajectory to Redis
        hashed_id = session_manager.crypto.hash_session_id(user_id, tenant_id)
        await session_manager._save_session_to_redis(hashed_id, tenant_id, session_1)

        # Step 2: Simulate Pod-Death
        session_manager.clear_cache()

        # Step 3: Recover in Pod-2
        # CRITICAL: Use same CryptoUtils to ensure same hash IDs
        session_manager_pod2 = RedisSessionManager(
            redis_client=mock_redis, crypto_utils=crypto_utils
        )
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
        # Use approximate comparison for floating-point (precision issue)
        last_vector = session_2.trajectory_buffer[9]
        assert abs(last_vector[0] - 0.9) < 0.001, (
            f"First element should be ~0.9, got {last_vector[0]}"
        )
        assert abs(last_vector[1] - 1.8) < 0.001, (
            f"Second element should be ~1.8, got {last_vector[1]}"
        )
        assert abs(last_vector[2] - 2.7) < 0.001, (
            f"Third element should be ~2.7, got {last_vector[2]}"
        )

        print("✅ MOCK CHAOS TEST PASSED: Session trajectory survives pod death")

    finally:
        # Cleanup
        try:
            session_key = session_manager.crypto.hash_session_id(user_id, tenant_id)
            redis_key = f"hakgal:tenant:{tenant_id}:session:{session_key}"
            await mock_redis.delete(redis_key)
        except Exception:
            pass
