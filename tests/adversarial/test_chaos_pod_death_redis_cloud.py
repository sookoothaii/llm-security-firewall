"""
HAK_GAL v2.3.3: Chaos Test - Pod Death Resilience (Redis Cloud)

CRITICAL TEST (P0): Validates that session state survives pod death using Redis Cloud.
This test uses Redis Cloud instead of local Redis.

Environment Variables Required:
- REDIS_CLOUD_HOST: Redis Cloud host (e.g., redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com)
- REDIS_CLOUD_PORT: Redis Cloud port (e.g., 19088)
- REDIS_CLOUD_USERNAME: Redis Cloud username (e.g., default)
- REDIS_CLOUD_API_KEY: Redis Cloud API Key (used as password)

Creator: Joerg Bollwahn
Date: 2025-01-15
Status: P0 Mandatory Test (v2.3.3) - Redis Cloud Version
License: MIT
"""

import pytest
import os

# Import Redis async client
try:
    import redis.asyncio as redis

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None

from hak_gal.core.redis_session_manager import RedisSessionManager
from hak_gal.utils.crypto import CryptoUtils


def get_redis_cloud_config():
    """
    Get Redis Cloud configuration from environment variables.

    For Google OAuth login: You need the database password, not the API key.
    The API key is for Redis Cloud API access, not for direct Redis connections.

    Get the database password from:
    Redis Cloud Dashboard -> Your Database -> Configuration -> Default User Password
    """
    host = os.getenv(
        "REDIS_CLOUD_HOST", "redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com"
    )
    port = int(os.getenv("REDIS_CLOUD_PORT", "19088"))
    username = os.getenv("REDIS_CLOUD_USERNAME", "default")

    # Try database password first (for Google OAuth users)
    password = os.getenv("REDIS_CLOUD_PASSWORD")

    # Fallback to API key if password not set (for API key users)
    if not password:
        password = os.getenv("REDIS_CLOUD_API_KEY")

    if not password:
        pytest.skip(
            "REDIS_CLOUD_PASSWORD or REDIS_CLOUD_API_KEY environment variable not set. "
            "For Google OAuth: Get database password from Redis Cloud Dashboard -> Database -> Configuration"
        )

    return {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
    }


@pytest.mark.asyncio
@pytest.mark.skipif(not HAS_REDIS, reason="Redis not available")
async def test_session_state_survives_pod_death_redis_cloud():
    """
    CRITICAL CHAOS TEST (P0): Session state survives pod death using Redis Cloud.

    Simulates:
    - User has session in Pod-1
    - Pod-1 dies (cache cleared)
    - User lands on Pod-2
    - Expected: Session state is intact, no data loss, no security incident
    """
    # Setup: Get Redis Cloud config
    config = get_redis_cloud_config()

    # Create Redis client for Redis Cloud
    # For Google OAuth: Use username + database password
    # The password should be the database password from Redis Cloud Dashboard
    redis_client = redis.Redis(
        host=config["host"],
        port=config["port"],
        username=config["username"],
        password=config["password"],  # Database password (not API key)
        db=0,
        decode_responses=False,  # Binary mode for compatibility
    )

    # Test: Create session manager with Redis Cloud
    crypto_utils = CryptoUtils()
    session_manager = RedisSessionManager(
        redis_client=redis_client, crypto_utils=crypto_utils
    )

    tenant_id = "alpha"
    user_id = "user_123_redis_cloud"

    try:
        # Test Redis connection
        await redis_client.ping()
        print(f"Connected to Redis Cloud: {config['host']}:{config['port']}")

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

        # Verify cache is empty
        assert len(session_manager._sessions) == 0

        # Step 4: Create new session manager instance (Pod-2)
        session_manager_pod2 = RedisSessionManager(
            redis_client=redis_client, crypto_utils=crypto_utils
        )

        # Step 5: Load session from Redis Cloud (Pod-2 recovery)
        session_2 = await session_manager_pod2.load_session_from_redis(
            raw_user_id=user_id, tenant_id=tenant_id
        )

        # Step 6: Assert - State is preserved
        assert session_2 is not None, "Session should be recoverable from Redis Cloud"
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

        print("CHAOS TEST PASSED (Redis Cloud): Session state survives pod death")

    finally:
        # Cleanup: Delete test session from Redis Cloud
        try:
            session_key = session_manager.crypto.hash_session_id(user_id, tenant_id)
            redis_key = f"hakgal:tenant:{tenant_id}:session:{session_key}"
            await redis_client.delete(redis_key)
            print(f"Cleaned up test session: {redis_key}")
        except Exception as e:
            print(f"WARNING: Cleanup warning: {e}")
        finally:
            await redis_client.aclose()


@pytest.mark.asyncio
@pytest.mark.skipif(not HAS_REDIS, reason="Redis not available")
async def test_multiple_sessions_survive_pod_death_redis_cloud():
    """
    CHAOS TEST: Multiple sessions survive pod death using Redis Cloud.

    Simulates: 10 active sessions, pod dies, all sessions recoverable.
    """
    config = get_redis_cloud_config()

    redis_client = redis.Redis(
        host=config["host"],
        port=config["port"],
        username=config["username"],
        password=config["password"],  # Database password
        db=0,
        decode_responses=False,
    )

    crypto_utils = CryptoUtils()
    session_manager = RedisSessionManager(
        redis_client=redis_client, crypto_utils=crypto_utils
    )
    tenant_id = "alpha"

    # Create 10 sessions (smaller number for Redis Cloud to avoid quota issues)
    num_sessions = 10
    user_ids = [f"user_redis_cloud_{i}" for i in range(num_sessions)]

    try:
        # Test Redis connection
        await redis_client.ping()
        print(f"Connected to Redis Cloud: {config['host']}:{config['port']}")

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
        session_manager_pod2 = RedisSessionManager(
            redis_client=redis_client, crypto_utils=crypto_utils
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
            f"CHAOS TEST PASSED (Redis Cloud): {recovered_count}/{num_sessions} sessions recovered"
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
