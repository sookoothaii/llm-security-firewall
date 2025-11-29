"""
HAK_GAL v2.3.3: Redis-Backed Session Manager

CRITICAL FIX (P0): Pod-Death Resilience via Redis persistence.
Sessions survive pod restarts, ensuring business continuity.

Architecture:
- Sessions persisted to Redis (not just in-memory)
- In-memory cache for performance (Redis is source of truth)
- Automatic TTL for session expiration
- Tenant isolation via Redis ACL patterns

Creator: Joerg Bollwahn
Date: 2025-01-15
Status: P0 Implementation (v2.3.3)
License: MIT
"""

import asyncio
import json
import logging
from typing import Any, Optional

try:
    import redis.asyncio as redis

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None

from hak_gal.core.session_manager import SessionManager, SessionState
from hak_gal.utils.crypto import CryptoUtils
from hak_gal.utils.tenant_redis_pool import TenantRedisPool
from hak_gal.core.exceptions import SystemError

logger = logging.getLogger(__name__)


class RedisSessionManager(SessionManager):
    """
    Redis-backed SessionManager for Pod-Death Resilience.

    CRITICAL: Sessions are persisted to Redis, not just in-memory.
    This ensures state survives pod restarts.

    Architecture:
    - In-memory cache for performance (fast path)
    - Redis as source of truth (pod-death recovery)
    - Automatic TTL for session expiration
    - Tenant isolation via Redis ACL patterns
    """

    def __init__(
        self,
        tenant_redis_pool: Optional[TenantRedisPool] = None,
        redis_client: Optional[redis.Redis] = None,
        crypto_utils: Optional[CryptoUtils] = None,
        ttl_seconds: int = 3600,  # 1 hour default TTL
    ):
        """
        Initialize Redis-backed SessionManager.

        Args:
            tenant_redis_pool: TenantRedisPool instance (P2: preferred)
            redis_client: Redis async client (backward compatibility)
            crypto_utils: CryptoUtils instance
            ttl_seconds: Session TTL in seconds (default: 3600 = 1 hour)

        Raises:
            ValueError: If neither tenant_redis_pool nor redis_client provided
        """
        super().__init__(crypto_utils=crypto_utils)

        if not HAS_REDIS:
            raise SystemError(
                "Redis not available. Install: pip install redis",
                component="RedisSessionManager",
            )

        self.tenant_redis_pool = tenant_redis_pool
        self.redis_client = redis_client
        self.ttl_seconds = ttl_seconds

        if not tenant_redis_pool and not redis_client:
            raise ValueError(
                "Either tenant_redis_pool (P2) or redis_client (P1) must be provided"
            )

    async def _get_redis_client(self, tenant_id: str) -> redis.Redis:
        """Get Redis client for tenant."""
        if self.tenant_redis_pool:
            # P2: Use tenant-specific client (ACL isolation)
            return await self.tenant_redis_pool.get_tenant_client(tenant_id)
        elif self.redis_client:
            # P1: Use shared client
            return self.redis_client
        else:
            raise ValueError("Redis client not available")

    def _get_redis_key(self, hashed_id: str, tenant_id: str) -> str:
        """Get Redis key for session (matches ACL pattern)."""
        return f"hakgal:tenant:{tenant_id}:session:{hashed_id}"

    async def _save_session_to_redis(
        self, hashed_id: str, tenant_id: str, session: SessionState
    ) -> None:
        """Save session to Redis (with TTL)."""
        try:
            redis_client = await self._get_redis_client(tenant_id)
            redis_key = self._get_redis_key(hashed_id, tenant_id)

            # Serialize to JSON
            session_data = json.dumps(session.model_dump(), default=str)

            # Save with TTL
            await redis_client.setex(redis_key, self.ttl_seconds, session_data)
        except Exception as e:
            logger.error(f"RedisSessionManager: Failed to save session to Redis: {e}")
            # Fail-open: Continue even if Redis fails (for availability)
            # In production, you might want fail-closed

    async def _load_session_from_redis(
        self, hashed_id: str, tenant_id: str
    ) -> Optional[SessionState]:
        """Load session from Redis (bypassing cache)."""
        try:
            redis_client = await self._get_redis_client(tenant_id)
            redis_key = self._get_redis_key(hashed_id, tenant_id)

            session_data = await redis_client.get(redis_key)
            if session_data:
                # Handle both bytes and str (for mock Redis compatibility)
                if isinstance(session_data, bytes):
                    session_data = session_data.decode("utf-8")
                # Deserialize from JSON
                data = json.loads(session_data)
                session = SessionState(**data)
                return session
        except Exception as e:
            logger.warning(
                f"RedisSessionManager: Failed to load session from Redis: {e}"
            )

        return None

    def get_or_create_session(
        self, raw_user_id: str, tenant_id: str = "default"
    ) -> SessionState:
        """
        Get or create session (with Redis persistence).

        CRITICAL: If session exists in Redis but not in cache, load from Redis.
        This ensures pod-death resilience.

        Note: This is a sync method for backward compatibility, but it uses
        async Redis operations internally. For new code, use async_get_or_create_session.
        """
        # Check cache first (fast path)
        hashed_id = self.crypto.hash_session_id(raw_user_id, tenant_id)
        if hashed_id in self._sessions:
            return self._sessions[hashed_id]

        # Load from Redis (pod-death recovery) - sync wrapper
        try:
            session = asyncio.run(self._load_session_from_redis(hashed_id, tenant_id))
            if session:
                self._sessions[hashed_id] = session
                return session
        except Exception as e:
            logger.warning(f"RedisSessionManager: Failed to load from Redis: {e}")

        # Create new session
        session = SessionState()
        self._sessions[hashed_id] = session

        # Persist to Redis (async, fire-and-forget)
        asyncio.create_task(self._save_session_to_redis(hashed_id, tenant_id, session))

        return session

    async def async_get_or_create_session(
        self, raw_user_id: str, tenant_id: str = "default"
    ) -> SessionState:
        """
        Async version of get_or_create_session (preferred for new code).

        CRITICAL: If session exists in Redis but not in cache, load from Redis.
        This ensures pod-death resilience.
        """
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required")

        hashed_id = self.crypto.hash_session_id(raw_user_id, tenant_id)

        # Check cache first (fast path)
        if hashed_id in self._sessions:
            return self._sessions[hashed_id]

        # Load from Redis (pod-death recovery)
        session = await self._load_session_from_redis(hashed_id, tenant_id)
        if session:
            self._sessions[hashed_id] = session
            return session

        # Create new session
        session = SessionState()
        self._sessions[hashed_id] = session

        # Persist to Redis
        await self._save_session_to_redis(hashed_id, tenant_id, session)

        return session

    def update_context(
        self, raw_user_id: str, key: str, value: Any, tenant_id: str = "default"
    ) -> None:
        """Update context data (with Redis persistence)."""
        session = self.get_or_create_session(raw_user_id, tenant_id)
        session.context_data[key] = value

        # Persist to Redis (async, fire-and-forget)
        hashed_id = self.crypto.hash_session_id(raw_user_id, tenant_id)
        asyncio.create_task(self._save_session_to_redis(hashed_id, tenant_id, session))

    async def async_update_context(
        self, raw_user_id: str, key: str, value: Any, tenant_id: str = "default"
    ) -> None:
        """Async version of update_context (preferred for new code)."""
        session = await self.async_get_or_create_session(raw_user_id, tenant_id)
        session.context_data[key] = value

        # Persist to Redis
        hashed_id = self.crypto.hash_session_id(raw_user_id, tenant_id)
        await self._save_session_to_redis(hashed_id, tenant_id, session)

    def clear_cache(self) -> None:
        """
        Clear in-memory cache (simulates pod death).

        CRITICAL: This is used in chaos tests to simulate pod restart.
        After clearing cache, sessions should be recoverable from Redis.
        """
        self._sessions.clear()
        logger.info("RedisSessionManager: Cache cleared (pod death simulation)")

    async def load_session_from_redis(
        self, raw_user_id: str, tenant_id: str
    ) -> Optional[SessionState]:
        """
        Load session from Redis (bypassing cache).

        CRITICAL: This simulates Pod-2 loading session after Pod-1 death.
        """
        hashed_id = self.crypto.hash_session_id(raw_user_id, tenant_id)
        session = await self._load_session_from_redis(hashed_id, tenant_id)

        if session:
            # Update cache
            self._sessions[hashed_id] = session

        return session
