"""
HAK_GAL v2.3.3: Per-Tenant Redis Sliding Window Rate Limiter

CRITICAL FIX (P1): Replaces global TokenBucket with per-tenant isolation.
Prevents Cross-Tenant DoS attacks.

Architecture:
- Redis Sorted Sets (ZSET) for sliding window
- Atomic Lua script execution (no race conditions)
- Per-tenant isolation via key prefixing

Creator: Joerg Bollwahn
Date: 2025-01-15
Status: P1 Implementation (v2.3.3)
License: MIT
"""

import time
import logging
from typing import Tuple, Optional, Dict

from hak_gal.core.exceptions import SecurityException

logger = logging.getLogger(__name__)

# Lua script for atomic sliding window rate limiting
LUA_SLIDING_WINDOW_SCRIPT = """
-- KEYS[1] = limiter_key
-- ARGV[1] = current_timestamp_ms
-- ARGV[2] = window_size_ms (e.g., 1000)
-- ARGV[3] = max_requests_per_window (e.g., 10)

local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_req = tonumber(ARGV[3])

-- 1. Remove old entries outside window
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

-- 2. Count current entries
local count = redis.call('ZCARD', key)

if count >= max_req then
    -- 3. Block request
    return {0, count} -- {allowed, current_count}
else
    -- 4. Add current request
    redis.call('ZADD', key, now, now .. ':' .. math.random(1000000, 9999999)) -- unique member
    -- 5. Set TTL on key (automatic cleanup)
    redis.call('EXPIRE', key, math.ceil(window / 1000) + 1)
    return {1, count + 1} -- {allowed, new_count}
end
"""


class TenantRateLimiter:
    """
    Per-Tenant Redis Sliding Window Rate Limiter.

    CRITICAL FIX (P1): Replaces global TokenBucket to prevent Cross-Tenant DoS.
    CRITICAL FIX (P2): Uses TenantRedisPool for Redis ACL isolation.

    Features:
    - Sliding Window (not Token Bucket) for fair rate limiting
    - Atomic Lua script execution (no race conditions)
    - Per-tenant isolation via key prefixing
    - Redis ACL isolation (P2)
    - Automatic cleanup via TTL

    Key Schema:
        hakgal:limiter:tenant:{tenant_id}:guard:{guard_name}:window:{window_size_ms}
    """

    def __init__(
        self,
        tenant_redis_pool=None,
        redis_client=None,  # Backward compatibility
        window_ms: int = 1000,
        max_requests: int = 10,
    ):
        """
        Initialize Tenant Rate Limiter.

        CRITICAL FIX (P2): Prefer tenant_redis_pool for Redis ACL isolation.

        Args:
            tenant_redis_pool: TenantRedisPool instance (P2: preferred)
            redis_client: Redis async client (backward compatibility, P1)
            window_ms: Sliding window size in milliseconds (default: 1000 = 1 second)
            max_requests: Maximum requests per window (default: 10)
        """
        # CRITICAL FIX (P2): Use TenantRedisPool for ACL isolation
        if tenant_redis_pool is not None:
            self.tenant_redis_pool = tenant_redis_pool
            self.redis = None  # Will be fetched per-tenant
        elif redis_client is not None:
            # Backward compatibility (P1)
            self.tenant_redis_pool = None
            self.redis = redis_client
            logger.warning(
                "TenantRateLimiter: Using shared redis_client. "
                "For production, use tenant_redis_pool for Redis ACL isolation (P2)."
            )
        else:
            raise ValueError(
                "Either tenant_redis_pool (P2) or redis_client (P1) must be provided"
            )

        self.window_ms = window_ms
        self.max_requests = max_requests

        # Lua script SHA (loaded on first use, per tenant)
        self.lua_sha_cache: Dict[str, str] = {}  # tenant_id -> lua_sha
        self.lua_sha: Optional[str] = None  # P1 backward compatibility
        self._script_loaded = False

        # CRITICAL FIX (Solo-Dev): Metrics tracking for status CLI
        self.total_requests = 0  # Total requests checked
        self.blocked_requests = 0  # Requests blocked by rate limiter

    async def initialize(self, tenant_id: Optional[str] = None) -> None:
        """
        Load Lua script into Redis (call on startup).

        CRITICAL FIX (P2): If using tenant_redis_pool, script is loaded per-tenant.

        Args:
            tenant_id: Optional tenant_id for per-tenant initialization (P2)
        """
        try:
            if self.tenant_redis_pool is not None:
                # P2: Load script per tenant
                if tenant_id:
                    redis_client = await self.tenant_redis_pool.get_tenant_client(
                        tenant_id
                    )
                    lua_sha = await redis_client.script_load(LUA_SLIDING_WINDOW_SCRIPT)
                    self.lua_sha_cache[tenant_id] = lua_sha
                    logger.info(
                        f"TenantRateLimiter: Lua script loaded for tenant {tenant_id} "
                        f"(SHA: {lua_sha[:8]}...)"
                    )
                else:
                    logger.warning(
                        "TenantRateLimiter: tenant_id required for P2 initialization. "
                        "Script will be loaded on first use."
                    )
            else:
                # P1: Load script once
                self.lua_sha = await self.redis.script_load(LUA_SLIDING_WINDOW_SCRIPT)
                self._script_loaded = True
                logger.info(
                    f"TenantRateLimiter: Lua script loaded (SHA: {self.lua_sha[:8]}...)"
                )
        except Exception as e:
            logger.error(f"TenantRateLimiter: Failed to load Lua script: {e}")
            raise

    async def is_allowed(self, tenant_id: str, guard_name: str) -> Tuple[bool, int]:
        """
        Check if request is allowed for tenant/guard combination.

        CRITICAL: Per-tenant isolation - tenant A cannot consume tenant B's quota.

        Args:
            tenant_id: Tenant identifier (required)
            guard_name: Guard name (e.g., "financial_transfer")

        Returns:
            Tuple of (allowed: bool, current_request_count: int)
            - allowed: True if request is allowed, False if rate limit exceeded
            - current_request_count: Current number of requests in window

        Raises:
            SecurityException: If Redis connection fails (fail-closed)
        """
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required (P1: Tenant Isolation)")

        if not guard_name or not guard_name.strip():
            raise ValueError("guard_name is required")

        # CRITICAL FIX (P2): Get tenant-specific Redis client
        if self.tenant_redis_pool is not None:
            redis_client = await self.tenant_redis_pool.get_tenant_client(tenant_id)
            # Load script for this tenant if not cached
            if tenant_id not in self.lua_sha_cache:
                self.lua_sha_cache[tenant_id] = await redis_client.script_load(
                    LUA_SLIDING_WINDOW_SCRIPT
                )
            lua_sha = self.lua_sha_cache[tenant_id]
        else:
            # P1: Use shared client
            redis_client = self.redis
            if not self._script_loaded:
                await self.initialize()
            lua_sha = self.lua_sha

        # Build Redis key with tenant isolation
        # CRITICAL FIX (P2): Key must match Redis ACL pattern
        key = f"hakgal:tenant:{tenant_id}:limiter:guard:{guard_name}:window:{self.window_ms}"

        # Current timestamp in milliseconds
        now_ms = int(time.time() * 1000)

        try:
            # Execute Lua script atomically
            result = await redis_client.evalsha(
                lua_sha,
                1,  # number of keys
                key,
                now_ms,
                self.window_ms,
                self.max_requests,
            )

            # Result: {allowed (0 or 1), current_count}
            allowed_int, count = result
            allowed = bool(allowed_int)

            # CRITICAL FIX (Solo-Dev): Track metrics
            self.total_requests += 1
            if not allowed:
                self.blocked_requests += 1

            logger.debug(
                f"TenantRateLimiter: tenant={tenant_id}, guard={guard_name}, "
                f"allowed={allowed}, count={count}/{self.max_requests}"
            )

            return allowed, int(count)

        except Exception as e:
            # Handle NoScriptError (script not loaded)
            if "NOSCRIPT" in str(e) or "NoScriptError" in str(type(e).__name__):
                logger.warning(
                    f"TenantRateLimiter: Script not loaded for tenant {tenant_id}, reloading..."
                )
                if self.tenant_redis_pool is not None:
                    # P2: Reload for this tenant
                    redis_client = await self.tenant_redis_pool.get_tenant_client(
                        tenant_id
                    )
                    self.lua_sha_cache[tenant_id] = await redis_client.script_load(
                        LUA_SLIDING_WINDOW_SCRIPT
                    )
                else:
                    # P1: Reload once
                    await self.initialize()
                # Retry once
                return await self.is_allowed(tenant_id, guard_name)

            # Fail-closed: Redis failure blocks request
            logger.error(f"TenantRateLimiter: Redis error: {e}")
            raise SecurityException(
                message=f"Rate limiter unavailable: {e}",
                code="RATE_LIMITER_ERROR",
                metadata={
                    "tenant_id": tenant_id,
                    "guard_name": guard_name,
                },
            ) from e

    def get_key(self, tenant_id: str, guard_name: str) -> str:
        """
        Get Redis key for tenant/guard combination (for debugging/monitoring).

        CRITICAL FIX (P2): Key pattern matches Redis ACL pattern.

        Args:
            tenant_id: Tenant identifier
            guard_name: Guard name

        Returns:
            Redis key string
        """
        return f"hakgal:tenant:{tenant_id}:limiter:guard:{guard_name}:window:{self.window_ms}"
