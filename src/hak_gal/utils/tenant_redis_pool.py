"""
HAK_GAL v2.3.3: Tenant-Specific Redis Connection Pool

CRITICAL FIX (P2): Redis ACL isolation per tenant.
Prevents cross-tenant data access even if one tenant is compromised.

Architecture:
- Each tenant has own Redis user with ACL restrictions
- Credentials fetched from Vault/KMS
- Tenant-specific connection pools

Creator: Joerg Bollwahn
Date: 2025-01-15
Status: P2 Implementation (v2.3.3)
License: MIT
"""

import logging
from typing import Dict, Optional
import redis.asyncio as redis

logger = logging.getLogger(__name__)


class TenantRedisPool:
    """
    Tenant-Specific Redis Connection Pool Manager.

    CRITICAL FIX (P2): Each tenant has isolated Redis user with ACL restrictions.

    Security Property:
    - Tenant Alpha can only access `hakgal:tenant:alpha:*` keys
    - Tenant Beta can only access `hakgal:tenant:beta:*` keys
    - Compromise of one tenant does NOT grant access to other tenants' data
    """

    def __init__(
        self,
        base_host: str,
        base_port: int = 6379,
        credential_fetcher=None,
    ):
        """
        Initialize Tenant Redis Pool Manager.

        Args:
            base_host: Redis host (e.g., "localhost" or "redis.internal")
            base_port: Redis port (default: 6379)
            credential_fetcher: Callable(tenant_id) -> dict with 'redis_username' and 'redis_password'
                              If None, uses default credentials (NOT for production)
        """
        self.base_host = base_host
        self.base_port = base_port
        self.credential_fetcher = credential_fetcher
        self.tenant_pools: Dict[str, redis.ConnectionPool] = {}

    async def _fetch_tenant_credentials(self, tenant_id: str) -> Dict[str, str]:
        """
        Fetch tenant-specific Redis credentials.

        CRITICAL: In production, this should fetch from Vault/KMS.
        For development, uses default pattern.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Dict with 'redis_username' and 'redis_password'
        """
        if self.credential_fetcher:
            return await self.credential_fetcher(tenant_id)

        # Development fallback (NOT for production)
        logger.warning(
            f"TenantRedisPool: Using default credentials for tenant {tenant_id}. "
            "This is NOT secure for production. Configure credential_fetcher."
        )
        return {
            "redis_username": f"tenant_{tenant_id}",
            "redis_password": f"tenant_{tenant_id}_password",  # MUST be fetched from Vault
        }

    async def get_tenant_client(self, tenant_id: str) -> redis.Redis:
        """
        Get Redis client for specific tenant (with ACL isolation).

        CRITICAL: Each tenant gets its own connection pool with tenant-specific credentials.
        This ensures Redis ACL isolation.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Redis async client configured for tenant-specific ACL

        Raises:
            ValueError: If tenant_id is missing
            SystemError: If credential fetch fails
        """
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required (P2: Redis ACL Isolation)")

        # Check cache (thread-safe)
        if tenant_id in self.tenant_pools:
            pool = self.tenant_pools[tenant_id]
            return redis.Redis(connection_pool=pool)

        # Fetch credentials (from Vault/KMS in production)
        try:
            creds = await self._fetch_tenant_credentials(tenant_id)
            username = creds.get("redis_username", f"tenant_{tenant_id}")
            password = creds.get("redis_password")

            if not password:
                raise ValueError(f"Redis password not found for tenant {tenant_id}")

            # Create tenant-specific connection pool
            pool = redis.ConnectionPool(
                host=self.base_host,
                port=self.base_port,
                username=username,
                password=password,
                db=0,
                max_connections=10,  # Per-tenant pool size
                decode_responses=False,  # Binary mode for Lua scripts
            )

            # Cache pool
            self.tenant_pools[tenant_id] = pool

            logger.info(
                f"TenantRedisPool: Created Redis pool for tenant {tenant_id} "
                f"(user: {username})"
            )

            return redis.Redis(connection_pool=pool)

        except Exception as e:
            logger.error(
                f"TenantRedisPool: Failed to create client for tenant {tenant_id}: {e}"
            )
            raise SystemError(
                f"Failed to create Redis client for tenant {tenant_id}: {e}",
                component="TenantRedisPool",
            ) from e

    def clear_cache(self, tenant_id: Optional[str] = None) -> None:
        """
        Clear connection pool cache.

        Args:
            tenant_id: If provided, clear only this tenant's pool. Otherwise, clear all.
        """
        if tenant_id:
            if tenant_id in self.tenant_pools:
                pool = self.tenant_pools[tenant_id]
                pool.disconnect()
                del self.tenant_pools[tenant_id]
                logger.debug(f"TenantRedisPool: Cleared pool for tenant {tenant_id}")
        else:
            for pool in self.tenant_pools.values():
                pool.disconnect()
            self.tenant_pools.clear()
            logger.debug("TenantRedisPool: Cleared all pools")
