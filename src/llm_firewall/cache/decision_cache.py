"""
HAK_GAL Decision Cache - Redis/LangCache-Backed Firewall Decision Caching

Performance optimization: Cache firewall decisions after normalization layer
to achieve < 1 ms hit latency for repeated prompts.

Architecture:
- Supports Redis (exact match) and LangCache (semantic search)
- Reuses existing TenantRedisPool infrastructure
- Fail-open: Cache errors don't break firewall operation
- Cache key (Redis): fw:v1:tenant:{tenant_id}:dec:{sha256(text)[:16]}
- TTL: 3600s (configurable via REDIS_TTL env)

Creator: Implementation Order (2025-12-01)
Status: P0 Performance Optimization
License: MIT
"""

import json
import hashlib
import logging
import os
import time
from typing import Optional, Dict, Any

try:
    from redis.exceptions import RedisError
    import redis  # Sync Redis client
    import redis.asyncio as redis_async  # Async Redis client (for future use)

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    RedisError = Exception  # type: ignore
    redis = None  # type: ignore
    redis_async = None  # type: ignore

# LangCache support via adapter
try:
    from llm_firewall.cache.langcache_adapter import (
        get_semantic_cached,
        set_semantic_cached,
    )

    HAS_LANGCACHE = True
except ImportError:
    HAS_LANGCACHE = False
    get_semantic_cached = None  # type: ignore
    set_semantic_cached = None  # type: ignore

logger = logging.getLogger(__name__)

# Global TenantRedisPool instance (set by initialization)
_redis_pool: Optional[Any] = None

# Adapter health monitoring (P0 - Circuit Breaker Pattern)
try:
    from llm_firewall.core.adapter_health import AdapterHealth

    HAS_ADAPTER_HEALTH = True
except ImportError:
    HAS_ADAPTER_HEALTH = False
    AdapterHealth = None  # type: ignore

# Global health monitors
if HAS_ADAPTER_HEALTH and AdapterHealth is not None:
    _redis_health = AdapterHealth(
        "redis_cache", failure_threshold=3, recovery_timeout=30.0
    )
    _langcache_health = AdapterHealth(
        "langcache", failure_threshold=2, recovery_timeout=30.0
    )
else:
    _redis_health = None  # type: ignore
    _langcache_health = None  # type: ignore


def _get_redis_pool():
    """Get global TenantRedisPool instance."""
    global _redis_pool
    return _redis_pool


def _get_cache_mode() -> str:
    """Get cache mode from environment variable."""
    mode = os.getenv("CACHE_MODE", "exact").lower()
    if mode not in ("exact", "semantic", "hybrid"):
        logger.warning(f"Invalid CACHE_MODE '{mode}', defaulting to 'exact'")
        return "exact"
    return mode


def _use_semantic_cache() -> bool:
    """Check if semantic cache (LangCache) should be used."""
    mode = _get_cache_mode()
    return mode in ("semantic", "hybrid") and HAS_LANGCACHE


def initialize_cache(redis_pool=None):
    """
    Initialize decision cache with TenantRedisPool instance.

    Args:
        redis_pool: TenantRedisPool instance (optional, can be set via env)
    """
    global _redis_pool
    if redis_pool:
        _redis_pool = redis_pool
        logger.info("Decision cache initialized with TenantRedisPool")
    else:
        # Try to get from environment or use fallback
        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            logger.info("Decision cache using REDIS_URL from environment")
        else:
            logger.warning(
                "Decision cache: No TenantRedisPool provided and no REDIS_URL. "
                "Cache will be disabled (fail-open)."
            )


def _key(tenant_id: str, text: str) -> str:
    """
    Generate cache key for decision.

    Args:
        tenant_id: Tenant identifier
        text: Normalized text (after Layer 0.25)

    Returns:
        Cache key: fw:v1:tenant:{tenant_id}:dec:{sha256(text)[:16]}
    """
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return f"fw:v1:tenant:{tenant_id}:dec:{h}"


async def _get_cached_async(tenant_id: str, text: str) -> Optional[Dict[str, Any]]:
    """
    Async implementation of get_cached.

    Args:
        tenant_id: Tenant identifier
        text: Normalized text (after Layer 0.25)

    Returns:
        Cached decision dict or None (fail-open on cache errors)
    """
    if not tenant_id or not tenant_id.strip():
        tenant_id = "default"

    try:
        redis_pool = _get_redis_pool()
        if redis_pool:
            # Use TenantRedisPool (preferred)
            client = await redis_pool.get_tenant_client(tenant_id)
        else:
            # Fallback to REDIS_URL or REDIS_CLOUD_* env vars
            redis_url = os.getenv("REDIS_URL")
            if redis_url:
                client = redis_async.from_url(
                    redis_url, socket_timeout=0.1, decode_responses=False
                )
            else:
                # Try REDIS_CLOUD_* env vars
                redis_host = os.getenv("REDIS_CLOUD_HOST") or os.getenv("REDIS_HOST")
                redis_port_str = os.getenv("REDIS_CLOUD_PORT") or os.getenv(
                    "REDIS_PORT", "6379"
                )
                redis_port = int(redis_port_str) if redis_port_str else 6379
                redis_username = os.getenv("REDIS_CLOUD_USERNAME") or os.getenv(
                    "REDIS_USERNAME"
                )
                redis_password = os.getenv("REDIS_CLOUD_PASSWORD") or os.getenv(
                    "REDIS_PASSWORD"
                )

                if not redis_host or not redis_password:
                    return None

                client = redis_async.Redis(
                    host=redis_host,
                    port=redis_port,
                    username=redis_username,
                    password=redis_password,
                    decode_responses=False,
                    socket_timeout=0.1,
                )

        key = _key(tenant_id, text)
        raw = await client.get(key)
        if raw:
            # Handle both bytes and str
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            decision = json.loads(raw)
            logger.debug(f"[Redis] Exact HIT (async) for tenant {tenant_id}")
            return decision
        return None
    except RedisError as e:
        logger.debug("Redis cache miss (RedisError): %s", str(e)[:100])
        return None
    except Exception as e:
        logger.debug("Async cache get failed: %s", str(e)[:100])
        return None


async def _set_cached_async(
    tenant_id: str, text: str, decision: Dict[str, Any], ttl: Optional[int] = None
) -> None:
    """
    Async implementation of set_cached.

    Args:
        tenant_id: Tenant identifier
        text: Normalized text (after Layer 0.25)
        decision: Decision dict to cache
        ttl: Time-to-live in seconds (default: 3600, or REDIS_TTL env var)
    """
    if not tenant_id or not tenant_id.strip():
        tenant_id = "default"

    if ttl is None:
        ttl = int(os.getenv("REDIS_TTL", "3600"))

    try:
        redis_pool = _get_redis_pool()
        if redis_pool:
            # Use TenantRedisPool (preferred)
            client = await redis_pool.get_tenant_client(tenant_id)
        else:
            # Fallback to REDIS_URL or REDIS_CLOUD_* env vars
            redis_url = os.getenv("REDIS_URL")
            if redis_url:
                client = redis_async.from_url(
                    redis_url, socket_timeout=0.1, decode_responses=False
                )
            else:
                # Try REDIS_CLOUD_* env vars
                redis_host = os.getenv("REDIS_CLOUD_HOST") or os.getenv("REDIS_HOST")
                redis_port_str = os.getenv("REDIS_CLOUD_PORT") or os.getenv(
                    "REDIS_PORT", "6379"
                )
                redis_port = int(redis_port_str) if redis_port_str else 6379
                redis_username = os.getenv("REDIS_CLOUD_USERNAME") or os.getenv(
                    "REDIS_USERNAME"
                )
                redis_password = os.getenv("REDIS_CLOUD_PASSWORD") or os.getenv(
                    "REDIS_PASSWORD"
                )

                if not redis_host or not redis_password:
                    return

                client = redis_async.Redis(
                    host=redis_host,
                    port=redis_port,
                    username=redis_username,
                    password=redis_password,
                    decode_responses=False,
                    socket_timeout=0.1,
                )

        key = _key(tenant_id, text)
        value = json.dumps(decision)
        await client.setex(key, ttl, value)
    except RedisError as e:
        logger.info("Redis cache write failed (RedisError): %s", str(e)[:100])
    except Exception as e:
        logger.debug("Redis cache write failed (Exception): %s", str(e)[:100])


def get_cached(tenant_id: str, text: str) -> Optional[Dict[str, Any]]:
    """
    Get cached firewall decision (sync implementation).

    Supports hybrid mode: Exact (Redis) → Semantic (LangCache) → Miss

    Args:
        tenant_id: Tenant identifier (defaults to "default" if not provided)
        text: Normalized text (after Layer 0.25)

    Returns:
        Cached decision dict or None (fail-open on cache errors)
    """
    return get_hybrid_cached(tenant_id, text)


def get_hybrid_cached(tenant_id: str, text: str) -> Optional[Dict[str, Any]]:
    """
    Get cached firewall decision using hybrid cache strategy.

    Strategy (CACHE_MODE=hybrid):
    1. Exact match (Redis) → Hit? Return (fastest)
    2. Semantic search (LangCache) → Hit? Return (similar)
    3. Miss → Return None (fall through to pipeline)

    Args:
        tenant_id: Tenant identifier (defaults to "default" if not provided)
        text: Normalized text (after Layer 0.25)

    Returns:
        Cached decision dict or None (fail-open on cache errors)
    """
    if not tenant_id or not tenant_id.strip():
        tenant_id = "default"

    cache_mode = _get_cache_mode()

    # Step 1: Try exact match (Redis) if mode is exact or hybrid
    if cache_mode in ("exact", "hybrid"):
        try:
            decision = _get_exact_cached(tenant_id, text)
            if decision:
                return decision
        except Exception as e:
            logger.debug(f"[Hybrid Cache] Exact cache error (fail-open): {e}")
            # Fail-open: Continue to semantic cache

    # Step 2: Try semantic search (LangCache) if mode is semantic or hybrid
    if cache_mode in ("semantic", "hybrid") and _use_semantic_cache():
        try:
            decision = get_semantic_cached(text, tenant_id)
            if decision:
                return decision
        except Exception as e:
            logger.debug(f"[Hybrid Cache] Semantic cache error (fail-open): {e}")
            # Fail-open: Continue to pipeline

    # Step 3: Miss
    return None


def _get_exact_cached(tenant_id: str, text: str) -> Optional[Dict[str, Any]]:
    """Get cached decision using exact match (Redis) with circuit breaker."""
    if not HAS_REDIS:
        return None

    # Check circuit breaker
    if _redis_health and not _redis_health.should_attempt():
        logger.warning("Redis cache circuit breaker OPEN, failing open")
        return None

    start_time = time.perf_counter()

    try:
        # Get Redis client (sync)
        redis_pool = _get_redis_pool()
        if redis_pool:
            # Use TenantRedisPool - need to get sync client
            # For now, fall back to direct connection
            pass

        # Try REDIS_URL or REDIS_CLOUD_* env vars
        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            client = redis.from_url(
                redis_url, socket_timeout=1.0, decode_responses=False
            )
        else:
            # Try REDIS_CLOUD_* env vars
            redis_host = os.getenv("REDIS_CLOUD_HOST") or os.getenv("REDIS_HOST")
            redis_port_str = os.getenv("REDIS_CLOUD_PORT") or os.getenv(
                "REDIS_PORT", "6379"
            )
            redis_port = int(redis_port_str) if redis_port_str else 6379
            redis_username = os.getenv("REDIS_CLOUD_USERNAME") or os.getenv(
                "REDIS_USERNAME"
            )
            redis_password = os.getenv("REDIS_CLOUD_PASSWORD") or os.getenv(
                "REDIS_PASSWORD"
            )

            if not redis_host or not redis_password:
                return None

            # Use sync Redis client (not async)
            # Increased timeout for Redis Cloud (network latency)
            client = redis.Redis(
                host=redis_host,
                port=redis_port,
                username=redis_username,
                password=redis_password,
                decode_responses=False,
                socket_timeout=1.0,  # 1s timeout for Redis Cloud
                socket_connect_timeout=2.0,
            )

        key = _key(tenant_id, text)
        raw = client.get(key)
        if raw:
            # Handle both bytes and str
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            decision = json.loads(raw)
            logger.debug(f"[Redis] Exact HIT for tenant {tenant_id}")

            # Record successful request
            if _redis_health:
                latency_ms = (time.perf_counter() - start_time) * 1000
                _redis_health.record_request(latency_ms, success=True)

            return decision

        # Cache miss (not an error)
        if _redis_health:
            latency_ms = (time.perf_counter() - start_time) * 1000
            _redis_health.record_request(latency_ms, success=True)

        return None
    except RedisError as e:
        logger.debug("Redis cache miss (RedisError): %s", str(e)[:100])

        # Record failed request
        if _redis_health:
            latency_ms = (time.perf_counter() - start_time) * 1000
            _redis_health.record_request(latency_ms, success=False)

        return None
    except Exception as e:
        logger.debug("Exact cache get failed: %s", str(e)[:100])

        # Record failed request
        if _redis_health:
            latency_ms = (time.perf_counter() - start_time) * 1000
            _redis_health.record_request(latency_ms, success=False)

        return None


def set_cached(
    tenant_id: str, text: str, decision: Dict[str, Any], ttl: Optional[int] = None
) -> None:
    """
    Cache firewall decision (sync implementation).

    Supports hybrid mode: Write to both exact (Redis) and semantic (LangCache) caches.

    Args:
        tenant_id: Tenant identifier (defaults to "default" if not provided)
        text: Normalized text (after Layer 0.25)
        decision: Decision dict to cache
        ttl: Time-to-live in seconds (default: 3600, or REDIS_TTL env var)
    """
    set_hybrid_cached(tenant_id, text, decision, ttl)


def set_hybrid_cached(
    tenant_id: str, text: str, decision: Dict[str, Any], ttl: Optional[int] = None
) -> None:
    """
    Store decision in both exact and semantic caches (hybrid mode) with circuit breaker.

    Strategy:
    - If CACHE_MODE=exact: Write to Redis only
    - If CACHE_MODE=semantic: Write to LangCache only
    - If CACHE_MODE=hybrid: Write to both (fail-open on errors)

    Args:
        tenant_id: Tenant identifier (defaults to "default" if not provided)
        text: Normalized text (after Layer 0.25)
        decision: Decision dict to cache
        ttl: Time-to-live in seconds (default: 3600, or REDIS_TTL env var)
    """
    if not tenant_id or not tenant_id.strip():
        tenant_id = "default"

    if ttl is None:
        ttl = int(os.getenv("REDIS_TTL", "3600"))

    cache_mode = _get_cache_mode()

    # Write to exact cache (Redis) if mode is exact or hybrid
    if cache_mode in ("exact", "hybrid"):
        start_time = time.perf_counter()

        # Check circuit breaker
        if _redis_health and not _redis_health.should_attempt():
            logger.warning("Redis cache circuit breaker OPEN, skipping set")
        else:
            try:
                _set_exact_cached(tenant_id, text, decision, ttl)

                # Record successful request
                if _redis_health:
                    latency_ms = (time.perf_counter() - start_time) * 1000
                    _redis_health.record_request(latency_ms, success=True)
            except Exception as e:
                logger.debug(f"Redis cache set error (fail-open): {e}")

                # Record failed request
                if _redis_health:
                    latency_ms = (time.perf_counter() - start_time) * 1000
                    _redis_health.record_request(latency_ms, success=False)
                # Fail-open: Continue to semantic cache

    # Write to semantic cache (LangCache) if mode is semantic or hybrid
    if cache_mode in ("semantic", "hybrid") and _use_semantic_cache():
        try:
            set_semantic_cached(text, decision, tenant_id, ttl)
        except Exception as e:
            logger.debug(f"LangCache set error (fail-open): {e}")
            # Fail-open: Don't raise exception


def _set_exact_cached(
    tenant_id: str, text: str, decision: Dict[str, Any], ttl: int
) -> None:
    """Set cached decision using exact match (Redis)."""
    if not HAS_REDIS:
        return

    try:
        # Get Redis client (sync)
        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            client = redis.from_url(
                redis_url, socket_timeout=1.0, decode_responses=False
            )
        else:
            # Try REDIS_CLOUD_* env vars
            redis_host = os.getenv("REDIS_CLOUD_HOST") or os.getenv("REDIS_HOST")
            redis_port_str = os.getenv("REDIS_CLOUD_PORT") or os.getenv(
                "REDIS_PORT", "6379"
            )
            redis_port = int(redis_port_str) if redis_port_str else 6379
            redis_username = os.getenv("REDIS_CLOUD_USERNAME") or os.getenv(
                "REDIS_USERNAME"
            )
            redis_password = os.getenv("REDIS_CLOUD_PASSWORD") or os.getenv(
                "REDIS_PASSWORD"
            )

            if not redis_host or not redis_password:
                return

            client = redis.Redis(
                host=redis_host,
                port=redis_port,
                username=redis_username,
                password=redis_password,
                decode_responses=False,
                socket_timeout=1.0,
                socket_connect_timeout=2.0,
            )

        key = _key(tenant_id, text)
        value = json.dumps(decision)
        client.setex(key, ttl, value)
        logger.debug(f"[Redis] Cached decision for tenant {tenant_id}")
    except RedisError as e:
        logger.debug("Redis cache write failed (RedisError): %s", str(e)[:100])
        raise
    except Exception as e:
        logger.debug("Exact cache set failed: %s", str(e)[:100])
        raise


def get_cache_health() -> Dict[str, Any]:
    """
    Get cache health metrics (for monitoring endpoint).

    Returns:
        Dictionary with health metrics for Redis and LangCache adapters.
    """
    return {
        "redis": _redis_health.get_health_metrics() if _redis_health else None,
        "langcache": _langcache_health.get_health_metrics()
        if _langcache_health
        else None,
        "timestamp": time.time(),
    }
