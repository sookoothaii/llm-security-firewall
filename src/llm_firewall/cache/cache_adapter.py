"""
HAK_GAL Cache Adapter - Protocol Implementation for Decision Cache

Adapter that wraps decision_cache functions to implement DecisionCachePort.
This allows the cache to be injected into the domain layer without
violating the Dependency Rule.

FAIL-SAFE POLICY:
- Circuit breaker OPEN → Automatically fallback to NullCacheAdapter
- This contains failure policy in adapter layer (not domain layer)
- Prevents cache failure from bypassing security (fail-safe, not fail-open)

Creator: Pragmatic Hexagonal Architecture Evolution
Date: 2025-12-01
Status: P0 - Dependency Rule Enforcement + Fail-Safe Policy
License: MIT
"""

import logging
from typing import Optional, Dict, Any
from llm_firewall.core.ports import DecisionCachePort

try:
    from llm_firewall.cache.decision_cache import (
        get_cached,
        set_cached,
        get_cache_health,
    )
    from llm_firewall.core.adapter_health import AdapterHealth

    HAS_CACHE = True
    HAS_ADAPTER_HEALTH = True
except ImportError:
    HAS_CACHE = False
    HAS_ADAPTER_HEALTH = False
    get_cached = None  # type: ignore
    set_cached = None  # type: ignore
    get_cache_health = None  # type: ignore
    AdapterHealth = None  # type: ignore

logger = logging.getLogger(__name__)


class DecisionCacheAdapter(DecisionCachePort):
    """
    Adapter that implements DecisionCachePort using decision_cache functions.

    This adapter wraps the existing cache implementation to fulfill the
    protocol contract, enabling dependency injection without architectural
    changes to the cache layer.

    FAIL-SAFE BEHAVIOR:
    - Checks circuit breaker status before attempting cache operations
    - If circuit OPEN: Automatically falls back to NullCacheAdapter (fail-safe)
    - Failure policy is contained in adapter layer, not domain layer
    """

    def __init__(self, fallback_adapter: Optional[DecisionCachePort] = None):
        """
        Initialize adapter (validates cache availability).

        Args:
            fallback_adapter: Adapter to use when circuit breaker is OPEN.
                             Defaults to NullCacheAdapter (fail-safe behavior).
        """
        if not HAS_CACHE:
            raise ImportError(
                "DecisionCacheAdapter requires llm_firewall.cache.decision_cache"
            )

        # Set up fail-safe fallback
        if fallback_adapter is None:
            self.fallback_adapter: DecisionCachePort = NullCacheAdapter()
        else:
            self.fallback_adapter = fallback_adapter

        logger.info("DecisionCacheAdapter initialized with fail-safe fallback")

    def _is_circuit_open(self) -> bool:
        """
        Check if circuit breaker is OPEN (cache unavailable).

        Returns:
            True if circuit is OPEN, False otherwise
        """
        if not HAS_ADAPTER_HEALTH or get_cache_health is None:
            return False  # No circuit breaker, assume healthy

        try:
            health = get_cache_health()
            redis_health = health.get("redis")

            if redis_health is None:
                return False  # No health data, assume healthy

            # Check if circuit is OPEN
            state = redis_health.get("state", "CLOSED")
            return state == "OPEN"
        except Exception as e:
            logger.debug(f"Error checking circuit breaker: {e}")
            return False  # Assume healthy on error

    def get(self, tenant_id: str, text: str) -> Optional[Dict[str, Any]]:
        """
        Get cached firewall decision.

        FAIL-SAFE: If circuit breaker is OPEN, falls back to NullCacheAdapter
        (fail-safe behavior - domain layer sees no cache, not a bypass).

        Args:
            tenant_id: Tenant identifier
            text: Normalized text (after Layer 0.25)

        Returns:
            Cached decision dict or None if miss/error
        """
        # Fail-safe: Check circuit breaker before attempting
        if self._is_circuit_open():
            logger.warning("Cache circuit breaker OPEN - using fail-safe fallback")
            return self.fallback_adapter.get(tenant_id, text)

        if not HAS_CACHE or get_cached is None:
            return self.fallback_adapter.get(tenant_id, text)

        try:
            return get_cached(tenant_id, text)
        except Exception as e:
            logger.debug(f"Cache get error (fail-safe fallback): {e}")
            # Fail-safe: Return fallback (domain sees no cache, continues normally)
            return self.fallback_adapter.get(tenant_id, text)

    def set(
        self,
        tenant_id: str,
        text: str,
        decision: Dict[str, Any],
        ttl: Optional[int] = None,
    ) -> None:
        """
        Cache firewall decision.

        FAIL-SAFE: If circuit breaker is OPEN, silently skips cache write
        (fail-safe behavior - domain layer continues normally).

        Args:
            tenant_id: Tenant identifier
            text: Normalized text (after Layer 0.25)
            decision: Decision dict to cache
            ttl: Time-to-live in seconds (optional)
        """
        # Fail-safe: Check circuit breaker before attempting
        if self._is_circuit_open():
            logger.debug(
                "Cache circuit breaker OPEN - skipping cache write (fail-safe)"
            )
            return

        if not HAS_CACHE or set_cached is None:
            return

        try:
            set_cached(tenant_id, text, decision, ttl)
        except Exception as e:
            logger.debug(f"Cache set error (fail-safe, continuing): {e}")
            # Fail-safe: Silently continue (cache write failures don't block domain)


class NullCacheAdapter(DecisionCachePort):
    """
    Null adapter that implements DecisionCachePort but does nothing.

    Useful for:
    - Testing (no external dependencies)
    - Disabling cache
    - Fallback when cache unavailable
    """

    def get(self, tenant_id: str, text: str) -> Optional[Dict[str, Any]]:
        """Always returns None (no cache)."""
        return None

    def set(
        self,
        tenant_id: str,
        text: str,
        decision: Dict[str, Any],
        ttl: Optional[int] = None,
    ) -> None:
        """Does nothing (no cache)."""
        pass
