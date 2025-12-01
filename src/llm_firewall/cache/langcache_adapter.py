"""
LangCache Adapter for Semantic Caching
======================================

Provides semantic search capabilities using LangCache.
Used as secondary cache layer in hybrid mode.
"""

import os
import json
import logging
from typing import Optional, Dict, Any

try:
    from langcache import LangCache

    HAS_LANGCACHE = True
except ImportError:
    HAS_LANGCACHE = False
    LangCache = None  # type: ignore

logger = logging.getLogger(__name__)

# Global LangCache client (lazy initialization)
_langcache_client: Optional[LangCache] = None


def _get_langcache_client() -> Optional[LangCache]:
    """Get or create LangCache client (lazy initialization)."""
    global _langcache_client

    if _langcache_client is not None:
        return _langcache_client

    if not HAS_LANGCACHE:
        return None

    # Check if LangCache is configured
    api_key = os.getenv("LANGCACHE_API_KEY")
    server_url = os.getenv("LANGCACHE_SERVER_URL")
    cache_id = os.getenv("LANGCACHE_CACHE_ID")

    if not api_key or not server_url or not cache_id:
        return None

    try:
        _langcache_client = LangCache(
            server_url=server_url,
            cache_id=cache_id,
            api_key=api_key,
        )
        logger.info("LangCache client initialized")
        return _langcache_client
    except Exception as e:
        logger.warning(f"Failed to initialize LangCache (fail-open): {e}")
        return None


def get_semantic_cached(
    text: str, tenant_id: str = "default"
) -> Optional[Dict[str, Any]]:
    """
    Search for cached decision using semantic similarity.

    Args:
        text: Normalized text (after Layer 0.25)
        tenant_id: Tenant identifier (for attribute filtering)

    Returns:
        Cached decision dict or None (fail-open on errors)
    """
    if not HAS_LANGCACHE:
        return None

    try:
        langcache = _get_langcache_client()
        if not langcache:
            return None

        # Get similarity threshold (default: 0.92 for high precision)
        similarity_threshold = float(
            os.getenv("LANGCACHE_SIMILARITY_THRESHOLD", "0.92")
        )

        # Search with tenant_id attribute filter if not default
        attributes = {"tenant_id": tenant_id} if tenant_id != "default" else None

        search_result = langcache.search(
            prompt=text,
            similarity_threshold=similarity_threshold,
            attributes=attributes,
        )

        if search_result and search_result.data:
            # Use first result (highest similarity)
            entry = search_result.data[0]
            try:
                # Parse response as JSON
                decision = json.loads(entry.response)
                logger.debug(
                    f"[LangCache] Semantic HIT (similarity: {entry.similarity:.3f}, "
                    f"strategy: {entry.search_strategy})"
                )
                return decision
            except (json.JSONDecodeError, AttributeError) as e:
                logger.debug(f"[LangCache] Response not JSON: {e}")
                return None

        return None
    except Exception as e:
        logger.debug(f"[LangCache] Semantic search failed (fail-open): {e}")
        return None


def set_semantic_cached(
    text: str,
    decision: Dict[str, Any],
    tenant_id: str = "default",
    ttl: Optional[int] = None,
) -> None:
    """
    Store decision in LangCache using semantic indexing.

    Args:
        text: Normalized text (after Layer 0.25)
        decision: Decision dict to cache
        tenant_id: Tenant identifier (for attribute filtering)
        ttl: Time-to-live in seconds (default: 3600, or REDIS_TTL env var)
    """
    if not HAS_LANGCACHE:
        return

    try:
        langcache = _get_langcache_client()
        if not langcache:
            return

        # Convert decision to JSON string
        response = json.dumps(decision)

        # Convert TTL from seconds to milliseconds (LangCache uses milliseconds)
        if ttl is None:
            ttl = int(os.getenv("REDIS_TTL", "3600"))
        ttl_millis = ttl * 1000

        # Add tenant_id as attribute for filtering
        attributes = {"tenant_id": tenant_id} if tenant_id != "default" else {}

        langcache.set(
            prompt=text,
            response=response,
            attributes=attributes,
            ttl_millis=ttl_millis,
        )
        logger.debug(f"[LangCache] Stored semantic decision for tenant {tenant_id}")
    except Exception as e:
        logger.debug(f"[LangCache] Semantic write failed (fail-open): {e}")
