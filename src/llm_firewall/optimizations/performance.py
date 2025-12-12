"""
Performance Optimizations for LLM Firewall
===========================================

Native Python optimizations without Docker dependencies.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-07
License: MIT
"""

import time
from functools import lru_cache
from typing import Dict, Any, List, Optional
from collections import deque
import threading
from dataclasses import dataclass
import hashlib
import json


@dataclass
class CacheEntry:
    """Cache entry with TTL."""
    value: Any
    timestamp: float
    ttl: float


class LRUCache:
    """Thread-safe LRU cache with TTL."""
    
    def __init__(self, maxsize: int = 1000, default_ttl: float = 300.0):
        self.maxsize = maxsize
        self.default_ttl = default_ttl
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()
        self._access_order = deque()
    
    def _is_expired(self, entry: CacheEntry) -> bool:
        """Check if cache entry is expired."""
        return time.time() - entry.timestamp > entry.ttl
    
    def _cleanup_expired(self):
        """Remove expired entries."""
        current_time = time.time()
        expired_keys = [
            key for key, entry in self._cache.items()
            if current_time - entry.timestamp > entry.ttl
        ]
        for key in expired_keys:
            self._cache.pop(key, None)
            if key in self._access_order:
                self._access_order.remove(key)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self._lock:
            self._cleanup_expired()
            
            if key not in self._cache:
                return None
            
            entry = self._cache[key]
            if self._is_expired(entry):
                self._cache.pop(key, None)
                if key in self._access_order:
                    self._access_order.remove(key)
                return None
            
            # Update access order
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)
            
            return entry.value
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None):
        """Set value in cache."""
        with self._lock:
            self._cleanup_expired()
            
            if len(self._cache) >= self.maxsize:
                # Remove least recently used
                if self._access_order:
                    lru_key = self._access_order.popleft()
                    self._cache.pop(lru_key, None)
            
            ttl = ttl or self.default_ttl
            self._cache[key] = CacheEntry(
                value=value,
                timestamp=time.time(),
                ttl=ttl
            )
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)
    
    def clear(self):
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
            self._access_order.clear()
    
    def size(self) -> int:
        """Get current cache size."""
        with self._lock:
            self._cleanup_expired()
            return len(self._cache)


class ConnectionPool:
    """HTTP connection pool for detector microservices."""
    
    def __init__(self, max_connections: int = 10):
        self.max_connections = max_connections
        self._pools: Dict[str, List[Any]] = {}
        self._lock = threading.Lock()
    
    def get_connection(self, endpoint: str, client_class):
        """Get or create connection from pool."""
        with self._lock:
            if endpoint not in self._pools:
                self._pools[endpoint] = []
            
            pool = self._pools[endpoint]
            
            if pool:
                return pool.pop()
            else:
                # Create new connection
                return client_class()
    
    def return_connection(self, endpoint: str, connection: Any):
        """Return connection to pool."""
        with self._lock:
            if endpoint not in self._pools:
                self._pools[endpoint] = []
            
            pool = self._pools[endpoint]
            if len(pool) < self.max_connections:
                pool.append(connection)


class PerformanceOptimizer:
    """Optimizations for production performance."""
    
    def __init__(self):
        self.decision_cache = LRUCache(maxsize=5000, default_ttl=300.0)
        self.pattern_cache = LRUCache(maxsize=10000, default_ttl=600.0)
        self.connection_pool = ConnectionPool(max_connections=10)
    
    @staticmethod
    def optimize_inner_ring() -> Dict[str, Any]:
        """Optimize inner ring checks."""
        return {
            "precompile_patterns": True,
            "use_bloom_filter": False,  # Skip for now (requires extra dependency)
            "vectorized_operations": True,
            "memory_pooling": True,
            "cache_decisions": True,
        }
    
    def cache_key(self, text: str, context: Dict[str, Any]) -> str:
        """Generate cache key for decision caching."""
        # Normalize text (lowercase, strip whitespace)
        normalized = text.lower().strip()
        
        # Include relevant context
        context_str = json.dumps({
            "direction": context.get("direction"),
            "tool": context.get("tool"),
        }, sort_keys=True)
        
        # Create hash
        key_data = f"{normalized}:{context_str}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def get_cached_decision(self, text: str, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get cached decision if available."""
        cache_key = self.cache_key(text, context)
        return self.decision_cache.get(cache_key)
    
    def cache_decision(self, text: str, context: Dict[str, Any], decision: Dict[str, Any], ttl: Optional[float] = None):
        """Cache decision result."""
        cache_key = self.cache_key(text, context)
        self.decision_cache.set(cache_key, decision, ttl=ttl)
    
    @staticmethod
    def batch_detector_calls(requests: List[Dict[str, Any]], max_batch_size: int = 32) -> List[List[Dict[str, Any]]]:
        """Batch detector calls for microservices."""
        batches = []
        for i in range(0, len(requests), max_batch_size):
            batches.append(requests[i:i + max_batch_size])
        return batches
    
    @staticmethod
    def warmup_caches(firewall, warmup_queries: int = 100):
        """Warm up caches before production traffic."""
        warmup_data = [
            {"text": "Hello world", "direction": "inbound"},
            {"text": "rm -rf /tmp", "direction": "outbound"},
            {"text": "SELECT * FROM users", "direction": "outbound"},
            {"text": "What is the weather today?", "direction": "inbound"},
            {"text": "DROP TABLE users;", "direction": "outbound"},
        ]
        
        print(f"Warming up caches with {warmup_queries} queries...")
        for i in range(warmup_queries):
            for data in warmup_data:
                try:
                    firewall.process_input(
                        user_id=f"warmup_{i}",
                        text=data["text"]
                    )
                except Exception:
                    pass  # Ignore errors during warmup
        
        print("Cache warmup complete.")


# Global optimizer instance
_optimizer: Optional[PerformanceOptimizer] = None


def get_optimizer() -> PerformanceOptimizer:
    """Get global optimizer instance."""
    global _optimizer
    if _optimizer is None:
        _optimizer = PerformanceOptimizer()
    return _optimizer
