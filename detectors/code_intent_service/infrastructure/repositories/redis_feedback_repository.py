"""
Redis Feedback Repository - Redis Cloud Integration
====================================================

Implementiert FeedbackRepositoryPort mit Redis Cloud für persistente,
schnelle Feedback-Speicherung.

Features:
- Redis Cloud Integration (SSL)
- TTL-basierte Speicherung (30 Tage default)
- Score-basierte Indizierung für Analytics
- Echtzeit-Statistiken

Creator: Production Integration
Date: 2025-12-10
License: MIT
"""

import json
import pickle
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging
import os

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None  # type: ignore

from domain.services.ports import FeedbackRepositoryPort

logger = logging.getLogger(__name__)


class RedisFeedbackRepository(FeedbackRepositoryPort):
    """
    Feedback Repository mit Redis Cloud Integration.
    
    Nutzt Redis Cloud für schnelle, persistente Feedback-Speicherung.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        password: Optional[str] = None,
        username: Optional[str] = None,
        db: int = 0,
        ttl_hours: int = 720,  # 30 Tage
        ssl: bool = True
    ):
        """
        Initialize Redis Feedback Repository.
        
        Args:
            host: Redis host (default: from REDIS_CLOUD_HOST env)
            port: Redis port (default: from REDIS_CLOUD_PORT env)
            password: Redis password (default: from REDIS_CLOUD_PASSWORD env)
            username: Redis username (default: from REDIS_CLOUD_USERNAME env)
            db: Redis database number
            ttl_hours: TTL in hours (default: 720 = 30 days)
            ssl: Use SSL connection (default: True for Redis Cloud)
        """
        if not HAS_REDIS:
            raise ImportError(
                "redis package not installed. Install with: pip install redis"
            )
        
        # Get config from environment or parameters
        self.host = host or os.getenv("REDIS_CLOUD_HOST") or os.getenv("REDIS_HOST")
        self.port = port or int(os.getenv("REDIS_CLOUD_PORT") or os.getenv("REDIS_PORT", "6379"))
        self.password = password or os.getenv("REDIS_CLOUD_PASSWORD") or os.getenv("REDIS_PASSWORD")
        self.username = username or os.getenv("REDIS_CLOUD_USERNAME") or os.getenv("REDIS_USERNAME")
        self.db = db
        self.ttl = ttl_hours * 3600
        self.key_prefix = "llm_firewall:code_intent:feedback"
        
        if not self.host or not self.password:
            raise ValueError(
                "Redis host and password required. "
                "Set REDIS_CLOUD_HOST and REDIS_CLOUD_PASSWORD environment variables."
            )
        
        # Create Redis client
        # Redis Cloud on port 19088 doesn't require SSL - connect directly without SSL
        try:
            self.redis = redis.Redis(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                db=self.db,
                decode_responses=False,  # Binary mode for pickle
                ssl=False,  # Port 19088 doesn't require SSL
                socket_timeout=5.0,
                socket_connect_timeout=5.0,
            )
            
            # Test connection
            self.redis.ping()
            
            # Test connection
            self.redis.ping()
            logger.info(f"Connected to Redis Cloud: {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            raise
    
    def add(self, sample: Dict[str, Any]) -> None:
        """
        Add feedback sample to Redis.
        
        Args:
            sample: Feedback sample dict with text, scores, etc.
        """
        try:
            # Generate ID if not present
            if "id" not in sample:
                sample["id"] = str(uuid.uuid4())
            
            # Ensure timestamp
            if "timestamp" not in sample:
                sample["timestamp"] = datetime.now().isoformat()
            
            # Create key
            sample_id = sample["id"]
            key = f"{self.key_prefix}:{sample_id}"
            
            # Serialize with pickle (preserves object structure)
            data = pickle.dumps(sample)
            
            # Store with TTL
            self.redis.setex(key, self.ttl, data)
            
            # Add to set for quick queries
            self.redis.sadd(f"{self.key_prefix}:all", key)
            
            # Index by score for analytics
            final_score = sample.get("final_score", 0.0)
            score_key = f"{self.key_prefix}:by_score"
            self.redis.zadd(score_key, {key: final_score})
            
            # Index by blocked status
            blocked = sample.get("blocked", False)
            status_key = f"{self.key_prefix}:blocked" if blocked else f"{self.key_prefix}:allowed"
            self.redis.sadd(status_key, key)
            
            logger.debug(f"Feedback saved to Redis: {sample_id}")
            
        except Exception as e:
            logger.error(f"Failed to save feedback to Redis: {e}")
            # Fail-open: Don't raise, just log
    
    def get_samples(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get feedback samples from Redis.
        
        Args:
            limit: Maximum number of samples to return
            
        Returns:
            List of feedback sample dicts
        """
        try:
            # Get all keys
            pattern = f"{self.key_prefix}:*"
            keys = self.redis.keys(pattern)
            
            # Filter out index keys
            sample_keys = [k for k in keys if not k.endswith(b":all") and not k.endswith(b":by_score") 
                          and not k.endswith(b":blocked") and not k.endswith(b":allowed")]
            
            # Get samples
            samples = []
            for key in sample_keys[:limit]:
                data = self.redis.get(key)
                if data:
                    try:
                        sample = pickle.loads(data)
                        samples.append(sample)
                    except Exception as e:
                        logger.warning(f"Failed to deserialize sample {key}: {e}")
            
            # Sort by timestamp (newest first)
            samples.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            
            return samples
            
        except Exception as e:
            logger.error(f"Failed to get samples from Redis: {e}")
            return []
    
    def get_high_risk_samples(self, threshold: float = 0.7, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get feedback samples with high risk score.
        
        Args:
            threshold: Minimum risk score
            limit: Maximum number of samples
            
        Returns:
            List of high-risk feedback samples
        """
        try:
            score_key = f"{self.key_prefix}:by_score"
            keys = self.redis.zrangebyscore(score_key, threshold, 1.0, start=0, num=limit)
            
            samples = []
            for key in keys:
                data = self.redis.get(key)
                if data:
                    try:
                        sample = pickle.loads(data)
                        samples.append(sample)
                    except Exception as e:
                        logger.warning(f"Failed to deserialize sample {key}: {e}")
            
            return samples
            
        except Exception as e:
            logger.error(f"Failed to get high-risk samples: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about stored feedback.
        
        Returns:
            Dict with statistics
        """
        try:
            # Count total samples
            pattern = f"{self.key_prefix}:*"
            keys = self.redis.keys(pattern)
            sample_keys = [k for k in keys if not k.endswith(b":all") and not k.endswith(b":by_score")
                          and not k.endswith(b":blocked") and not k.endswith(b":allowed")]
            total = len(sample_keys)
            
            # Count blocked/allowed
            blocked_count = self.redis.scard(f"{self.key_prefix}:blocked")
            allowed_count = self.redis.scard(f"{self.key_prefix}:allowed")
            
            # Get average score
            score_key = f"{self.key_prefix}:by_score"
            scores = self.redis.zrange(score_key, 0, -1, withscores=True)
            avg_score = sum(score for _, score in scores) / len(scores) if scores else 0.0
            
            # Get Redis memory info
            try:
                info = self.redis.info("memory")
                memory_used = info.get("used_memory_human", "N/A")
            except:
                memory_used = "N/A"
            
            return {
                "total_samples": total,
                "blocked_samples": blocked_count,
                "allowed_samples": allowed_count,
                "block_rate": blocked_count / total if total > 0 else 0.0,
                "avg_score": float(avg_score),
                "redis_memory_used": memory_used,
                "redis_host": self.host,
                "redis_port": self.port,
            }
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {
                "total_samples": 0,
                "blocked_samples": 0,
                "allowed_samples": 0,
                "block_rate": 0.0,
                "avg_score": 0.0,
                "redis_memory_used": "N/A",
                "error": str(e)
            }

