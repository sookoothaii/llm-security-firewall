"""
Hybrid Feedback Repository - Redis + PostgreSQL
================================================

Kombiniert Redis (schnell, aktuell) und PostgreSQL (persistent, Analytics)
für optimale Performance und Persistenz.

Features:
- Redis: Aktuelle Samples (letzte 30 Tage), schnelle Abfragen
- PostgreSQL: Alle Samples, Analytics, False Positive/Negative Tracking
- Fail-over: Funktioniert auch wenn eine Komponente ausfällt

Creator: Production Integration
Date: 2025-12-10
License: MIT
"""

import logging
from typing import Dict, Any, List, Optional

from domain.services.ports import FeedbackRepositoryPort

logger = logging.getLogger(__name__)


class HybridFeedbackRepository(FeedbackRepositoryPort):
    """
    Hybrid Repository: Redis für schnellen Zugriff + PostgreSQL für Persistenz.
    
    Best of both worlds:
    - Redis: Echtzeit-Zugriff, aktuelle Samples (30 Tage)
    - PostgreSQL: Langzeit-Speicherung, Analytics, False Positive/Negative Tracking
    """

    def __init__(
        self,
        redis_repo: Optional[FeedbackRepositoryPort] = None,
        postgres_repo: Optional[FeedbackRepositoryPort] = None,
        memory_repo: Optional[FeedbackRepositoryPort] = None
    ):
        """
        Initialize Hybrid Feedback Repository.
        
        Args:
            redis_repo: Redis Feedback Repository (optional)
            postgres_repo: PostgreSQL Feedback Repository (optional)
            memory_repo: Memory Feedback Repository (fallback, optional)
        """
        self.redis = redis_repo
        self.postgres = postgres_repo
        self.memory = memory_repo
        
        if not redis_repo and not postgres_repo and not memory_repo:
            raise ValueError("At least one repository (Redis, PostgreSQL, or Memory) must be provided")
        
        logger.info(
            f"HybridFeedbackRepository initialized: "
            f"Redis={'OK' if redis_repo else 'N/A'}, "
            f"PostgreSQL={'OK' if postgres_repo else 'N/A'}, "
            f"Memory={'OK' if memory_repo else 'N/A'}"
        )
    
    def add(self, sample: Dict[str, Any]) -> None:
        """
        Add feedback sample to available repositories.
        
        Args:
            sample: Feedback sample dict
        """
        errors = []
        success = False
        
        # 1. Redis (schnell, für aktuelle Abfragen)
        if self.redis:
            try:
                self.redis.add(sample)
                logger.debug(f"Saved to Redis: {sample.get('id', 'unknown')}")
                success = True
            except Exception as e:
                errors.append(f"Redis: {e}")
                logger.warning(f"Redis save failed: {e}")
        
        # 2. PostgreSQL (persistent, für Analytics)
        if self.postgres:
            try:
                self.postgres.add(sample)
                logger.debug(f"Saved to PostgreSQL: {sample.get('id', 'unknown')}")
                success = True
            except Exception as e:
                errors.append(f"PostgreSQL: {e}")
                logger.warning(f"PostgreSQL save failed: {e}")
        
        # 3. Memory (fallback, always works)
        if self.memory:
            try:
                self.memory.add(sample)
                logger.debug(f"Saved to Memory: {sample.get('id', 'unknown')}")
                success = True
            except Exception as e:
                errors.append(f"Memory: {e}")
                logger.warning(f"Memory save failed: {e}")
        
        if not success:
            # All repositories failed
            logger.error(f"All repositories failed: {errors}")
            raise Exception(f"Failed to save to any repository: {errors}")
    
    def get_samples(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get feedback samples (prefer Redis, fallback to PostgreSQL, then Memory).
        
        Args:
            limit: Maximum number of samples
            
        Returns:
            List of feedback samples
        """
        # Try Redis first (faster, recent samples)
        if self.redis:
            try:
                samples = self.redis.get_samples(limit)
                if samples:
                    logger.debug(f"Retrieved {len(samples)} samples from Redis")
                    return samples
            except Exception as e:
                logger.warning(f"Redis get_samples failed: {e}")
        
        # Fallback to PostgreSQL
        if self.postgres:
            try:
                samples = self.postgres.get_samples(limit)
                if samples:
                    logger.debug(f"Retrieved {len(samples)} samples from PostgreSQL")
                    return samples
            except Exception as e:
                logger.warning(f"PostgreSQL get_samples failed: {e}")
        
        # Fallback to Memory
        if self.memory:
            try:
                samples = self.memory.get_samples(limit)
                if samples:
                    logger.debug(f"Retrieved {len(samples)} samples from Memory")
                    return samples
            except Exception as e:
                logger.warning(f"Memory get_samples failed: {e}")
        
        return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get combined statistics from all repositories.
        
        Returns:
            Dict with combined statistics
        """
        stats = {
            "redis": None,
            "postgres": None,
            "memory": None,
            "combined": {}
        }
        
        # Get Redis stats
        if self.redis:
            try:
                redis_stats = self.redis.get_statistics()
                stats["redis"] = redis_stats
            except Exception as e:
                logger.warning(f"Failed to get Redis stats: {e}")
        
        # Get PostgreSQL stats
        if self.postgres:
            try:
                postgres_stats = self.postgres.get_statistics()
                stats["postgres"] = postgres_stats
            except Exception as e:
                logger.warning(f"Failed to get PostgreSQL stats: {e}")
        
        # Get Memory stats
        if self.memory:
            try:
                memory_stats = self.memory.get_statistics()
                stats["memory"] = memory_stats
            except Exception as e:
                logger.warning(f"Failed to get Memory stats: {e}")
        
        # Combine stats (weighted average for block_rate, prioritize source with most samples)
        if stats["redis"] and stats["postgres"]:
            redis_total = stats["redis"].get("total_samples", 0)
            postgres_total = stats["postgres"].get("total_samples", 0)
            redis_blocked = stats["redis"].get("blocked_samples", 0)
            postgres_blocked = stats["postgres"].get("blocked_samples", 0)
            
            # Calculate weighted block rate
            total_samples = redis_total + postgres_total
            total_blocked = redis_blocked + postgres_blocked
            weighted_block_rate = total_blocked / total_samples if total_samples > 0 else 0.0
            
            # Use source with most samples for block_rate (more accurate)
            if redis_total >= postgres_total:
                primary_block_rate = stats["redis"].get("block_rate", 0.0)
            else:
                primary_block_rate = stats["postgres"].get("block_rate", 0.0)
            
            stats["combined"] = {
                "total_samples": total_samples,  # Sum of both repositories
                "blocked_samples": total_blocked,
                "allowed_samples": total_samples - total_blocked,
                "redis_samples": redis_total,
                "postgres_samples": postgres_total,
                "block_rate": weighted_block_rate,  # Weighted average across both repositories
                "block_rate_redis": stats["redis"].get("block_rate", 0.0),
                "block_rate_postgres": stats["postgres"].get("block_rate", 0.0),
                "false_positives": stats["postgres"].get("false_positives", 0),
                "false_negatives": stats["postgres"].get("false_negatives", 0),
            }
        elif stats["redis"]:
            stats["combined"] = stats["redis"]
        elif stats["postgres"]:
            stats["combined"] = stats["postgres"]
        elif stats["memory"]:
            stats["combined"] = stats["memory"]
        
        return stats
    
    def get_high_risk_samples(self, threshold: float = 0.7, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get high-risk samples (Redis has this method).
        
        Args:
            threshold: Minimum risk score
            limit: Maximum number of samples
            
        Returns:
            List of high-risk samples
        """
        if self.redis and hasattr(self.redis, "get_high_risk_samples"):
            try:
                return self.redis.get_high_risk_samples(threshold, limit)
            except Exception as e:
                logger.warning(f"Redis get_high_risk_samples failed: {e}")
        
        # Fallback: Filter from get_samples
        all_samples = self.get_samples(limit * 2)
        high_risk = [s for s in all_samples if s.get("final_score", 0.0) >= threshold]
        return high_risk[:limit]
    
    def get_false_positives(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Get false positive samples (PostgreSQL has this method).
        
        Args:
            limit: Maximum number of samples
            
        Returns:
            List of false positive samples
        """
        if self.postgres and hasattr(self.postgres, "get_false_positives"):
            try:
                return self.postgres.get_false_positives(limit)
            except Exception as e:
                logger.warning(f"PostgreSQL get_false_positives failed: {e}")
        
        return []
    
    def get_false_negatives(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Get false negative samples (PostgreSQL has this method).
        
        Args:
            limit: Maximum number of samples
            
        Returns:
            List of false negative samples
        """
        if self.postgres and hasattr(self.postgres, "get_false_negatives"):
            try:
                return self.postgres.get_false_negatives(limit)
            except Exception as e:
                logger.warning(f"PostgreSQL get_false_negatives failed: {e}")
        
        return []

