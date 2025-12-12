"""
Feedback Buffer Repository - In-Memory Feedback Storage
=======================================================

Implementiert FeedbackRepositoryPort mit in-memory Ring Buffer.
Nutzt bestehende FeedbackBuffer-Logik aus main.py.

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
License: MIT
"""

import logging
from collections import deque
from datetime import datetime
from typing import Dict, Any, List, Optional

from domain.services.ports import FeedbackRepositoryPort

logger = logging.getLogger(__name__)


class FeedbackBufferRepository(FeedbackRepositoryPort):
    """
    In-memory Feedback Repository mit Ring Buffer.
    
    Features:
    - Ring Buffer (max_size)
    - Priority-based sampling
    - Statistics
    """
    
    def __init__(self, max_size: int = 10000):
        """
        Initialize feedback buffer repository.
        
        Args:
            max_size: Maximum number of samples to store
        """
        self.buffer = deque(maxlen=max_size)
        self.priorities = {
            "critical": 0.4,  # 40% der Samples
            "high": 0.3,      # 30% der Samples
            "medium": 0.2,    # 20% der Samples
            "low": 0.1        # 10% der Samples
        }
        logger.info(f"FeedbackBufferRepository initialized (max_size={max_size})")
    
    def determine_priority(self, sample: Dict[str, Any]) -> str:
        """
        Bestimme Priorität basierend auf Sample-Eigenschaften.
        
        Args:
            sample: Feedback sample dict
            
        Returns:
            Priority string ("critical", "high", "medium", "low")
        """
        rule_score = sample.get("rule_score", 0.0)
        ml_score = sample.get("ml_score", 0.0)
        final_score = sample.get("final_score", 0.0)
        blocked = sample.get("blocked", False)
        
        # Critical: Bypasses (nicht blockiert, aber sollte blockiert sein)
        if not blocked and (rule_score > 0.5 or ml_score > 0.7):
            return "critical"
        
        # High: Große Diskrepanzen
        if abs(rule_score - ml_score) > 0.3:
            return "high"
        
        # Medium: Edge Cases
        if 0.4 < rule_score < 0.6 and 0.4 < ml_score < 0.6:
            return "medium"
        
        # Low: High Confidence Cases
        if rule_score > 0.8 and ml_score > 0.8:
            return "low"
        
        return "medium"  # Default
    
    def add(self, sample: Dict[str, Any]) -> None:
        """
        Add feedback sample to repository.
        
        Args:
            sample: Feedback sample dict with text, result, etc.
        """
        priority = self.determine_priority(sample)
        sample["priority"] = priority
        sample["added_at"] = datetime.now().isoformat()
        self.buffer.append(sample)
        logger.debug(f"Feedback sample added: priority={priority}, text={sample.get('text', '')[:50]}...")
    
    def get_samples(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get feedback samples for training.
        
        Args:
            limit: Maximum number of samples to return
            
        Returns:
            List of feedback sample dicts
        """
        # Sort by priority (critical first)
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_samples = sorted(
            self.buffer,
            key=lambda x: priority_order.get(x.get("priority", "medium"), 3)
        )
        
        return sorted_samples[:limit]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the feedback buffer.
        
        Returns:
            Dict with statistics
        """
        if not self.buffer:
            return {
                "total_samples": 0,
                "by_priority": {},
                "avg_rule_score": 0.0,
                "avg_ml_score": 0.0,
            }
        
        by_priority = {}
        total_rule_score = 0.0
        total_ml_score = 0.0
        count_with_ml = 0
        
        for sample in self.buffer:
            priority = sample.get("priority", "medium")
            by_priority[priority] = by_priority.get(priority, 0) + 1
            
            total_rule_score += sample.get("rule_score", 0.0)
            ml_score = sample.get("ml_score")
            if ml_score is not None:
                total_ml_score += ml_score
                count_with_ml += 1
        
        return {
            "total_samples": len(self.buffer),
            "by_priority": by_priority,
            "avg_rule_score": total_rule_score / len(self.buffer) if self.buffer else 0.0,
            "avg_ml_score": total_ml_score / count_with_ml if count_with_ml > 0 else 0.0,
        }


class NullFeedbackRepository(FeedbackRepositoryPort):
    """
    Null Object Pattern für Feedback Repository (wenn deaktiviert).
    """
    
    def add(self, sample: Dict[str, Any]) -> None:
        """No-op: Feedback collection disabled."""
        pass
    
    def get_samples(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Returns empty list."""
        return []

