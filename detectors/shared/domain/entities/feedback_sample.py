"""
Feedback Sample Entity - Shared

Represents a feedback sample for learning/improvement.
Can be used across all detector services.
"""
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime

from ..value_objects.risk_score import RiskScore


@dataclass
class FeedbackSample:
    """
    Feedback sample for model improvement.
    
    Used across all detector services for consistent feedback representation.
    """
    
    text: str
    detector_name: str
    risk_score: RiskScore
    was_blocked: bool
    is_false_positive: Optional[bool] = None
    is_false_negative: Optional[bool] = None
    user_feedback: Optional[str] = None  # "correct", "wrong_block", "wrong_allow"
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            "text": self.text,
            "detector_name": self.detector_name,
            "risk_score": float(self.risk_score),
            "confidence": self.risk_score.confidence,
            "was_blocked": self.was_blocked,
            "is_false_positive": self.is_false_positive,
            "is_false_negative": self.is_false_negative,
            "user_feedback": self.user_feedback,
            "metadata": {
                **self.metadata,
                "source": self.risk_score.source,
                "timestamp": self.timestamp.isoformat(),
            }
        }

