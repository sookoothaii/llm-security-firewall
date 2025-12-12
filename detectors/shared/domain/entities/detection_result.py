"""
Detection Result Entity - Shared

Core business object representing the result of a detection operation.
Can be used across all detector services.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime

from ..value_objects.risk_score import RiskScore


@dataclass
class DetectionResult:
    """
    Result of a detection operation.
    
    Used across all detector services for consistent result representation.
    """
    
    risk_score: RiskScore
    is_blocked: bool
    detector_name: str  # "code_intent", "persuasion", "content_safety", etc.
    category: Optional[str] = None  # "cybercrime", "misinformation", "harmful_content", etc.
    matched_patterns: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response"""
        return {
            "detector_name": self.detector_name,
            "risk_score": float(self.risk_score),
            "confidence": self.risk_score.confidence,
            "is_blocked": self.is_blocked,
            "category": self.category,
            "matched_patterns": self.matched_patterns,
            "metadata": {
                **self.metadata,
                "source": self.risk_score.source,
                "timestamp": self.timestamp.isoformat(),
            }
        }
    
    @property
    def is_malicious(self) -> bool:
        """Convenience property - alias for is_blocked"""
        return self.is_blocked

