"""
Risk Score Value Object - Shared

Immutable value object representing a risk score with validation.
Can be used across all detector services.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class RiskScore:
    """
    Immutable risk score value object.
    
    Used across all detector services for consistent risk representation.
    """
    
    value: float
    confidence: Optional[float] = None
    source: Optional[str] = None  # "rule_engine", "ml_model", "hybrid", "detector_name"
    
    def __post_init__(self):
        """Validate risk score value"""
        if not 0.0 <= self.value <= 1.0:
            raise ValueError(f"Risk score must be between 0.0 and 1.0, got {self.value}")
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
    
    def is_above_threshold(self, threshold: float) -> bool:
        """Check if risk score is above threshold"""
        return self.value >= threshold
    
    def __float__(self) -> float:
        """Allow conversion to float"""
        return self.value
    
    def __str__(self) -> str:
        """String representation"""
        return f"RiskScore(value={self.value:.3f}, confidence={self.confidence}, source={self.source})"
    
    @classmethod
    def create(
        cls,
        value: float,
        confidence: Optional[float] = None,
        source: Optional[str] = None
    ) -> "RiskScore":
        """
        Factory method for RiskScore.
        
        Args:
            value: Risk score value (0.0-1.0)
            confidence: Optional confidence (0.0-1.0)
            source: Optional source/method name (e.g., "code_intent", "persuasion", "rule_engine")
            
        Returns:
            RiskScore instance
        """
        return cls(
            value=value,
            confidence=confidence,
            source=source
        )

