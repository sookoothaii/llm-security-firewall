"""
Confidence Value Object - Shared

Immutable value object representing confidence level.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Confidence:
    """
    Immutable confidence value object.
    
    Represents confidence level (0.0-1.0) with validation.
    """
    
    value: float
    
    def __post_init__(self):
        """Validate confidence value"""
        if not 0.0 <= self.value <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.value}")
    
    def is_high(self, threshold: float = 0.8) -> bool:
        """Check if confidence is high"""
        return self.value >= threshold
    
    def is_low(self, threshold: float = 0.5) -> bool:
        """Check if confidence is low"""
        return self.value < threshold
    
    def __float__(self) -> float:
        """Allow conversion to float"""
        return self.value
    
    def __str__(self) -> str:
        """String representation"""
        return f"Confidence(value={self.value:.3f})"

