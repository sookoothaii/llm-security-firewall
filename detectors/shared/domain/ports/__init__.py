"""
Shared Ports/Protocols

Protocol definitions for detector services using Python Protocols.
No runtime overhead - type hints only.
"""

from typing import Protocol, runtime_checkable, Optional, Dict, Any, List

# Import shared entities for type hints
from ..entities.detection_result import DetectionResult
from ..entities.feedback_sample import FeedbackSample
from ..value_objects.risk_score import RiskScore


@runtime_checkable
class DetectorPort(Protocol):
    """
    Base port for all detector services.
    
    All detector services should implement this protocol.
    """
    
    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """
        Detect malicious patterns in text.
        
        Args:
            text: Text to analyze
            context: Optional context (user_id, session_id, tools, etc.)
            
        Returns:
            DetectionResult with risk_score and detection details
        """
        ...
    
    def get_name(self) -> str:
        """
        Get detector name.
        
        Returns:
            Detector name (e.g., "code_intent", "persuasion")
        """
        ...


@runtime_checkable
class CachePort(Protocol):
    """
    Port for caching decisions.
    
    Adapted from src/llm_firewall/core/ports/DecisionCachePort
    """
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get cached decision.
        
        Args:
            key: Cache key
            
        Returns:
            Cached decision dict or None if miss
        """
        ...
    
    def set(self, key: str, value: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """
        Cache decision.
        
        Args:
            key: Cache key
            value: Decision dict to cache
            ttl: Time-to-live in seconds (optional)
        """
        ...


@runtime_checkable
class DecoderPort(Protocol):
    """
    Port for text normalization/decoding.
    
    Adapted from src/llm_firewall/core/ports/DecoderPort
    """
    
    def normalize(self, text: str) -> tuple[str, float]:
        """
        Normalize text through recursive decoding.
        
        Args:
            text: Input text (may contain encoded segments)
            
        Returns:
            Tuple of (normalized_text, encoding_anomaly_score)
            - anomaly_score: 0.0 (normal) to 1.0 (highly suspicious)
        """
        ...


@runtime_checkable
class FeedbackRepositoryPort(Protocol):
    """
    Port for feedback sample storage.
    
    Can be used across all detector services.
    """
    
    def add(self, sample: FeedbackSample) -> None:
        """
        Add feedback sample to repository.
        
        Args:
            sample: FeedbackSample entity
        """
        ...
    
    def get_samples(
        self, 
        detector_name: Optional[str] = None,
        limit: int = 100
    ) -> List[FeedbackSample]:
        """
        Get feedback samples for training.
        
        Args:
            detector_name: Optional filter by detector name
            limit: Maximum number of samples to return
            
        Returns:
            List of FeedbackSample entities
        """
        ...


__all__ = [
    "DetectorPort",
    "CachePort",
    "DecoderPort",
    "FeedbackRepositoryPort",
    "DetectionResult",
    "FeedbackSample",
    "RiskScore",
]

