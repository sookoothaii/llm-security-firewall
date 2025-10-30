"""
Authentication Port (Hexagonal Architecture)
============================================

Port interface for actor authentication adapters.

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class AuthenticationResult:
    """Result of authentication check."""
    confidence: float  # 0.0 = definitely bot, 1.0 = definitely human
    method: str  # Authentication method used (e.g., "cultural_biometrics", "spatial_captcha")
    metadata: Dict[str, Any]  # Additional context (response_time, challenge_id, etc.)
    is_human: bool  # Derived from confidence and threshold

    def __post_init__(self):
        """Validate confidence range."""
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")


class AuthenticationPort(ABC):
    """
    Port for actor authentication adapters.
    
    Implementations can use text-based (Cultural Biometrics),
    vision-based (Spatial CAPTCHA), or other modalities.
    
    Design Principles:
    - Adapters are independent and composable
    - No adapter depends on another adapter
    - Composition happens at application layer
    """

    @abstractmethod
    def authenticate(self, user_id: str, context: Dict[str, Any]) -> AuthenticationResult:
        """
        Authenticate user based on provided context.
        
        Args:
            user_id: User identifier
            context: Request context (may include message, metadata, session_id, etc.)
            
        Returns:
            AuthenticationResult with confidence score and metadata
        """
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Return adapter name for logging/metrics."""
        pass

    @abstractmethod
    def get_latency_budget_ms(self) -> int:
        """
        Max acceptable latency for this adapter.
        
        Returns:
            Latency budget in milliseconds
        """
        pass

    @abstractmethod
    def supports_challenge(self) -> bool:
        """
        Does this adapter trigger interactive challenges?
        
        Returns:
            True if interactive (e.g., CAPTCHA), False if passive (e.g., biometrics)
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Is this adapter available in current environment?
        
        Returns:
            True if dependencies met, False if graceful degradation needed
        """
        pass


class MultiModalAuthenticator:
    """
    Combines multiple authentication adapters.
    
    Uses weighted voting to produce combined confidence score.
    """

    def __init__(self, adapters: list[AuthenticationPort], weights: Optional[Dict[str, float]] = None):
        """
        Initialize multi-modal authenticator.
        
        Args:
            adapters: List of authentication adapters
            weights: Optional weights per adapter (default: equal weights)
        """
        self.adapters = adapters
        self.weights = weights or {a.get_name(): 1.0 for a in adapters}

        # Normalize weights
        total = sum(self.weights.values())
        self.weights = {k: v/total for k, v in self.weights.items()}

    def authenticate(self, user_id: str, context: Dict[str, Any], threshold: float = 0.9) -> AuthenticationResult:
        """
        Authenticate using all available adapters.
        
        Args:
            user_id: User identifier
            context: Request context
            threshold: Confidence threshold for is_human
            
        Returns:
            Combined AuthenticationResult
        """
        results = []
        total_confidence = 0.0

        for adapter in self.adapters:
            if not adapter.is_available():
                continue

            result = adapter.authenticate(user_id, context)
            results.append(result)

            weight = self.weights.get(adapter.get_name(), 0.0)
            total_confidence += result.confidence * weight

        # Combine metadata
        combined_metadata = {
            "adapters_used": [r.method for r in results],
            "individual_scores": {r.method: r.confidence for r in results},
            "weights": self.weights
        }

        return AuthenticationResult(
            confidence=total_confidence,
            method="multi_modal_fusion",
            metadata=combined_metadata,
            is_human=total_confidence >= threshold
        )


