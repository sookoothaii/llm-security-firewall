"""
HAK_GAL Core Ports - Protocol Definitions for Hexagonal Architecture

Pragmatic port definitions using Python Protocols (structural subtyping).
These define the contracts that adapters must fulfill without enforcing
strict interface implementations.

Architecture Note:
- Protocols allow duck-typing: "If it quacks like a duck, it's a duck"
- Domain layer uses these for type hints and documentation
- Adapters can implement these naturally without inheritance
- No runtime overhead (type hints only, no abstract base classes)

Creator: Pragmatic Hexagonal Architecture Evolution
Date: 2025-12-01
Status: P0 - Dependency Rule Enforcement
License: MIT
"""

from typing import Protocol, Optional, Dict, Any, runtime_checkable


@runtime_checkable
class DecisionCachePort(Protocol):
    """
    Port for firewall decision caching.

    Adapters implementing this protocol:
    - RedisCache (exact match)
    - LangCache (semantic similarity)
    - InMemoryCache (test/mock)
    - HybridCache (exact + semantic)

    Usage:
        cache: DecisionCachePort = RedisCache(...)
        decision = cache.get("tenant123", "normalized_text")
        cache.set("tenant123", "normalized_text", decision_dict, ttl=3600)
    """

    def get(self, tenant_id: str, text: str) -> Optional[Dict[str, Any]]:
        """
        Get cached firewall decision.

        Args:
            tenant_id: Tenant identifier
            text: Normalized text (after Layer 0.25)

        Returns:
            Cached decision dict or None if miss/error (fail-open behavior)
        """
        ...

    def set(
        self,
        tenant_id: str,
        text: str,
        decision: Dict[str, Any],
        ttl: Optional[int] = None,
    ) -> None:
        """
        Cache firewall decision.

        Args:
            tenant_id: Tenant identifier
            text: Normalized text (after Layer 0.25)
            decision: Decision dict to cache
            ttl: Time-to-live in seconds (optional)
        """
        ...


@runtime_checkable
class DecoderPort(Protocol):
    """
    Port for recursive URL/percent decoding (Layer 0.25).

    Adapters implementing this protocol:
    - NormalizationLayer (current implementation)
    - DeepDecoder (alternative)

    Usage:
        decoder: DecoderPort = NormalizationLayer(max_decode_depth=3)
        clean_text, anomaly_score = decoder.normalize("encoded%20text")
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
class ValidatorPort(Protocol):
    """
    Port for WASM rule validation (if implemented).

    Adapters implementing this protocol:
    - WASMValidator (to be implemented)
    - MockValidator (test)

    Usage:
        validator: ValidatorPort = WASMValidator(rules_path="...")
        result = validator.validate(text, timeout=50)
    """

    def validate(self, text: str, timeout: int = 50) -> Dict[str, Any]:
        """
        Validate text against WASM rules with timeout enforcement.

        Args:
            text: Text to validate
            timeout: Maximum execution time in milliseconds

        Returns:
            Validation result dict with 'allowed', 'reason', etc.
        """
        ...


__all__ = ["DecisionCachePort", "DecoderPort", "ValidatorPort"]

# Code Intent Detection Ports (extended)
from .code_intent import (
    CodeIntentDetectorPort,
    BenignValidatorPort,
    IntentClassifierPort,
    ClassificationResult,
)

__all__.extend([
    "CodeIntentDetectorPort",
    "BenignValidatorPort",
    "IntentClassifierPort",
    "ClassificationResult",
])