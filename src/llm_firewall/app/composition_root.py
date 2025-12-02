"""
HAK_GAL Composition Root - Dependency Injection Container

Central place where all adapters are composed and injected into the domain layer.
This makes the architecture explicit and enables easy testing/mocking.

Architecture Note:
- Single Responsibility: Assemble system components
- Dependency Rule: All dependencies flow inward (domain ← adapters)
- Testability: Easy to swap adapters for tests

Creator: Pragmatic Hexagonal Architecture Evolution
Date: 2025-12-01
Status: P0 - Dependency Rule Enforcement
License: MIT
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Domain layer imports (inward dependency)
from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2

# Port imports (abstractions)
from llm_firewall.core.ports import DecisionCachePort, DecoderPort

# Adapter imports (infrastructure)
try:
    from llm_firewall.cache.cache_adapter import (
        DecisionCacheAdapter,
        NullCacheAdapter,
    )

    HAS_CACHE_ADAPTER = True
except ImportError:
    HAS_CACHE_ADAPTER = False
    DecisionCacheAdapter = None  # type: ignore
    NullCacheAdapter = None  # type: ignore

try:
    from hak_gal.layers.inbound.normalization_layer import NormalizationLayer

    HAS_NORMALIZATION_LAYER = True
except ImportError:
    HAS_NORMALIZATION_LAYER = False
    NormalizationLayer = None  # type: ignore


class CompositionRoot:
    """
    Composition root for assembling the firewall system.

    Usage:
        root = CompositionRoot()
        engine = root.create_firewall_engine()
        decision = engine.process_input("user123", "user input")
    """

    def __init__(
        self,
        enable_cache: bool = True,
        enable_normalization: bool = True,
    ):
        """
        Initialize composition root.

        Args:
            enable_cache: If True, use DecisionCacheAdapter. If False, use NullCacheAdapter.
            enable_normalization: If True, use NormalizationLayer. If False, use None.
        """
        self.enable_cache = enable_cache
        self.enable_normalization = enable_normalization

    def create_cache_adapter(self) -> DecisionCachePort:
        """
        Create cache adapter based on configuration.

        Returns:
            DecisionCachePort implementation (DecisionCacheAdapter or NullCacheAdapter)
        """
        if not self.enable_cache:
            logger.info("Cache disabled - using NullCacheAdapter")
            if NullCacheAdapter is None:
                raise RuntimeError("NullCacheAdapter not available")
            return NullCacheAdapter()

        if not HAS_CACHE_ADAPTER or DecisionCacheAdapter is None:
            logger.warning(
                "DecisionCacheAdapter not available - using NullCacheAdapter"
            )
            if NullCacheAdapter is None:
                raise RuntimeError("No cache adapter available")
            return NullCacheAdapter()

        try:
            adapter = DecisionCacheAdapter()
            logger.info("DecisionCacheAdapter initialized")
            return adapter
        except Exception as e:
            logger.warning(
                f"Failed to initialize DecisionCacheAdapter: {e} - using NullCacheAdapter"
            )
            if NullCacheAdapter is None:
                raise RuntimeError("No cache adapter available")
            return NullCacheAdapter()

    def create_decoder(self) -> Optional[DecoderPort]:
        """
        Create decoder adapter based on configuration.

        Returns:
            DecoderPort implementation (NormalizationLayer) or None
        """
        if not self.enable_normalization:
            logger.info("Normalization disabled")
            return None

        if not HAS_NORMALIZATION_LAYER or NormalizationLayer is None:
            logger.warning("NormalizationLayer not available")
            return None

        try:
            decoder = NormalizationLayer(max_decode_depth=3)
            logger.info("NormalizationLayer initialized (max_decode_depth=3)")
            return decoder
        except Exception as e:
            logger.warning(f"Failed to initialize NormalizationLayer: {e}")
            return None

    def create_firewall_engine(
        self,
        allowed_tools: Optional[list[str]] = None,
        strict_mode: bool = True,
        enable_sanitization: bool = True,
    ) -> FirewallEngineV2:
        """
        Create FirewallEngineV2 with all dependencies injected.

        This is the main factory method that composes the entire system.

        Args:
            allowed_tools: List of allowed tool names for Protocol HEPHAESTUS
            strict_mode: If True, blocks on any detected threat
            enable_sanitization: If True, attempts to sanitize dangerous arguments

        Returns:
            Fully configured FirewallEngineV2 instance
        """
        # Create adapters
        cache_adapter = self.create_cache_adapter()
        decoder = self.create_decoder()

        # Create engine with cache adapter injected
        engine = FirewallEngineV2(
            allowed_tools=allowed_tools,
            strict_mode=strict_mode,
            enable_sanitization=enable_sanitization,
            cache_adapter=cache_adapter,  # Dependency Injection - fixes Dependency Rule
        )

        logger.info("FirewallEngineV2 created via CompositionRoot with cache adapter")
        return engine


def create_default_firewall_engine(
    allowed_tools: Optional[list[str]] = None,
    strict_mode: bool = True,
    enable_sanitization: bool = True,
) -> FirewallEngineV2:
    """
    Convenience function to create a firewall engine with default configuration.

    This is the simplest way to create a firewall engine. For more control,
    use CompositionRoot directly.

    Args:
        allowed_tools: List of allowed tool names for Protocol HEPHAESTUS
        strict_mode: If True, blocks on any detected threat
        enable_sanitization: If True, attempts to sanitize dangerous arguments

    Returns:
        Fully configured FirewallEngineV2 instance
    """
    root = CompositionRoot(
        enable_cache=os.getenv("ENABLE_CACHE", "true").lower() == "true",
        enable_normalization=os.getenv("ENABLE_NORMALIZATION", "true").lower()
        == "true",
    )
    return root.create_firewall_engine(
        allowed_tools=allowed_tools,
        strict_mode=strict_mode,
        enable_sanitization=enable_sanitization,
    )
