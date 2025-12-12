"""
Base Composition Root for Detector Services

Adapted from src/llm_firewall/app/composition_root.py
Provides base functionality for all detector services.
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Import shared ports
from ...domain.ports import CachePort, DecoderPort

# Try to import root adapters (optional - graceful fallback if not available)
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
    try:
        from llm_firewall.pipeline.cascading_firewall import NormalizationGuard
        # Use NormalizationGuard as DecoderPort adapter
        HAS_NORMALIZATION_LAYER = True
        NormalizationLayer = None  # type: ignore
    except ImportError:
        HAS_NORMALIZATION_LAYER = False
        NormalizationLayer = None  # type: ignore
        NormalizationGuard = None  # type: ignore


class BaseCompositionRoot:
    """
    Base composition root for detector services.
    
    Provides common functionality:
    - Cache adapter creation
    - Decoder/normalization creation
    - Common configuration
    
    Service-specific composition roots should extend this class.
    
    Usage:
        class CodeIntentCompositionRoot(BaseCompositionRoot):
            def create_detection_service(self):
                cache = self.create_cache_adapter()
                decoder = self.create_decoder()
                # ... service-specific components
    """
    
    def __init__(
        self,
        enable_cache: bool = True,
        enable_normalization: bool = True,
    ):
        """
        Initialize base composition root.
        
        Args:
            enable_cache: If True, use DecisionCacheAdapter. If False, use NullCacheAdapter.
            enable_normalization: If True, use NormalizationLayer. If False, use None.
        """
        self.enable_cache = enable_cache
        self.enable_normalization = enable_normalization
    
    def create_cache_adapter(self) -> CachePort:
        """
        Create cache adapter based on configuration.
        
        Returns:
            CachePort implementation (DecisionCacheAdapter or NullCacheAdapter)
        """
        if not self.enable_cache:
            logger.info("Cache disabled - using NullCacheAdapter")
            if NullCacheAdapter is None:
                # Create a simple null adapter if root adapter not available
                return _NullCacheAdapter()
            return NullCacheAdapter()
        
        if not HAS_CACHE_ADAPTER or DecisionCacheAdapter is None:
            logger.warning(
                "DecisionCacheAdapter not available - using NullCacheAdapter"
            )
            if NullCacheAdapter is None:
                return _NullCacheAdapter()
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
                return _NullCacheAdapter()
            return NullCacheAdapter()
    
    def create_decoder(self) -> Optional[DecoderPort]:
        """
        Create decoder adapter based on configuration.
        
        Returns:
            DecoderPort implementation (NormalizationLayer/NormalizationGuard) or None
        """
        if not self.enable_normalization:
            logger.info("Normalization disabled")
            return None
        
        # Try NormalizationLayer first (hak_gal)
        if HAS_NORMALIZATION_LAYER and NormalizationLayer is not None:
            try:
                decoder = NormalizationLayer(max_decode_depth=3)
                logger.info("NormalizationLayer initialized (max_decode_depth=3)")
                return decoder
            except Exception as e:
                logger.warning(f"Failed to initialize NormalizationLayer: {e}")
        
        # Try NormalizationGuard (llm_firewall)
        if HAS_NORMALIZATION_LAYER and NormalizationGuard is not None:
            try:
                decoder = NormalizationGuard(max_recursion=3)
                logger.info("NormalizationGuard initialized (max_recursion=3)")
                return decoder
            except Exception as e:
                logger.warning(f"Failed to initialize NormalizationGuard: {e}")
        
        logger.warning("No normalization layer available")
        return None


class _NullCacheAdapter:
    """
    Simple null cache adapter if root adapter not available.
    """
    
    def get(self, key: str) -> Optional[dict]:
        """Always returns None (cache miss)"""
        return None
    
    def set(self, key: str, value: dict, ttl: Optional[int] = None) -> None:
        """No-op (does nothing)"""
        pass

