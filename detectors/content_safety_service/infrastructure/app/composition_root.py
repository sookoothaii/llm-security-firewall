"""
Content Safety Service Composition Root

Central place where all adapters are composed and injected into the domain layer.
Extends BaseCompositionRoot from shared components.
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

import sys
from pathlib import Path

# Add detectors directory to path for shared imports
service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

# Import Base Composition Root
from shared.infrastructure.composition import BaseCompositionRoot

# Import domain ports
from domain.ports import ContentSafetyAnalyzerPort

# Import application service
from application.services.content_safety_detection_service import ContentSafetyDetectionService

# Import infrastructure adapters
from infrastructure.adapters.content_safety_pattern_analyzer import ContentSafetyPatternAnalyzerAdapter


class ContentSafetyCompositionRoot(BaseCompositionRoot):
    """
    Composition root for assembling the content safety detection service.
    
    Extends BaseCompositionRoot to inherit common functionality (cache, decoder).
    Adds service-specific components (pattern analyzer).
    
    Usage:
        root = ContentSafetyCompositionRoot(block_threshold=0.5)
        detection_service = root.create_detection_service()
        result = detection_service.detect("user input")
    """
    
    def __init__(
        self,
        block_threshold: float = 0.5,
        enable_cache: bool = True,
        enable_normalization: bool = True,
    ):
        """
        Initialize composition root.
        
        Args:
            block_threshold: Risk score threshold for blocking (0.0-1.0)
            enable_cache: If True, use cache adapter (from BaseCompositionRoot).
            enable_normalization: If True, use normalization (from BaseCompositionRoot).
        """
        # Initialize base composition root
        super().__init__(enable_cache=enable_cache, enable_normalization=enable_normalization)
        
        self.block_threshold = block_threshold
        logger.info(
            f"ContentSafetyCompositionRoot initialized "
            f"(threshold: {self.block_threshold}, extends BaseCompositionRoot)"
        )
    
    def create_content_safety_analyzer(self) -> ContentSafetyAnalyzerPort:
        """
        Create content safety analyzer adapter.
        
        Returns:
            ContentSafetyAnalyzerPort implementation
        """
        return ContentSafetyPatternAnalyzerAdapter()
    
    def create_detection_service(self) -> ContentSafetyDetectionService:
        """
        Create content safety detection service with all dependencies.
        
        Returns:
            ContentSafetyDetectionService instance with all dependencies injected
        """
        analyzer = self.create_content_safety_analyzer()
        
        # Cache and decoder are available from BaseCompositionRoot if needed
        # (currently not used in content safety service, but available for future use)
        cache = self.create_cache_adapter()
        decoder = self.create_decoder()
        
        service = ContentSafetyDetectionService(
            content_safety_analyzer=analyzer,
            block_threshold=self.block_threshold,
        )
        
        logger.info("ContentSafetyDetectionService created with all dependencies")
        return service

