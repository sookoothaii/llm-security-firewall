"""
Persuasion Service Composition Root

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
from domain.ports import PersuasionPatternAnalyzerPort

# Import application service
from application.services.persuasion_detection_service import PersuasionDetectionService

# Import infrastructure adapters
from infrastructure.adapters.persuasion_pattern_analyzer import PersuasionPatternAnalyzerAdapter


class PersuasionCompositionRoot(BaseCompositionRoot):
    """
    Composition root for assembling the persuasion detection service.
    
    Extends BaseCompositionRoot to inherit common functionality (cache, decoder).
    Adds service-specific components (pattern analyzer).
    
    Usage:
        root = PersuasionCompositionRoot(block_threshold=0.5)
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
            f"PersuasionCompositionRoot initialized "
            f"(threshold: {self.block_threshold}, extends BaseCompositionRoot)"
        )
    
    def create_pattern_analyzer(self) -> PersuasionPatternAnalyzerPort:
        """
        Create pattern analyzer adapter.
        
        Returns:
            PersuasionPatternAnalyzerPort implementation
        """
        return PersuasionPatternAnalyzerAdapter()
    
    def create_detection_service(self) -> PersuasionDetectionService:
        """
        Create persuasion detection service with all dependencies.
        
        Returns:
            PersuasionDetectionService instance with all dependencies injected
        """
        pattern_analyzer = self.create_pattern_analyzer()
        
        # Cache and decoder are available from BaseCompositionRoot if needed
        # (currently not used in persuasion service, but available for future use)
        cache = self.create_cache_adapter()
        decoder = self.create_decoder()
        
        service = PersuasionDetectionService(
            pattern_analyzer=pattern_analyzer,
            block_threshold=self.block_threshold,
        )
        
        logger.info("PersuasionDetectionService created with all dependencies")
        return service

