"""
Persuasion Service API Controller

Handles HTTP requests for persuasion detection.
"""
import logging
import time
from typing import Dict, Any

from fastapi import HTTPException

# Import shared components
import sys
from pathlib import Path

service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from shared.domain.ports import DetectorPort
from shared.api.models.base_response import DetectionData

# Import API models
from api.models.request_models import DetectionRequest
from api.models.response_models import DetectionResponse

logger = logging.getLogger(__name__)


class PersuasionController:
    """
    Controller for persuasion detection endpoints.
    """
    
    def __init__(self, detection_service: DetectorPort):
        """
        Initialize controller.
        
        Args:
            detection_service: DetectorPort implementation
        """
        self.detection_service = detection_service
        logger.info("PersuasionController initialized")
    
    async def detect(self, request: DetectionRequest) -> DetectionResponse:
        """
        Detect persuasion and misinformation patterns.
        
        Args:
            request: DetectionRequest with text and context
            
        Returns:
            DetectionResponse with detection results
        """
        start_time = time.time()
        
        try:
            # Extract text and context
            text = request.text
            context = request.context or {}
            
            # Add session_id and user_id to context if provided
            if request.session_id:
                context["session_id"] = request.session_id
            if request.user_id:
                context["user_id"] = request.user_id
            
            # Perform detection
            result = self.detection_service.detect(text, context)
            
            # Convert DetectionResult to DetectionData
            result_dict = result.to_dict()
            
            detection_data = DetectionData(
                detector_name=result.detector_name,
                is_malicious=result.is_blocked,
                risk_score=float(result.risk_score),
                confidence=result.risk_score.confidence,
                is_blocked=result.is_blocked,
                category=result.category,
                matched_patterns=result.matched_patterns,
                metadata={
                    **result.metadata,
                    "processing_time_ms": (time.time() - start_time) * 1000,
                }
            )
            
            latency_ms = (time.time() - start_time) * 1000
            
            return DetectionResponse(
                success=True,
                data=detection_data.model_dump(),
                error=None
            )
            
        except Exception as e:
            logger.error(f"Detection error: {e}", exc_info=True)
            
            # Fail-open: Return low risk on error
            latency_ms = (time.time() - start_time) * 1000
            
            return DetectionResponse(
                success=False,
                data=None,
                error=str(e)
            )

