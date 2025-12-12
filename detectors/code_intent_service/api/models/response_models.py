"""
API Response Models
===================

Pydantic models for API responses.
Extends shared BaseDetectionResponse.
"""

import sys
from pathlib import Path
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

# Add detectors directory to path for shared imports
service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from shared.api.models import BaseDetectionResponse


class DetectionResponse(BaseDetectionResponse):
    """
    Response model for code intent detection.
    
    Extends BaseDetectionResponse from shared components.
    Service-specific fields can be added here if needed.
    """
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "data": {
                    "detector_name": "code_intent",
                    "is_malicious": True,
                    "risk_score": 0.85,
                    "confidence": 0.9,
                    "is_blocked": True,
                    "matched_patterns": ["destructive_rm"],
                    "metadata": {
                        "processing_time_ms": 12.5,
                        "rule_score": 0.9,
                        "ml_score": None,
                        "threshold": 0.5,
                        "method": "rule_engine_high_confidence"
                    }
                },
                "error": None
            }
        }


class HealthResponse(BaseModel):
    """Response model for health check."""
    
    status: str = Field(..., description="Service status")
    
    components: Dict[str, str] = Field(
        ...,
        description="Status of individual components"
    )
    
    version: str = Field(default="1.0.0", description="Service version")
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "components": {
                    "detection_service": "operational",
                    "benign_validator": "operational",
                    "ml_classifier": "available",
                    "rule_engine": "operational"
                },
                "version": "1.0.0"
            }
        }

