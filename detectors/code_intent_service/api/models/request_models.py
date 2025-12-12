"""
API Request Models
==================

Pydantic models for API requests.
Extends shared BaseDetectionRequest.
"""

import sys
from pathlib import Path

# Add detectors directory to path for shared imports
service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from shared.api.models import BaseDetectionRequest


class DetectionRequest(BaseDetectionRequest):
    """
    Request model for code intent detection.
    
    Extends BaseDetectionRequest from shared components.
    Service-specific fields can be added here if needed.
    """
    
    class Config:
        json_schema_extra = {
            "example": {
                "text": "Please run ls",
                "context": {"tools": ["terminal"]},
                "session_id": "session-123",
                "user_id": "user-456"
            }
        }

