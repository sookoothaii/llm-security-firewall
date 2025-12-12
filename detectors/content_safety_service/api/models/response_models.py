"""
Content Safety Service Response Models

Extends shared BaseDetectionResponse.
"""
import sys
from pathlib import Path

service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from shared.api.models.base_response import BaseDetectionResponse, DetectionData


class DetectionResponse(BaseDetectionResponse):
    """
    Detection response model for content safety service.
    
    Extends BaseDetectionResponse with service-specific fields if needed.
    Uses DetectionData from shared components for consistent structure.
    """
    pass

