"""
Content Safety Service Request Models

Extends shared BaseDetectionRequest.
"""
import sys
from pathlib import Path

service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from shared.api.models.base_request import BaseDetectionRequest


class DetectionRequest(BaseDetectionRequest):
    """
    Detection request model for content safety service.
    
    Extends BaseDetectionRequest with service-specific fields if needed.
    Currently uses all fields from BaseDetectionRequest.
    """
    pass

