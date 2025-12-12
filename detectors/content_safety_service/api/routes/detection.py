"""
Detection Routes
"""
from fastapi import APIRouter

# Import shared components
import sys
from pathlib import Path

service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from api.controllers.content_safety_controller import ContentSafetyController
from api.models.request_models import DetectionRequest
from api.models.response_models import DetectionResponse

# Import composition root
from infrastructure.app.composition_root import ContentSafetyCompositionRoot

router = APIRouter(prefix="/v1", tags=["detection"])

# Create composition root and controller (singleton pattern)
_composition_root: ContentSafetyCompositionRoot | None = None
_controller: ContentSafetyController | None = None


def get_controller() -> ContentSafetyController:
    """Get or create controller instance"""
    global _composition_root, _controller
    
    if _controller is None:
        # Create composition root
        _composition_root = ContentSafetyCompositionRoot(
            block_threshold=0.5,
            enable_cache=True,
            enable_normalization=True
        )
        
        # Create detection service
        detection_service = _composition_root.create_detection_service()
        
        # Create controller
        _controller = ContentSafetyController(detection_service)
    
    return _controller


@router.post("/detect", response_model=DetectionResponse)
async def detect(request: DetectionRequest):
    """
    Detect content safety violations and jailbreak attempts.
    
    Endpoint matches detector registry format.
    """
    controller = get_controller()
    return await controller.detect(request)

