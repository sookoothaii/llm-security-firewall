"""
API Models

Request and response models for API endpoints.
"""

from .request_models import DetectionRequest
from .response_models import DetectionResponse, HealthResponse

__all__ = ["DetectionRequest", "DetectionResponse", "HealthResponse"]

