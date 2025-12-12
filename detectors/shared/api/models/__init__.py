"""
Shared API Models

Common request/response models for detector services.
"""

from .base_request import BaseDetectionRequest
from .base_response import BaseDetectionResponse

__all__ = ["BaseDetectionRequest", "BaseDetectionResponse"]

