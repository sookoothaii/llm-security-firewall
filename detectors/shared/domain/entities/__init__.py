"""
Shared Domain Entities

Core business objects that can be used across all detector services.
"""

from .detection_result import DetectionResult
from .feedback_sample import FeedbackSample

__all__ = ["DetectionResult", "FeedbackSample"]

