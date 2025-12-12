"""
V2.1 Hotfix Module

Provides hotfix detector for V2 model to reduce False Positive Rate.
"""

from .v2_1_hotfix_detector import (
    V21HotfixDetector,
    TechnicalQuestionWhitelist,
    load_v21_hotfix_detector
)

__all__ = [
    'V21HotfixDetector',
    'TechnicalQuestionWhitelist',
    'load_v21_hotfix_detector'
]

