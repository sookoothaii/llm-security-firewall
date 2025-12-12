"""
Ensemble Detection Module

Combines multiple models for improved robustness.
"""

from .weighted_ensemble_detector import (
    WeightedEnsembleDetector,
    AdaptiveEnsembleDetector,
    ModelWrapper,
    load_ensemble_models
)

__all__ = [
    'WeightedEnsembleDetector',
    'AdaptiveEnsembleDetector',
    'ModelWrapper',
    'load_ensemble_models'
]

