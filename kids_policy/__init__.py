"""
Kids Policy Engine - Truth Preservation & Cultural Sensitivity for Child-Facing AI

Part of HAK/GAL LLM Security Firewall.
Creator: Joerg Bollwahn

TAG-2 Status: COMPLETE (33/33 PASSED)
TAG-2.1 Status: PENDING (Cultural Matrix Pilot)

MEMORY OPTIMIZATION (2025-12-05):
- Removed direct imports to prevent transformers (362.7 MB) from loading at module import
- All validators loaded lazily via getter functions or @property decorators
"""

__version__ = "0.1.0"
__author__ = "Joerg Bollwahn"

# LAZY IMPORT: Do NOT import TruthPreservationValidatorV2_3 at module level
# This prevents transformers (362.7 MB) and torch (350.9 MB) from being loaded at import time
# The validator is loaded lazily via @property in firewall_engine_v2.py

# Singleton instance cache (loaded on first access)
_truth_validator_instance = None
_truth_validator_class = None
_validation_result_class = None


def get_truth_validator():
    """
    Lazy getter for TruthPreservationValidatorV2_3 instance.

    This function loads transformers (362.7 MB) only when called for the first time.
    Subsequent calls return the cached singleton instance.

    Returns:
        TruthPreservationValidatorV2_3 instance or None if not available
    """
    global _truth_validator_instance, _truth_validator_class, _validation_result_class

    if _truth_validator_instance is None:
        try:
            # LAZY IMPORT: transformers loaded here, not at module import
            from .truth_preservation.validators.truth_preservation_validator_v2_3 import (
                TruthPreservationValidatorV2_3,
                ValidationResult,
            )

            _truth_validator_class = TruthPreservationValidatorV2_3
            _validation_result_class = ValidationResult
            _truth_validator_instance = TruthPreservationValidatorV2_3()
        except ModuleNotFoundError:
            # CI environment without optional dependencies
            return None

    return _truth_validator_instance


def get_truth_validator_class():
    """
    Lazy getter for TruthPreservationValidatorV2_3 class (for type hints/testing).

    Returns:
        TruthPreservationValidatorV2_3 class or None if not available
    """
    global _truth_validator_class

    if _truth_validator_class is None:
        try:
            from .truth_preservation.validators.truth_preservation_validator_v2_3 import (
                TruthPreservationValidatorV2_3,
            )

            _truth_validator_class = TruthPreservationValidatorV2_3
        except ModuleNotFoundError:
            return None

    return _truth_validator_class


# Export only version info and lazy getters - actual classes loaded on demand
__all__ = [
    "__version__",
    "__author__",
    "get_truth_validator",
    "get_truth_validator_class",
]
