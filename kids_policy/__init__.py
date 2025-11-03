"""
Kids Policy Engine - Truth Preservation & Cultural Sensitivity for Child-Facing AI

Part of HAK/GAL LLM Security Firewall.
Creator: Joerg Bollwahn

TAG-2 Status: COMPLETE (33/33 PASSED)
TAG-2.1 Status: PENDING (Cultural Matrix Pilot)
"""

__version__ = "0.1.0"
__author__ = "Joerg Bollwahn"

from .truth_preservation.validators.truth_preservation_validator_v2_3 import (
    TruthPreservationValidatorV2_3,
    ValidationResult,
)

__all__ = ["TruthPreservationValidatorV2_3", "ValidationResult"]

