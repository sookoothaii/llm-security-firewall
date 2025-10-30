"""Persuasion detection module for LLM Security Firewall"""

from .detector import PersuasionDetector, PersuasionSignal
from .instructionality import instructionality_score, requires_safety_wrap
from .invariance_gate import InvarianceGate, InvarianceResult
from .neutralizer import Neutralizer

__all__ = [
    "PersuasionDetector",
    "PersuasionSignal",
    "Neutralizer",
    "InvarianceGate",
    "InvarianceResult",
    "instructionality_score",
    "requires_safety_wrap",
]
