"""Persuasion detection module for LLM Security Firewall"""
from .detector import PersuasionDetector, PersuasionSignal
from .neutralizer import Neutralizer
from .invariance_gate import InvarianceGate, InvarianceResult
from .instructionality import instructionality_score, requires_safety_wrap

__all__ = [
    "PersuasionDetector", 
    "PersuasionSignal",
    "Neutralizer",
    "InvarianceGate",
    "InvarianceResult",
    "instructionality_score",
    "requires_safety_wrap"
]

