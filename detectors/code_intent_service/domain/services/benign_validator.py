"""
Benign Validator Protocol

Defines the interface for benign text validation.
Uses Protocol (structural typing) for performance (no runtime overhead).

NOTE: This is a legacy file. New code should use domain/services/ports.py
which follows the established pattern from src/llm_firewall/core/ports/.
"""
from typing import Protocol, runtime_checkable

# Re-export from ports for backward compatibility
from .ports import BenignValidatorPort

# Legacy aliases (deprecated - use BenignValidatorPort instead)
BenignValidator = BenignValidatorPort
BenignValidatorComposite = BenignValidatorPort  # Composite also implements the same protocol

