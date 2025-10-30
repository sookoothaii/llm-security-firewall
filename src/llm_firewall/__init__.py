"""
LLM Security Firewall
=====================

Bidirectional Security Framework for Human/LLM Interfaces

Creator: Joerg Bollwahn
License: MIT
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Joerg Bollwahn"

# Core imports (graceful degradation if not available)
try:
    from llm_firewall.core import (
        EvidenceDecision,
        FirewallConfig,
        SecurityFirewall,
        ValidationResult,
    )
    __all__ = [
        "SecurityFirewall",
        "FirewallConfig",
        "ValidationResult",
        "EvidenceDecision",
    ]
except ImportError:
    # Core not available - plugins can still work independently
    __all__ = []
