"""
LLM Security Firewall
=====================

Bidirectional Security Framework for Human/LLM Interfaces

Creator: Joerg Bollwahn
License: MIT
Version: 5.0.0rc1
"""

__version__ = "2.5.0"
__author__ = "Joerg Bollwahn"

# Simple Guard API (recommended for new code)
try:
    from llm_firewall.guard import (
        GuardResult,
        check_input,
        check_output,
        safe,
        validate,
    )

    HAS_GUARD = True
except ImportError:
    HAS_GUARD = False
    GuardResult = None  # type: ignore
    check_input = None  # type: ignore
    check_output = None  # type: ignore
    safe = None  # type: ignore
    validate = None  # type: ignore

# Guard module (for namespace: from llm_firewall import guard)
try:
    import llm_firewall.guard as guard

    HAS_GUARD_MODULE = True
except ImportError:
    HAS_GUARD_MODULE = False
    guard = None  # type: ignore

# Core imports (legacy API - graceful degradation if not available)
try:
    from llm_firewall.core import (
        EvidenceDecision,
        FirewallConfig,
        SecurityFirewall,
        ValidationResult,
    )

    HAS_CORE = True
except ImportError:
    HAS_CORE = False
    EvidenceDecision = None  # type: ignore
    FirewallConfig = None  # type: ignore
    SecurityFirewall = None  # type: ignore
    ValidationResult = None  # type: ignore

# Build __all__ based on availability
__all__ = []

if HAS_GUARD:
    __all__.extend(
        [
            "GuardResult",
            "check_input",
            "check_output",
            "safe",
            "validate",
            "guard",
        ]
    )

if HAS_CORE:
    __all__.extend(
        [
            "SecurityFirewall",
            "FirewallConfig",
            "ValidationResult",
            "EvidenceDecision",
        ]
    )
