"""
Core package for hexagonal architecture.

Re-exports symbols from parent core.py module for backward compatibility.
"""

import importlib.util
import sys
from pathlib import Path

# Load parent core.py module directly (not via import system)
core_py_path = Path(__file__).parent.parent / "core.py"

if core_py_path.exists():
    spec = importlib.util.spec_from_file_location(
        "llm_firewall._core_module", core_py_path
    )
    if spec and spec.loader:
        core_module = importlib.util.module_from_spec(spec)
        sys.modules["llm_firewall._core_module"] = core_module
        spec.loader.exec_module(core_module)

        # Re-export symbols
        SecurityFirewall = getattr(core_module, "SecurityFirewall", None)
        FirewallConfig = getattr(core_module, "FirewallConfig", None)
        ValidationResult = getattr(core_module, "ValidationResult", None)
        EvidenceDecision = getattr(core_module, "EvidenceDecision", None)
        LEX_BASE = getattr(core_module, "LEX_BASE", None)
        compute_features = getattr(core_module, "compute_features", None)
        _artifacts_base = getattr(core_module, "_artifacts_base", None)

        __all__ = [
            "SecurityFirewall",
            "FirewallConfig",
            "ValidationResult",
            "EvidenceDecision",
            "LEX_BASE",
            "compute_features",
            "_artifacts_base",
        ]
