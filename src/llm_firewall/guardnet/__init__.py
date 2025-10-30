"""
GuardNet: Proactive Firewall Guard Model

Standalone guard model trained on firewall signals for input classification.
Provides multi-task outputs: policy action, intent, actionability, obfuscation detection.

Architecture: Two-tower fusion (text encoder + engineered features) with multi-head outputs.
Export: ONNX-compatible for production deployment.
Integration: Gate 1 in guarded-completion pipeline.

Creator: Joerg Bollwahn
Date: 2025-10-30
Phase: 3 (Guard Model Implementation)
"""

from __future__ import annotations

__all__ = [
    "FirewallNet",
    "FeatureMLP",
    "compute_features",
    "export_onnx",
    "train_guardnet",
]

# Lazy imports to avoid heavy dependencies at module load
def __getattr__(name: str):
    if name == "FirewallNet":
        from llm_firewall.guardnet.model import FirewallNet
        return FirewallNet
    elif name == "FeatureMLP":
        from llm_firewall.guardnet.model import FeatureMLP
        return FeatureMLP
    elif name == "compute_features":
        from llm_firewall.guardnet.features.extractor import compute_features
        return compute_features
    elif name == "export_onnx":
        from llm_firewall.guardnet.export_onnx import export_onnx
        return export_onnx
    elif name == "train_guardnet":
        from llm_firewall.guardnet.train import train_guardnet
        return train_guardnet
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

