"""
GuardNet Feature Extraction

Deterministic feature computation for guard model training and inference.
Integrates with existing firewall components (canonicalization, regex, temporal gate).

Features:
- Obfuscation signals (ZWC density, base64 fraction, mixed-script ratio, punct burst)
- Temporal features (TTL delta, trust tier)
- OOD detection (embedding energy)
- Regex/Trie hits (intent and evasion patterns)

Creator: Joerg Bollwahn
"""

from __future__ import annotations

from llm_firewall.guardnet.features.extractor import (
    base64_fraction,
    compute_features,
    mixed_script_ratio,
    punct_burst_score,
    zwc_density,
)

__all__ = [
    "compute_features",
    "mixed_script_ratio",
    "punct_burst_score",
    "zwc_density",
    "base64_fraction",
]

