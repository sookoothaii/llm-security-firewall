"""Feature extraction for GuardNet."""

from llm_firewall.guardnet.features.extractor import (
    FEATURE_DIM,
    ExtractorOutput,
    extract_features,
)

__all__ = ["extract_features", "FEATURE_DIM", "ExtractorOutput"]
