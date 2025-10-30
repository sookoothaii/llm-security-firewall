"""
Meta-ensemble stacking with calibration gates.

Features:
- 7-dimensional feature vector (includes intent_margin)
- LogisticRegression + Platt scaling
- ECE/Brier gates (only activate if calibration quality sufficient)
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import List

# Meta-feature vector (versioned, stable order)
META_FEATURES = [
    "emb_sim",
    "ppl_anom",
    "llm_judge",
    "intent_lex",
    "intent_margin",
    "pattern_score",
    "evasion_density",
]


@dataclass
class MetaArtifacts:
    """Artifacts from meta-ensemble training."""

    coef: List[float]
    intercept: float
    features: List[str]
    platt_A: float
    platt_B: float
    ece: float
    brier: float


def _sigmoid(x: float) -> float:
    """Sigmoid activation."""
    return 1.0 / (1.0 + math.exp(-x))


def load_artifacts(base: Path) -> MetaArtifacts:
    """
    Load meta-ensemble artifacts from directory.

    Args:
        base: Path to artifacts/meta directory

    Returns:
        MetaArtifacts with model weights and calibration metrics
    """
    model = json.loads((base / "model_meta.json").read_text())
    platt = json.loads((base / "platt.json").read_text())
    metrics = json.loads((base / "metrics.json").read_text())

    return MetaArtifacts(
        coef=model["coef"],
        intercept=model["intercept"],
        features=model["features"],
        platt_A=platt["A"],
        platt_B=platt["B"],
        ece=metrics["ece"],
        brier=metrics["brier"],
    )


class MetaEnsemble:
    """Meta-ensemble classifier with Platt scaling."""

    def __init__(self, art: MetaArtifacts):
        """
        Initialize with artifacts.

        Args:
            art: MetaArtifacts from load_artifacts()

        Raises:
            AssertionError: If feature order doesn't match META_FEATURES
        """
        if art.features != META_FEATURES:
            raise ValueError(f"Feature mismatch: {art.features} != {META_FEATURES}")
        self.a = art

    def predict_proba(self, x: List[float]) -> float:
        """
        Predict probability with Platt-scaled logistic regression.

        Args:
            x: Feature vector (must match META_FEATURES order)

        Returns:
            Calibrated probability [0, 1]
        """
        # Linear combination
        z = sum(w * v for w, v in zip(self.a.coef, x)) + self.a.intercept

        # Platt scaling
        p = _sigmoid(self.a.platt_A * z + self.a.platt_B)

        return float(min(max(p, 0.0), 1.0))


def gate_by_calibration(
    art: MetaArtifacts, ece_max: float = 0.05, brier_max: float = 0.10
) -> bool:
    """
    Check if meta-ensemble meets calibration quality gates.

    Only use meta-ensemble if calibration quality is sufficient,
    otherwise fall back to linear combination.

    Args:
        art: MetaArtifacts with calibration metrics
        ece_max: Maximum acceptable ECE (Expected Calibration Error)
        brier_max: Maximum acceptable Brier score

    Returns:
        True if gates passed (safe to use meta-ensemble)
    """
    return (art.ece <= ece_max) and (art.brier <= brier_max)
