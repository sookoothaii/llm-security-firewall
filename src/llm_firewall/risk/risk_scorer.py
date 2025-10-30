"""
Risk scoring with meta-ensemble and data-driven floors.

Implements Joerg's compute_risk_score() with:
- Canonicalization (always)
- Pattern + Intent scoring
- Data-driven category floors (from floors.json)
- Meta-ensemble (gated by ECE/Brier)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from ..config import SETTINGS
from ..core import LEX_BASE, _artifacts_base, compute_features
from ..rules.scoring_gpt5 import intent_lex_score, load_lexicons, pattern_score
from ..text.normalize import canonicalize
from .stacking import MetaEnsemble, gate_by_calibration, load_artifacts


def _load_floors() -> Dict[str, float]:
    """
    Load data-driven category floors from artifacts.

    Returns:
        Dict mapping category names to floor values
    """
    floors_path = Path(__file__).resolve().parents[2] / "artifacts" / "floors.json"
    if floors_path.exists():
        try:
            return json.loads(floors_path.read_text())
        except Exception:
            return {}
    return {}


def compute_risk_score(
    text: str, kb: Optional[Any] = None, detectors: Dict[str, float] | None = None
) -> float:
    """
    Compute risk score with canonicalization, floors, and optional meta-ensemble.

    Pipeline:
    1. Canonicalize text (always, idempotent safety-net)
    2. Compute pattern + intent scores
    3. Linear combination: 0.6*pattern + 0.4*intent
    4. Apply data-driven category floors (OR-logic)
    5. If meta-ensemble enabled + calibrated, use it (still respect floors)

    Args:
        text: Input text (will be canonicalized)
        kb: Optional knowledge base (unused, for compatibility)
        detectors: Optional detector results (emb_sim, ppl_anom, llm_judge)

    Returns:
        Risk score [0, 1]
    """
    # Safety-net: Always canonicalize (idempotent)
    text = canonicalize(text)

    # Load lexicons and patterns
    if LEX_BASE is None:
        raise RuntimeError("LEX_BASE not available - core module not loaded")
    intents, evasions, harms = load_lexicons(base_dir=LEX_BASE)
    patterns_path = Path(__file__).parent.parent / "rules" / "patterns_gpt5.json"
    patterns_json = json.loads(patterns_path.read_text())

    # Compute scores
    p = pattern_score(text, patterns_json, harms["stems"])
    i = intent_lex_score(text, intents, evasions, max_gap=SETTINGS.max_gap)

    # Linear combination
    r_linear = min(1.0, p["score"] * 0.6 + i["lex_score"] * 0.4)

    # Category floors (data-driven from floors.json)
    cat = p["by_category"]
    floors = _load_floors()

    def fval(key: str, default: float) -> float:
        """Get floor value with fallback to default."""
        return float(floors.get(key, default))

    # Apply floors only if category fires
    f_I = (
        fval("jailbreak_instruction_bypass", 0.55)
        if cat.get("jailbreak_instruction_bypass", 0) > 0
        else 0.0
    )
    f_E = (
        fval("evasion_floor", 0.45)
        if (
            cat.get("obfuscation_encoding", 0.0) > 0
            or cat.get("unicode_evasion", 0.0) > 0
        )
        else 0.0
    )
    f_T = (
        fval("information_extraction_sensitive", 0.50)
        if cat.get("information_extraction_sensitive", 0.0) > 0
        else 0.0
    )
    f_C = (
        fval("capability_escalation", 0.50)
        if cat.get("capability_escalation", 0.0) > 0
        else 0.0
    )

    # Baseline: max(linear, floors)
    R_base = max(r_linear, f_I, f_E, f_T, f_C)

    # Meta-ensemble (if enabled and calibrated)
    if SETTINGS.use_meta_ensemble:
        try:
            if _artifacts_base is None or compute_features is None:
                raise RuntimeError("Meta-ensemble functions not available")

            art = load_artifacts(_artifacts_base())

            # Gate: Only use if ECE/Brier quality sufficient
            if gate_by_calibration(art):
                feats = compute_features(text, detectors=detectors)
                meta = MetaEnsemble(art)
                r_meta = meta.predict_proba(feats)

                # Still respect category floors (safety-net)
                return float(max(r_meta, f_I, f_E, f_T, f_C))
        except Exception:
            # Fallback to baseline if meta-ensemble fails
            pass

    return float(R_base)
