"""
GPT-5 Detection Pack Integration
=================================

Scientific A/B testable layer using:
- Pattern matching (43 regex patterns with categories/weights)
- Intent lexicon scoring (14 clusters with Aho-Corasick)
- Evasion phrase detection (shared across clusters)
- Harm domain macro expansion

Research Design:
- Isolated layer (can be enabled/disabled via config)
- Combines pattern_score and intent_lex_score
- Calibrated threshold for optimal ASR/FPR trade-off

Integration: October 28, 2025
Source: GPT-5 Detection Pack (feat/gpt5-detection-pack)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)


class GPT5Detector:
    """
    GPT-5 Detection Pack: Pattern + Intent Lexicon Scoring.

    Combines:
    1. Regex pattern matching (weighted categories)
    2. Intent cluster detection (Aho-Corasick trie)
    3. Evasion phrase matching
    4. Harm domain macro expansion

    Design:
    - Separate layer for A/B testing
    - Config-controlled (enable_gpt5_detector flag)
    - Does NOT replace existing layers (Defense in Depth)
    """

    def __init__(
        self,
        enabled: bool = True,
        pattern_weight: float = 1.0,
        intent_weight: float = 0.8,
        threshold: float = 0.5,
    ):
        """
        Initialize GPT5Detector.

        Args:
            enabled: Whether this detector is active
            pattern_weight: Weight for pattern_score (default: 1.0)
            intent_weight: Weight for intent_lex_score (default: 0.8)
            threshold: Risk threshold for blocking (default: 0.5)
        """
        self.enabled = enabled
        self.pattern_weight = pattern_weight
        self.intent_weight = intent_weight
        self.threshold = threshold
        self.available = False

        if not enabled:
            logger.info("GPT5Detector disabled via config")
            return

        # Try to import scoring_gpt5
        try:
            from llm_firewall.rules.scoring_gpt5 import evaluate, load_lexicons

            self.evaluate_fn = evaluate

            # Verify lexicons exist
            lex_dir = Path(__file__).parent.parent / "lexicons_gpt5"
            if not lex_dir.exists():
                logger.warning(
                    f"GPT-5 lexicons not found at {lex_dir}, detector disabled"
                )
                self.available = False
                return

            # Test load
            try:
                load_lexicons(lex_dir)
                self.available = True
                logger.info(
                    f"GPT5Detector initialized (pattern_w={pattern_weight}, intent_w={intent_weight}, threshold={threshold})"
                )
            except Exception as e:
                logger.warning(f"Failed to load GPT-5 lexicons: {e}, detector disabled")
                self.available = False

        except ImportError as e:
            logger.warning(f"scoring_gpt5 not available: {e}, detector disabled")
            self.available = False

    def check(self, text: str) -> Dict[str, Any]:
        """
        Check text against GPT-5 detection patterns.

        Args:
            text: Input text to analyze

        Returns:
            {
                "risk_score": float [0-1],
                "reason": str,
                "blocked": bool,
                "details": {
                    "pattern": {...},
                    "intent": {...}
                }
            }
        """
        if not self.enabled or not self.available:
            return {
                "risk_score": 0.0,
                "reason": "GPT5Detector disabled or unavailable",
                "blocked": False,
                "details": {},
            }

        try:
            # CRITICAL: Canonicalize BEFORE evaluation (evasion resistance)
            try:
                from ..text.normalize import canonicalize

                text_canonical = canonicalize(text)
            except ImportError:
                # Fallback if canonicalization not available
                logger.warning(
                    "Canonicalization not available - evasion attacks possible!"
                )
                text_canonical = text

            # Run evaluation (with windowing for long texts)
            # Use windowing if text is long to prevent false positives
            if len(text_canonical) > 1024:
                try:
                    from ..rules.scoring_gpt5 import evaluate_windowed

                    result = evaluate_windowed(text_canonical, max_gap=3)
                except Exception:
                    # Fallback to normal evaluation
                    result = self.evaluate_fn(text_canonical)
            else:
                result = self.evaluate_fn(text_canonical)

            # Extract scores
            pattern_score = result["pattern"]["score"]
            intent_score = result["intent"]["lex_score"]

            # Weighted combination (max of weighted scores)
            # Rationale: If EITHER pattern OR intent fires strongly, flag it
            r_linear = (
                pattern_score * self.pattern_weight
                + intent_score * self.intent_weight * 0.4
            )

            # Category floors (OR-logic for escalation)
            # Ensure high single-category scores escalate properly
            cat = result["pattern"]["by_category"]
            f_I = 0.55 if cat.get("jailbreak_instruction_bypass", 0) > 0 else 0.0
            f_E = (
                0.45
                if (
                    cat.get("obfuscation_encoding", 0) > 0
                    or cat.get("unicode_evasion", 0) > 0
                )
                else 0.0
            )
            f_T = 0.50 if cat.get("information_extraction_sensitive", 0) > 0 else 0.0
            f_C = 0.50 if cat.get("capability_escalation", 0) > 0 else 0.0

            # Take maximum of linear and floor-based risk
            combined_score = max(r_linear, f_I, f_E, f_T, f_C)

            # Determine if blocked
            blocked = combined_score >= self.threshold

            # Build reason
            if blocked:
                top_category = (
                    list(result["pattern"]["by_category"].keys())[0]
                    if result["pattern"]["by_category"]
                    else "unknown"
                )
                top_intent = result["intent"]["top_cluster"]
                reason = f"GPT-5: pattern={pattern_score:.3f} (cat={top_category}), intent={intent_score:.3f} (cluster={top_intent})"
            else:
                reason = "GPT-5: Below threshold"

            return {
                "risk_score": round(combined_score, 6),
                "reason": reason,
                "blocked": blocked,
                "details": {
                    "pattern_score": pattern_score,
                    "intent_score": intent_score,
                    "pattern_details": result["pattern"],
                    "intent_details": result["intent"],
                    "combination_method": "max(pattern*w_p, intent*w_i)",
                },
            }

        except Exception as e:
            logger.error(f"GPT5Detector error: {e}", exc_info=True)
            return {
                "risk_score": 0.0,
                "reason": f"GPT5Detector error: {e}",
                "blocked": False,
                "details": {"error": str(e)},
            }
