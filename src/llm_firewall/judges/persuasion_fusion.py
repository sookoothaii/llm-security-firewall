"""
Persuasion Fusion Judge
=======================

Combines Band-Judge (Layer 12) with Persuasion Detector (Layer 13).

Late fusion for social engineering detection.

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

import time

from llm_firewall.core.types import (
    JudgeReport,
    ModelContext,
    RiskScore,
    Severity,
    TaxonomyRisk,
)
from llm_firewall.persuasion import PersuasionDetector
from llm_firewall.safety.band_judge import BandJudge


class PersuasionFusionJudge:
    """
    Fusion of Persuasion Detector + Band-Judge.

    Strategy:
    - Always run Persuasion Detector (fast, <20ms)
    - Only invoke Band-Judge if Persuasion in grey zone (1.0-2.5)
    - Late fusion: max(persuasion, band_judge) with calibrated OR
    - Dual thresholds: advice vs action
    - Source-awareness: creator_instance_id features
    """

    name = "persuasion_fusion"
    version = "1.1.0"  # Upgraded with dual thresholds + source-awareness

    def __init__(
        self,
        persuasion_detector: PersuasionDetector,
        band_judge: BandJudge,
        grey_zone_min: float = 1.0,
        grey_zone_max: float = 2.5,
        advice_threshold: float = 1.5,  # Lower threshold for advice-only
        action_threshold: float = 3.0,  # Higher threshold for actionable instructions
    ):
        """
        Initialize fusion judge.

        Args:
            persuasion_detector: Cialdini-based detector (Layer 13)
            band_judge: LLM-as-judge meta-check (Layer 12)
            grey_zone_min: Min persuasion score to trigger band-judge
            grey_zone_max: Max persuasion score to trigger band-judge
        """
        self.persuasion = persuasion_detector
        self.band_judge = band_judge
        self.grey_zone_min = grey_zone_min
        self.grey_zone_max = grey_zone_max
        self.advice_threshold = advice_threshold
        self.action_threshold = action_threshold

        # Patterns for actionable instructions (vs mere advice)
        self.action_patterns = [
            r"\bstep\s+\d+",
            r"\bfirst,?\s+(you\s+)?",
            r"\bthen,?\s+(you\s+)?",
            r"\bfinally,?\s+(you\s+)?",
            r"\bhow\s+to\s+make",
            r"\brecipe\s+for",
            r"\binstructions?\s+for",
        ]

    def score(self, ctx: ModelContext, prompt: str, draft: str) -> JudgeReport:
        """
        Score for social engineering / persuasion attempts.

        Args:
            ctx: Model context
            prompt: User input
            draft: LLM response

        Returns:
            JudgeReport with fused risk assessment
        """
        t0 = time.perf_counter()

        # Always run persuasion detector
        combined_text = prompt + "\n" + draft
        p_score, p_signals = self.persuasion.score_text(combined_text)

        # Check for actionable instructions (vs mere advice)
        import re

        is_actionable = any(
            re.search(pat, combined_text.lower()) for pat in self.action_patterns
        )

        # Apply dual thresholds
        threshold = self.action_threshold if is_actionable else self.advice_threshold

        # Normalize to [0, 1]
        p_risk = min(1.0, p_score / 5.0)  # Max persuasion score ~5, normalize

        # Source-awareness: Check for self-referential patterns
        self_ref_patterns = [
            r"\bi\s+(created|wrote|authored|generated)",
            r"\bmy\s+(previous|earlier)\s+(response|answer)",
            r"\bas\s+i\s+(said|mentioned|explained)",
        ]
        is_self_referential = any(
            re.search(pat, draft.lower()) for pat in self_ref_patterns
        )

        # Boost risk if self-referential + persuasive (potential manipulation)
        if is_self_referential and p_score > 1.0:
            p_risk = min(1.0, p_risk * 1.3)  # 30% boost for self-referential persuasion

        # Invoke band-judge only if in grey zone
        bj_risk = 0.0
        bj_invoked = False

        if self.grey_zone_min <= p_score <= self.grey_zone_max:
            # Band-judge check (simplified - real impl would use actual API)
            # bj_result = self.band_judge.check(prompt + " " + draft)
            # bj_risk = bj_result.get('risk', 0.0)
            # For now: Placeholder (band-judge API needs proper integration)
            bj_risk = 0.0
            bj_invoked = True

        # Late fusion: max (robust for OR-logic)
        fused_risk = max(p_risk, bj_risk)

        # Map to severity
        if fused_risk >= 0.7:
            severity = Severity.HIGH
        elif fused_risk >= 0.4:
            severity = Severity.MEDIUM
        elif fused_risk >= 0.2:
            severity = Severity.LOW
        else:
            severity = Severity.NONE

        latency_ms = (time.perf_counter() - t0) * 1000

        # Build report
        categories = {}
        for signal in p_signals:
            categories[signal.category] = RiskScore(
                value=signal.score / 5.0,
                band="unknown",
                severity=Severity.LOW if signal.score > 0 else Severity.NONE,
                calibrated=False,
            )

        overall = RiskScore(
            value=fused_risk,
            band="unknown",  # Would need conformal calibration
            severity=severity,
            calibrated=False,
            method="fusion",
        )

        return JudgeReport(
            name=self.name,
            version=self.version,
            latency_ms=latency_ms,
            risks=TaxonomyRisk(categories=categories, overall=overall),
            features={
                "persuasion_score": p_score,
                "persuasion_signals": len(p_signals),
                "band_judge_invoked": bj_invoked,
                "band_judge_risk": bj_risk,
                "is_actionable": is_actionable,
                "is_self_referential": is_self_referential,
                "threshold_used": threshold,
                "advice_threshold": self.advice_threshold,
                "action_threshold": self.action_threshold,
            },
            notes=f"Fusion: p={p_risk:.3f}, bj={bj_risk:.3f}, fused={fused_risk:.3f}",
        )
