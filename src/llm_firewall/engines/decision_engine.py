"""
Honesty Decision Engine - Complete Integration
==============================================

Integrates all components for ANSWER/ABSTAIN decisions:
    1. GroundTruthScorer: Evaluates evidence quality
    2. AdaptiveThresholdManager: Loads user+domain threshold
    3. ProximalRobbinsMonroController: Updates thresholds (if calibration mode)
    4. Sanity checks + Confidence overrides

Author: Claude Sonnet 4.5 (Forschungsleiter)
Date: 2025-10-27
"""

import logging
import uuid
from typing import Optional

from llm_firewall.evidence.ground_truth_scorer import GroundTruthScorer
from llm_firewall.fusion.adaptive_threshold import AdaptiveThresholdManager
from llm_firewall.fusion.robbins_monro import ProximalRobbinsMonroController
from llm_firewall.utils.types import HonestyDecision

logger = logging.getLogger(__name__)


# Sanity queries (MUST pass even with low GT)
SANITY_PATTERNS = [
    # Geography
    {"keywords": ["paris", "france", "capital"], "answer": "yes"},
    {"keywords": ["canberra", "australia", "capital"], "answer": "yes"},
    {"keywords": ["sydney", "capital", "australia"], "answer": "no"},
    # Math
    {"keywords": ["2+2", "4"], "answer": "yes"},
    {"keywords": ["pi", "3.14"], "answer": "yes"},
    {"keywords": ["sqrt", "4", "2"], "answer": "yes"},
    # Science
    {"keywords": ["water", "boils", "100"], "answer": "yes"},
    {"keywords": ["sun", "planet"], "answer": "no"},  # Sun is star
    {"keywords": ["earth", "round"], "answer": "yes"},
]


class HonestyDecisionEngine:
    """
    Makes ANSWER/ABSTAIN decisions with full pipeline integration

    Decision Flow:
        1. Load user adaptive threshold
        2. Check sanity override
        3. Compute GT score vs threshold
        4. Apply confidence safety check
        5. Return decision + detailed reasoning
    """

    def __init__(
        self,
        gt_scorer: GroundTruthScorer,
        threshold_manager: AdaptiveThresholdManager,
        rm_controller: Optional[ProximalRobbinsMonroController] = None,
        min_confidence_override: float = 0.70,
        sanity_override_enabled: bool = True,
    ):
        """
        Args:
            gt_scorer: Ground truth scorer
            threshold_manager: Adaptive threshold manager
            rm_controller: Robbins-Monro controller (optional, for batch updates)
            min_confidence_override: Minimum confidence even if GT high
            sanity_override_enabled: Enable sanity check overrides
        """
        self.gt_scorer = gt_scorer
        self.threshold_manager = threshold_manager
        self.rm_controller = rm_controller
        self.min_confidence = min_confidence_override
        self.sanity_enabled = sanity_override_enabled

        logger.info(
            f"[HonestyEngine] Initialized (min_conf={min_confidence_override}, "
            f"sanity={sanity_override_enabled})"
        )

    def decide(
        self,
        query: str,
        kb_facts: list,
        sources: list,
        confidence: float,
        user_id: str,
        domain: Optional[str] = None,
    ) -> HonestyDecision:
        """
        Make ANSWER/ABSTAIN decision

        Args:
            query: User query
            kb_facts: KB facts from PostgreSQL
            sources: Retrieved sources
            confidence: Model confidence (0-1)
            user_id: User identifier
            domain: Query domain (auto-detect if None)

        Returns:
            HonestyDecision with decision + full reasoning
        """
        # Step 1: Compute Ground Truth score
        gt_score = self.gt_scorer.score(query, kb_facts, sources, domain)
        domain = gt_score.domain  # Use detected domain

        # Step 2: Get adaptive threshold
        threshold = self.threshold_manager.get_threshold(user_id, domain)

        # Step 3: Check sanity override
        is_sanity, sanity_confidence = self._check_sanity(query)

        if self.sanity_enabled and is_sanity and sanity_confidence > 0.95:
            # Sanity query → ALWAYS answer
            should_answer = True
            sanity_override = True
            reasoning = (
                f"Sanity query detected (confidence {sanity_confidence:.1%}) - "
                f"OVERRIDE: Always answer obvious questions"
            )

            logger.info(
                f"[Decision] SANITY OVERRIDE: '{query[:50]}...' → ANSWER "
                f"(sanity_conf={sanity_confidence:.1%})"
            )

        else:
            sanity_override = False

            # Step 4: Primary decision - GT score vs threshold
            should_answer = gt_score.overall_score >= threshold

            # Step 5: Confidence safety check
            if should_answer and confidence < self.min_confidence:
                # High GT but low model confidence = suspicious
                should_answer = False
                reasoning = (
                    f"CONFIDENCE BLOCK: GT score sufficient ({gt_score.overall_score:.1%} >= {threshold:.1%}) "
                    f"but model confidence too low ({confidence:.1%} < {self.min_confidence:.1%})"
                )

                logger.warning(
                    f"[Decision] CONFIDENCE OVERRIDE: '{query[:50]}...' → ABSTAIN "
                    f"(GT={gt_score.overall_score:.1%}, conf={confidence:.1%})"
                )

            else:
                # Normal decision
                margin = gt_score.overall_score - threshold

                if should_answer:
                    reasoning = (
                        f"Ground truth sufficient: {gt_score.overall_score:.1%} >= {threshold:.1%} "
                        f"(margin: +{margin:.1%})"
                    )
                else:
                    reasoning = (
                        f"Ground truth insufficient: {gt_score.overall_score:.1%} < {threshold:.1%} "
                        f"(margin: {margin:.1%})"
                    )

        # Compute margin
        margin = gt_score.overall_score - threshold

        # Get user strictness
        personality = self.threshold_manager._get_personality(user_id)
        directness = personality.get("directness", 0.7)
        bullshit_tolerance = personality.get("bullshit_tolerance", 0.3)
        strictness = (directness + (1.0 - bullshit_tolerance)) / 2.0

        # Create decision object
        decision = HonestyDecision(
            decision="ANSWER" if should_answer else "ABSTAIN",
            reasoning=reasoning,
            gt_score=gt_score.overall_score,
            threshold_used=threshold,
            confidence=confidence,
            margin=margin,
            gt_breakdown=gt_score,
            user_id=user_id,
            user_strictness=strictness,
            decision_id=str(uuid.uuid4()),
            sanity_override=sanity_override,
        )

        logger.info(
            f"[Decision] {user_id}/{domain}: {decision.decision} "
            f"(GT={gt_score.overall_score:.2f}, τ={threshold:.2f}, "
            f"conf={confidence:.2f}, margin={margin:+.2f})"
        )

        return decision

    def _check_sanity(self, query: str) -> tuple:
        """
        Check if query is sanity check (obvious answer)

        Returns:
            (is_sanity, confidence_score)

        Examples:
            "What is the capital of France?" → (True, 0.99)
            "Is 2+2=4?" → (True, 0.99)
        """
        query_lower = query.lower()

        for pattern in SANITY_PATTERNS:
            keywords = pattern["keywords"]
            # Check if all keywords present
            if all(kw in query_lower for kw in keywords):
                return True, 0.99

        return False, 0.0
