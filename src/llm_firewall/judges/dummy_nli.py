"""
Dummy NLI for Testing
=====================

Simple regex-based NLI scorer for testing NLIConsistencyJudge.

Production should use real NLI model (e.g., roberta-large-mnli).

Creator: GPT-5 (adapted by Joerg Bollwahn)
Date: 2025-10-30
License: MIT
"""

import re
from typing import Tuple


class DummyNLI:
    """
    Dummy NLI scorer for testing.

    Uses simple heuristics:
    - Contradiction: Hypothesis negates premise
    - Entailment: High word overlap
    - Neutral: Default
    """

    def __init__(self):
        """Initialize dummy NLI."""
        self.neg_pattern = re.compile(
            r"\b(no|not|never|without|cannot|can't|won't)\b", re.I
        )

    def __call__(self, premise: str, hypothesis: str) -> Tuple[float, float, float]:
        """
        Return logits for (entailment, contradiction, neutral).

        Args:
            premise: Premise text
            hypothesis: Hypothesis text

        Returns:
            (entailment_logit, contradiction_logit, neutral_logit)
        """
        # Contradiction: Hypothesis has negation but premise doesn't
        has_neg_hyp = bool(self.neg_pattern.search(hypothesis))
        has_neg_prem = bool(self.neg_pattern.search(premise))

        if has_neg_hyp and not has_neg_prem:
            contradiction = 2.0
        else:
            contradiction = 0.1

        # Entailment: High word overlap
        prem_words = set(premise.lower().split())
        hyp_words = set(hypothesis.lower().split())
        overlap = len(prem_words & hyp_words)

        if overlap > 5:
            entailment = 1.5
        else:
            entailment = 0.2

        # Neutral: Default
        neutral = 0.3

        return (entailment, contradiction, neutral)
