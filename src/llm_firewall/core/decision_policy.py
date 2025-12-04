"""
AnswerPolicy: Epistemic Decision Layer for LLM Security Firewall
================================================================

Implements utility-based decision making: answer vs. silence based on
expected utility of correctness vs. cost of errors.

Mathematical foundation:
    E[U(answer)] = p_correct * B - (1 - p_correct) * C
    E[U(silence)] = -A

    Answer if: p_correct >= (C - A) / (C + B)

Where:
    - p_correct: Estimated probability that answer is correct
    - B: Benefit if answer is correct
    - C: Cost if answer is wrong
    - A: Cost of silence (block / no answer)

This replaces/additional to simple threshold-based decisions with
explicit cost-benefit trade-offs.

Author: Joerg Bollwahn
Date: 2025-12-02
License: MIT
"""

from dataclasses import dataclass
from typing import Literal, Optional


@dataclass
class AnswerPolicy:
    """
    AnswerPolicy configuration for epistemic decision making.

    Attributes:
        benefit_correct: Benefit (B) if answer is correct (default: 1.0)
        cost_wrong: Cost (C) if answer is wrong (default: 9.0)
        cost_silence: Cost (A) of silence/block (default: 0.0)
        policy_name: Optional name for logging/debugging
    """

    benefit_correct: float = 1.0
    cost_wrong: float = 9.0
    cost_silence: float = 0.0
    policy_name: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate policy parameters."""
        if self.benefit_correct < 0:
            raise ValueError("benefit_correct must be >= 0")
        if self.cost_wrong < 0:
            raise ValueError("cost_wrong must be >= 0")
        if self.cost_silence < 0:
            raise ValueError("cost_silence must be >= 0")
        if self.benefit_correct == 0 and self.cost_wrong == 0:
            raise ValueError(
                "At least one of benefit_correct or cost_wrong must be > 0"
            )

    def threshold(self) -> float:
        """
        Calculate minimal p_correct threshold for answering.

        Returns:
            Minimal p_correct value (0.0-1.0) required to answer.
            If threshold > 1.0, always block. If threshold < 0.0, always allow.
        """
        B = self.benefit_correct
        C = self.cost_wrong
        A = self.cost_silence

        if B + C == 0:
            return 1.0  # Default: block if no benefit/cost defined

        threshold = (C - A) / (C + B)
        return max(0.0, min(1.0, threshold))  # Clamp to [0, 1]

    def decide(
        self, p_correct: float, risk_score: Optional[float] = None
    ) -> Literal["answer", "silence"]:
        """
        Decide whether to answer or remain silent based on p_correct.

        Args:
            p_correct: Estimated probability that answer is correct (0.0-1.0)
            risk_score: Optional risk score (if provided, used to derive p_correct)

        Returns:
            "answer" if expected utility of answering >= expected utility of silence,
            "silence" otherwise.
        """
        # If risk_score provided, derive p_correct from it
        if risk_score is not None:
            p_risk = max(0.0, min(1.0, risk_score))
            p_correct = 1.0 - p_risk

        # Clamp p_correct to valid range
        p_correct = max(0.0, min(1.0, p_correct))

        # Calculate threshold
        t = self.threshold()

        # Decision: answer if p_correct >= threshold
        return "answer" if p_correct >= t else "silence"

    def expected_utility_answer(self, p_correct: float) -> float:
        """
        Calculate expected utility of answering.

        Args:
            p_correct: Probability that answer is correct

        Returns:
            Expected utility: p_correct * B - (1 - p_correct) * C
        """
        p_correct = max(0.0, min(1.0, p_correct))
        return p_correct * self.benefit_correct - (1.0 - p_correct) * self.cost_wrong

    def expected_utility_silence(self) -> float:
        """
        Calculate expected utility of silence.

        Returns:
            Expected utility: -A
        """
        return -self.cost_silence


# Predefined policy configurations
POLICIES = {
    "default": AnswerPolicy(
        benefit_correct=1.0,
        cost_wrong=5.0,
        cost_silence=0.5,
        policy_name="default",
    ),
    "kids": AnswerPolicy(
        benefit_correct=1.0,
        cost_wrong=50.0,
        cost_silence=0.0,
        policy_name="kids",
    ),
    "internal_debug": AnswerPolicy(
        benefit_correct=1.0,
        cost_wrong=1.0,
        cost_silence=2.0,
        policy_name="internal_debug",
    ),
    "strict": AnswerPolicy(
        benefit_correct=1.0,
        cost_wrong=20.0,
        cost_silence=0.0,
        policy_name="strict",
    ),
    "permissive": AnswerPolicy(
        benefit_correct=1.0,
        cost_wrong=2.0,
        cost_silence=1.0,
        policy_name="permissive",
    ),
    "kids_evidence": AnswerPolicy(
        benefit_correct=1.0,
        cost_wrong=1.857142857142857,  # Calibrated for threshold=0.65: (0.65/(1-0.65)) ≈ 1.857
        cost_silence=0.0,
        policy_name="kids_evidence",
    ),
}


def get_policy(policy_name: str) -> AnswerPolicy:
    """
    Get predefined policy by name.

    Args:
        policy_name: Name of policy ("default", "kids", "internal_debug", etc.)

    Returns:
        AnswerPolicy instance

    Raises:
        KeyError: If policy_name not found
    """
    if policy_name not in POLICIES:
        raise KeyError(
            f"Policy '{policy_name}' not found. Available: {list(POLICIES.keys())}"
        )
    return POLICIES[policy_name]
