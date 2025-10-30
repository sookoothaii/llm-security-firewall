# -*- coding: utf-8 -*-
"""
Policy Invariance Gate

Applies persuasion detection + neutralization and compares policy decisions
between the original and the neutral restatement. Divergence → conservative block.

Interface:
- `policy_decider(prompt: str) -> str` must return one of {"allow","allow_high_level","block"}.
- `detector` is the PersuasionDetector instance (L1/L2 deterministic).
- `neutralizer` is the Neutralizer instance (rule-based).

This module does not execute any model; it orchestrates decisions.

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from llm_firewall.persuasion.detector import PersuasionDetector
from llm_firewall.persuasion.neutralizer import Neutralizer
from llm_firewall.text.normalize_unicode import normalize

Decision = str  # "allow" | "allow_high_level" | "block"


@dataclass
class InvarianceResult:
    original: str
    restated: str
    s_persuasion: float
    decision_original: Decision
    decision_restated: Decision
    action: Decision  # final action after invariance logic
    reason: str


class InvarianceGate:
    def __init__(
        self,
        detector: PersuasionDetector,
        neutralizer: Neutralizer,
        policy_decider: Callable[[str], Decision],
        warn_threshold: float = 1.5,
        block_threshold: float = 3.0,
    ):
        self.detector = detector
        self.neutralizer = neutralizer
        self.policy_decider = policy_decider
        self.warn_t = warn_threshold
        self.block_t = block_threshold

    def evaluate(self, prompt: str) -> InvarianceResult:
        t = normalize(prompt)
        s, _ = self.detector.score_text(t)
        # Decide on original
        d_orig: Decision = self.policy_decider(t)
        restated_obj = self.neutralizer.restate_neutral(t)
        restated = str(restated_obj["restated"])  # Explicit cast for type checker
        d_rest: Decision = self.policy_decider(restated)

        # Conservative combination rule (fail-safe):
        # If decisions diverge, or persuasion score high, prefer stricter one.
        if d_orig != d_rest:
            final: Decision = min(
                d_orig, d_rest, key=self._severity
            )  # "block" < "allow_high_level" < "allow"
            reason = f"Divergent decisions under restatement (orig={d_orig}, restated={d_rest})."
        else:
            final = d_orig
            reason = "Decisions agree."

        # Escalate when persuasion is strong
        if s >= self.block_t:
            final = "block"
            reason += " Strong persuasion signals detected (>= block threshold)."
        elif s >= self.warn_t and final == "allow":
            final = "allow_high_level"  # or trigger clarification flow
            reason += " Persuasion signals detected (>= warn threshold)."

        return InvarianceResult(
            original=t,
            restated=restated,
            s_persuasion=s,
            decision_original=d_orig,
            decision_restated=d_rest,
            action=final,
            reason=reason,
        )

    @staticmethod
    def _severity(d: Decision) -> int:
        order = {"block": 0, "allow_high_level": 1, "allow": 2}
        return order.get(d, 0)
