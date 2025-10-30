# -*- coding: utf-8 -*-
"""
Deterministic persuasion detector (L1/L2) using regex + lightweight heuristics.
Intended for use in a bidirectional firewall: pre- and post- generation.
Artifacts (lexicons) live in src/llm_firewall/lexicons/persuasion.

Based on Cialdini's 7 Principles of Influence (2024/2025 Research)

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

FLAGS = re.IGNORECASE | re.UNICODE


@dataclass
class PersuasionSignal:
    """Signal from a persuasion category"""

    category: str
    regex_hits: int
    keyword_hits: int
    score: float


DEFAULT_WEIGHTS = {"regex": 1.0, "keyword": 0.5}


class PersuasionDetector:
    """
    Detects persuasion-based jailbreak attempts.

    Uses 7 Cialdini Principles + Roleplay/Jailbreak patterns:
    - Authority
    - Commitment/Consistency
    - Liking (Flattery)
    - Reciprocity
    - Scarcity/Urgency
    - Social Proof
    - Unity/Identity
    - Roleplay/Ignore Rules
    """

    def __init__(self, lexicon_dir: str | pathlib.Path):
        """
        Initialize detector with lexicon directory.

        Args:
            lexicon_dir: Path to directory containing *.json lexicons
        """
        self.lexicon_dir = pathlib.Path(lexicon_dir)
        self._compiled: Dict[str, Tuple[List[re.Pattern], List[str]]] = {}
        self._load()

    def _load(self):
        """Load all JSON lexicons from directory"""
        for p in sorted(self.lexicon_dir.glob("*.json")):
            data = json.loads(p.read_text(encoding="utf-8"))
            regs = [re.compile(r, FLAGS) for r in data.get("regex", [])]
            kws = [k.lower() for k in data.get("keywords", [])]
            self._compiled[p.stem] = (regs, kws)

    def categories(self) -> List[str]:
        """Return list of loaded category names"""
        return list(self._compiled.keys())

    @staticmethod
    def _kw_hits(text: str, kws: List[str]) -> int:
        """Count keyword hits in text"""
        tl = text.lower()
        return sum(1 for k in kws if k in tl)

    def score_text(
        self, text: str, weights: Dict[str, float] = DEFAULT_WEIGHTS
    ) -> Tuple[float, List[PersuasionSignal]]:
        """
        Score text for persuasion patterns.

        Args:
            text: Input text (should be pre-normalized)
            weights: Scoring weights (regex=1.0, keyword=0.5 default)

        Returns:
            (total_score, signals_by_category)
        """
        total = 0.0
        signals: List[PersuasionSignal] = []
        for cat, (regs, kws) in self._compiled.items():
            rh = sum(1 for rgx in regs if rgx.search(text))
            kh = self._kw_hits(text, kws)
            s = rh * weights.get("regex", 1.0) + kh * weights.get("keyword", 0.5)
            if s > 0:
                signals.append(PersuasionSignal(cat, rh, kh, float(s)))
            total += s
        # Sort signals by contribution
        signals.sort(key=lambda x: x.score, reverse=True)
        return total, signals

    def decide(
        self, text: str, warn_threshold: float = 1.5, block_threshold: float = 3.0
    ) -> str:
        """
        Make decision: block, warn, or allow.

        Args:
            text: Input text (should be pre-normalized)
            warn_threshold: Score threshold for warning
            block_threshold: Score threshold for blocking

        Returns:
            "block" | "warn" | "allow"
        """
        score, _ = self.score_text(text)
        if score >= block_threshold:
            return "block"
        if score >= warn_threshold:
            return "warn"
        return "allow"

