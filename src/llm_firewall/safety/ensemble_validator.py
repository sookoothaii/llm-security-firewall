"""
Ensemble Voting System for Multi-Layer Security
================================================

Combines signals from multiple layers using voting logic:
- Requires 2 of 3 layers to agree on BLOCK decision
- Reduces false positives while maintaining security

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Tuple

logger = logging.getLogger(__name__)


@dataclass
class LayerVote:
    """Single layer's vote."""

    layer_name: str
    is_threat: bool
    confidence: float
    reason: str


@dataclass
class EnsembleDecision:
    """Final ensemble decision."""

    is_threat: bool
    votes_for_block: int
    votes_for_safe: int
    confidence: float
    reason: str
    layer_votes: List[LayerVote]


class EnsembleValidator:
    """
    Ensemble voting system for multi-layer detection.

    Decision Logic:
    - If 2+ layers vote BLOCK: BLOCK
    - If 2+ layers vote SAFE: SAFE
    - Tie (1-1-abstain): Use highest confidence

    This reduces false positives while maintaining security.
    """

    def __init__(self, min_votes_to_block: int = 2):
        """
        Initialize ensemble validator.

        Args:
            min_votes_to_block: Minimum layers that must vote BLOCK (default: 2)
        """
        self.min_votes_to_block = min_votes_to_block
        logger.info(f"Ensemble validator initialized (min_votes: {min_votes_to_block})")

    def decide(
        self,
        pattern_vote: LayerVote,
        embedding_vote: LayerVote,
        perplexity_vote: LayerVote,
    ) -> EnsembleDecision:
        """
        Make ensemble decision using ADAPTIVE CONFIDENCE-BASED WEIGHTING.

        Decision Logic (Profi-Lösung):
        1. HIGH CONFIDENCE EMBEDDING (>0.55) + Pattern SAFE → Check if legitimate
        2. If Pattern=BLOCK → Always block (high precision)
        3. If Embedding HIGH (>0.55) + Pattern NOT explicitly safe → Block
        4. Otherwise: Require 2+ votes

        Args:
            pattern_vote: Vote from pattern-based safety validator
            embedding_vote: Vote from embedding detector
            perplexity_vote: Vote from perplexity detector

        Returns:
            EnsembleDecision with final verdict
        """
        layer_votes = [pattern_vote, embedding_vote, perplexity_vote]

        # Count votes
        block_votes = sum(1 for v in layer_votes if v.is_threat)
        safe_votes = len(layer_votes) - block_votes

        # ADAPTIVE LOGIC - Profi-Lösung

        # Rule 1: Pattern explicitly blocks → always block (high precision)
        if pattern_vote.is_threat:
            is_threat = True
            confidence = pattern_vote.confidence
            reason = f"Ensemble: Pattern explicitly blocked. {pattern_vote.reason}"

        # Rule 2: HIGH confidence embedding (>0.55) → block unless clearly benign
        elif embedding_vote.is_threat and embedding_vote.confidence > 0.55:
            # Check if perplexity confirms it's NOT adversarial (benign signal)
            if not perplexity_vote.is_threat and perplexity_vote.confidence < 0.1:
                # Perplexity says "looks normal" → might be false positive
                # But still block if confidence is VERY high (>0.70)
                if embedding_vote.confidence > 0.70:
                    is_threat = True
                    confidence = embedding_vote.confidence
                    reason = f"Ensemble: Very high embedding similarity ({embedding_vote.confidence:.3f}). {embedding_vote.reason}"
                else:
                    is_threat = False
                    confidence = 0.5
                    reason = f"Ensemble: Embedding flagged ({embedding_vote.confidence:.3f}) but likely benign (normal perplexity). Safe."
            else:
                # Not clearly benign → block
                is_threat = True
                confidence = embedding_vote.confidence
                reason = f"Ensemble: High embedding similarity ({embedding_vote.confidence:.3f}). {embedding_vote.reason}"

        # Rule 3: Standard voting (need 2+ layers)
        elif block_votes >= self.min_votes_to_block:
            is_threat = True
            confidence = (
                sum(v.confidence for v in layer_votes if v.is_threat) / block_votes
            )
            reason = f"Ensemble: {block_votes}/3 layers detected threat. "
            reason += ", ".join([v.reason for v in layer_votes if v.is_threat])

        # Rule 4: Safe
        else:
            is_threat = False
            if safe_votes > 0:
                confidence = (
                    sum(v.confidence for v in layer_votes if not v.is_threat)
                    / safe_votes
                )
            else:
                confidence = 0.5
            reason = f"Ensemble: Only {block_votes}/3 layers flagged (need {self.min_votes_to_block}+). Safe."

        return EnsembleDecision(
            is_threat=is_threat,
            votes_for_block=block_votes,
            votes_for_safe=safe_votes,
            confidence=confidence,
            reason=reason,
            layer_votes=layer_votes,
        )

    def validate(
        self, text: str, pattern_detector, embedding_detector, perplexity_detector
    ) -> Tuple[bool, str]:
        """
        Run ensemble validation on text.

        Args:
            text: Input text
            pattern_detector: Pattern-based validator
            embedding_detector: Embedding detector
            perplexity_detector: Perplexity detector

        Returns:
            (is_safe, reason) tuple
        """
        # Get votes from each layer
        pattern_result = pattern_detector.validate(text)
        pattern_vote = LayerVote(
            layer_name="Pattern",
            is_threat=(pattern_result.action == "BLOCK"),
            confidence=pattern_result.intent_score
            if hasattr(pattern_result, "intent_score")
            else 0.8,
            reason=f"Pattern: {pattern_result.reason}",
        )

        embedding_result = (
            embedding_detector.detect(text)
            if embedding_detector and embedding_detector.available
            else None
        )
        if embedding_result:
            embedding_vote = LayerVote(
                layer_name="Embedding",
                is_threat=embedding_result.is_jailbreak,
                confidence=embedding_result.max_similarity,
                reason=f"Embedding: sim={embedding_result.max_similarity:.3f}",
            )
        else:
            # Abstain if detector unavailable
            embedding_vote = LayerVote(
                layer_name="Embedding",
                is_threat=False,
                confidence=0.0,
                reason="Embedding: unavailable",
            )

        perplexity_result = (
            perplexity_detector.detect(text)
            if perplexity_detector and perplexity_detector.available
            else None
        )
        if perplexity_result:
            perplexity_vote = LayerVote(
                layer_name="Perplexity",
                is_threat=perplexity_result.is_adversarial,
                confidence=1.0 - (perplexity_result.perplexity / 1000.0)
                if perplexity_result.is_adversarial
                else 0.0,
                reason=f"Perplexity: {perplexity_result.perplexity:.1f}",
            )
        else:
            # Abstain if detector unavailable
            perplexity_vote = LayerVote(
                layer_name="Perplexity",
                is_threat=False,
                confidence=0.0,
                reason="Perplexity: unavailable",
            )

        # Make ensemble decision
        decision = self.decide(pattern_vote, embedding_vote, perplexity_vote)

        logger.info(
            f"Ensemble decision: {decision.votes_for_block}/3 BLOCK, {decision.votes_for_safe}/3 SAFE"
        )

        return (not decision.is_threat, decision.reason)
