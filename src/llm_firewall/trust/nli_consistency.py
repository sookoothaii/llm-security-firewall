"""
NLI Consistency Checker - Evidence vs KB Consensus
===================================================

Checks if new evidence is consistent with existing KB knowledge.

Based on GPT-5 Evidence Pipeline (2025-10-27):
"NLI-basierte Konsistenz-Checks zwischen neuem Fakt und KB-Konsens"
"""

from __future__ import annotations
from typing import Sequence, Protocol, Optional
import logging

logger = logging.getLogger(__name__)


class NLIModel(Protocol):
    """Protocol for NLI model implementations."""
    
    def entailment_prob(self, premise: str, hypothesis: str) -> float:
        """
        Return P(entailment) in [0,1].
        
        Args:
            premise: Background knowledge
            hypothesis: Claim to check
            
        Returns:
            Probability of entailment
        """
        ...


class FakeNLI(NLIModel):
    """
    Deterministic stub for tests.
    
    Simple substring match (for testing only).
    """
    
    def entailment_prob(self, premise: str, hypothesis: str) -> float:
        """Simple substring entailment for testing."""
        # Deterministic stub: substring match
        premise_lower = premise.strip().lower()
        hypothesis_lower = hypothesis.strip().lower()
        
        if hypothesis_lower in premise_lower:
            return 1.0
        else:
            return 0.0


def consistency_against_kb(
    hypothesis: str,
    kb_sentences: Sequence[str],
    model: NLIModel,
    agg: str = "max"
) -> float:
    """
    Compute aggregate entailment score vs. KB consensus.
    
    Args:
        hypothesis: New claim to validate
        kb_sentences: Existing KB facts (premises)
        model: NLI model implementation
        agg: Aggregation method ('mean' or 'max')
        
    Returns:
        Aggregate entailment score (0-1)
        
    Examples:
        >>> model = FakeNLI()
        >>> kb = ["Paris is the capital of France"]
        >>> consistency_against_kb("Paris", kb, model, "max")
        1.0
    """
    if not kb_sentences:
        logger.warning("[NLI] Empty KB - cannot validate consistency")
        return 0.0
    
    # Compute entailment for each KB sentence
    scores = []
    for premise in kb_sentences:
        score = model.entailment_prob(premise, hypothesis)
        scores.append(score)
    
    # Aggregate
    if agg == "mean":
        result = sum(scores) / len(scores)
    elif agg == "max":
        result = max(scores)  # Optimistic: any strong support
    elif agg == "min":
        result = min(scores)  # Pessimistic: all must support
    else:
        raise ValueError(f"Unknown aggregation: {agg}")
    
    logger.debug(
        f"[NLI] Consistency check: {result:.2f} "
        f"({len(kb_sentences)} KB sentences, agg={agg})"
    )
    
    return result


def check_contradiction(
    hypothesis: str,
    kb_sentences: Sequence[str],
    model: NLIModel
) -> float:
    """
    Check for contradictions with KB.
    
    Args:
        hypothesis: Claim to check
        kb_sentences: Existing KB facts
        model: NLI model
        
    Returns:
        Max contradiction score (0-1)
    """
    if not kb_sentences:
        return 0.0
    
    # For real NLI models, check contradiction label
    # For now, use simple heuristics
    contradiction_scores = []
    
    # Check for negations and opposites
    hypothesis_lower = hypothesis.lower()
    
    for sentence in kb_sentences:
        sentence_lower = sentence.lower()
        
        # Simple heuristic: negation words
        if ('not' in hypothesis_lower and 'not' not in sentence_lower) or \
           ('not' in sentence_lower and 'not' not in hypothesis_lower):
            contradiction_scores.append(0.5)
        else:
            contradiction_scores.append(0.0)
    
    return max(contradiction_scores) if contradiction_scores else 0.0

