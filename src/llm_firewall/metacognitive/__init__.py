"""
Metacognitive Deception Detection (MDD)
========================================

Layer 13 of the LLM Security Firewall.

World-first: Detects reasoning-output inconsistencies, overconfident claims,
and metacognitive deception in LLM responses.

Core Components:
- ReasoningParser: Extract thinking blocks and claims
- ConsistencyChecker: NLI-based reasoning-output validation
- QualityScorer: Reasoning depth and logic chain analysis
- MetacognitiveValidator: Main validator orchestrating all checks

Creator: Joerg Bollwahn
Date: 2025-10-29
"""

from llm_firewall.metacognitive.consistency import ConsistencyChecker
from llm_firewall.metacognitive.parser import ReasoningBlock, ReasoningParser
from llm_firewall.metacognitive.quality import QualityScorer, ReasoningQuality
from llm_firewall.metacognitive.validator import (
    MetacognitiveResult,
    MetacognitiveValidator,
)

__all__ = [
    "MetacognitiveValidator",
    "MetacognitiveResult",
    "ReasoningParser",
    "ReasoningBlock",
    "ConsistencyChecker",
    "QualityScorer",
    "ReasoningQuality",
]
