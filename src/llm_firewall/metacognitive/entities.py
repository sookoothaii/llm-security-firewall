"""
Domain entities for Metacognitive Deception Detection.

Pure domain logic - no external dependencies.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class ConsistencyLevel(Enum):
    """Consistency between reasoning and output."""

    ENTAILMENT = "entailment"  # Reasoning supports output
    NEUTRAL = "neutral"  # Reasoning doesn't contradict output
    CONTRADICTION = "contradiction"  # Reasoning contradicts output


class DeceptionType(Enum):
    """Types of metacognitive deception."""

    REASONING_OUTPUT_MISMATCH = "reasoning_output_mismatch"
    MISSING_LOGIC_STEPS = "missing_logic_steps"
    OVERCONFIDENT_CLAIM = "overconfident_claim"
    SELF_CONTRADICTION = "self_contradiction"
    CIRCULAR_REASONING = "circular_reasoning"


@dataclass
class Claim:
    """A claim extracted from reasoning or output."""

    text: str
    source: str  # 'reasoning' or 'output'
    confidence: float = 1.0
    line_number: Optional[int] = None


@dataclass
class ReasoningBlock:
    """Extracted reasoning block from LLM response."""

    raw_text: str
    claims: List[Claim] = field(default_factory=list)
    tag_type: str = "thinking"  # 'thinking', 'antml:thinking', custom
    char_length: int = 0

    def __post_init__(self):
        if self.char_length == 0:
            self.char_length = len(self.raw_text)


@dataclass
class ReasoningQuality:
    """Quality assessment of reasoning."""

    depth_score: float  # 0-1, based on length and structure
    logic_chain_score: float  # 0-1, based on connectives and flow
    completeness_score: float  # 0-1, based on missing steps
    overall_score: float  # 0-1, weighted average

    def __post_init__(self):
        if not (0.0 <= self.depth_score <= 1.0):
            raise ValueError(f"depth_score must be in [0,1], got {self.depth_score}")
        if not (0.0 <= self.logic_chain_score <= 1.0):
            raise ValueError(
                f"logic_chain_score must be in [0,1], got {self.logic_chain_score}"
            )
        if not (0.0 <= self.completeness_score <= 1.0):
            raise ValueError(
                f"completeness_score must be in [0,1], got {self.completeness_score}"
            )
        if not (0.0 <= self.overall_score <= 1.0):
            raise ValueError(
                f"overall_score must be in [0,1], got {self.overall_score}"
            )


@dataclass
class ConsistencyCheck:
    """Result of reasoning-output consistency check."""

    level: ConsistencyLevel
    score: float  # 0-1, confidence in consistency assessment
    reasoning_claim: Claim
    output_claim: Claim
    explanation: str = ""


@dataclass
class MetacognitiveResult:
    """Result of metacognitive validation."""

    has_reasoning: bool
    reasoning_blocks: List[ReasoningBlock]
    quality: Optional[ReasoningQuality]
    consistency_checks: List[ConsistencyCheck]
    deception_detected: bool
    deception_types: List[DeceptionType] = field(default_factory=list)
    risk_score: float = 0.0  # 0-1, overall deception risk
    explanation: str = ""

    def __post_init__(self):
        if not (0.0 <= self.risk_score <= 1.0):
            raise ValueError(f"risk_score must be in [0,1], got {self.risk_score}")
