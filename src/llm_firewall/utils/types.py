"""
Type Definitions for Adversarial Honesty System
================================================
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class FeedbackType(str, Enum):
    """User feedback on system decision"""
    CORRECT = "CORRECT"                    # System decision was correct
    WRONG_ABSTAIN = "WRONG_ABSTAIN"        # Should have answered (Type I error)
    WRONG_ANSWER = "WRONG_ANSWER"          # Should have abstained (Type II error)


class ConvergenceStatus(str, Enum):
    """Threshold convergence state"""
    LEARNING = "LEARNING"          # < 20 samples
    CONVERGING = "CONVERGING"      # Variance decreasing
    CONVERGED = "CONVERGED"        # Variance < threshold
    DIVERGING = "DIVERGING"        # Variance increasing (instability)


@dataclass
class GroundTruthScore:
    """Ground truth assessment result"""
    overall_score: float              # 0-1 weighted average
    kb_coverage: float                # 0-1 KB fact density
    source_quality: float             # 0-1 source count + quality
    recency_score: float              # 0-1 temporal freshness

    # Breakdown
    kb_fact_count: int
    source_count: int
    verified_source_count: int
    days_since_newest: int

    # Domain
    domain: str
    domain_half_life: int             # days

    # Metadata
    query: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class HonestyDecision:
    """Honesty decision result"""
    decision: str                     # 'ANSWER' | 'ABSTAIN'
    reasoning: str                    # Human-readable explanation

    # Scores
    gt_score: float
    threshold_used: float
    confidence: float
    margin: float                     # gt_score - threshold

    # Breakdown
    gt_breakdown: GroundTruthScore

    # User context
    user_id: str
    user_strictness: float

    # Decision metadata
    decision_id: str
    timestamp: datetime = field(default_factory=datetime.now)

    # Sanity override flag
    sanity_override: bool = False

    # Explanation
    formatted_explanation: Optional[str] = None


@dataclass
class ThresholdUpdate:
    """Threshold learning update result"""
    old_threshold: float
    new_threshold: float
    adjustment: float
    learning_rate: float

    # Trigger
    feedback_type: FeedbackType
    gt_score: float

    # Statistics
    n_updates: int
    n_type1_errors: int               # Wrong abstain
    n_type2_errors: int               # Wrong answer
    n_correct: int

    # Convergence
    variance: float
    convergence_status: ConvergenceStatus

    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class LearningUpdate:
    """Learning loop result"""
    threshold_updates: List[ThresholdUpdate]

    # Overall metrics
    total_feedbacks: int
    precision: float                  # correct_answer / (correct_answer + wrong_answer)
    recall: float                     # correct_answer / (correct_answer + wrong_abstain)
    f1_score: float

    # Error analysis
    type1_rate: float                 # wrong_abstain / total
    type2_rate: float                 # wrong_answer / total

    # Recommendations
    should_recalibrate: bool
    convergence_achieved: bool

    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class HonestyStatistics:
    """System statistics over time window"""
    user_id: str
    time_window: str                  # 'last_7_days' | 'last_30_days' | 'all_time'

    # Decision counts
    total_decisions: int
    answered: int
    abstained: int
    abstention_rate: float

    # Accuracy (with feedback)
    n_with_feedback: int
    correct_answers: int
    correct_abstentions: int
    wrong_answers: int
    wrong_abstentions: int

    # Performance metrics
    precision: float                  # When answer, how often correct
    recall: float                     # Of answerable, how many answered
    f1_score: float
    type1_error_rate: float
    type2_error_rate: float

    # Learning progress
    avg_threshold: float
    threshold_variance: float
    convergence_status: ConvergenceStatus

    # Distribution
    gt_score_mean: float
    gt_score_std: float
    gt_score_histogram: Dict[str, int]  # Bins: 0-0.2, 0.2-0.4, ...

    # Temporal
    computed_at: datetime = field(default_factory=datetime.now)
    first_decision: Optional[datetime] = None
    last_decision: Optional[datetime] = None


@dataclass
class DomainConfig:
    """Domain-specific configuration"""
    domain: str

    # Weights for GT scoring
    weight_kb: float = 0.40
    weight_sources: float = 0.40
    weight_recency: float = 0.20

    # Half-life for recency
    half_life_days: int = 365

    # Requirements
    min_kb_facts: int = 5
    min_sources: int = 3
    min_verified_sources: int = 1

    # Initial threshold
    base_threshold: float = 0.70

