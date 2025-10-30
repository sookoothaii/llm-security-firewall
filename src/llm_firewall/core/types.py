"""
Common Types for LLM Security Firewall
=======================================

Type definitions for gates, judges, and risk aggregation.

Based on GPT-5 specification 2025-10-30.

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional, Protocol


class Decision(Enum):
    """Final decision for request."""

    ALLOW = "allow"
    ABSTAIN = "abstain"  # Ask for clarification / safe template
    REDACT = "redact"  # Partial allow with redactions
    DENY = "deny"


class Severity(IntEnum):
    """Risk severity levels."""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class RiskScore:
    """
    Calibrated risk score in [0,1].

    Includes conformal band and provenance.
    """

    value: float  # Risk score [0, 1]
    band: str  # Conformal band (e.g., "S0".."S4")
    severity: Severity  # Derived severity level
    calibrated: bool = True  # Was calibration applied?
    method: str = "platt"  # Calibration method: platt|ats|sls|isotonic|none

    def __post_init__(self):
        """Validate risk score range."""
        if not (0.0 <= self.value <= 1.0):
            raise ValueError(f"Risk value must be in [0, 1], got {self.value}")


@dataclass
class TaxonomyRisk:
    """Per-policy category risks."""

    categories: Dict[str, RiskScore]  # e.g., {"self-harm": ..., "weapons": ...}
    overall: RiskScore


@dataclass
class JudgeReport:
    """Report from a single judge."""

    name: str  # Judge identifier
    version: str  # Judge version
    latency_ms: float  # Execution time
    risks: TaxonomyRisk  # Risk assessment
    features: Dict[str, Any] = field(default_factory=dict)  # Feature values
    notes: Optional[str] = None  # Additional context


@dataclass
class AggregatedRisk:
    """Aggregated risk from multiple judges."""

    overall: RiskScore  # Combined risk score
    per_judge: List[JudgeReport]  # Individual judge reports
    conformal_qhat: float  # Average q-hat across judges
    coverage_target: float  # Target coverage (e.g., 0.90)
    abstain_prob: float  # Probability of abstention


@dataclass
class ModelContext:
    """Context for LLM request."""

    session_id: str
    request_id: str
    user_id: Optional[str]
    model_id: str
    prompt_hash: str
    time_utc: datetime
    extras: Dict[str, Any] = field(default_factory=dict)


# Protocols (Interfaces)


class Judge(Protocol):
    """
    Judge interface for multi-agent defense.

    Each judge provides independent risk assessment.
    """

    name: str
    version: str

    def score(self, ctx: ModelContext, prompt: str, draft: str) -> JudgeReport:
        """
        Score prompt/draft for risk.

        Must be deterministic for same seed.

        Args:
            ctx: Request context
            prompt: User input
            draft: LLM response draft

        Returns:
            JudgeReport with calibrated risk
        """
        ...
