"""
CARE Port (Hexagonal Architecture)
Creator: Joerg Bollwahn

Cognitive And Research Effectiveness assessment.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional


@dataclass
class ReadinessScore:
    """Cognitive readiness assessment result."""

    user_id: str
    readiness_score: float  # 0.0-1.0
    recommendation: str  # READY, MARGINAL, NOT_READY
    factors: Dict[str, float]  # Contributing factors
    timestamp: datetime
    model_confidence: float


@dataclass
class SessionOutcome:
    """Research session outcome for CARE learning."""

    session_id: str
    user_id: str
    facts_attempted: int
    facts_supported: int
    success_rate: float
    cognitive_state: Dict[str, float]
    timestamp: datetime


class CAREPort(ABC):
    """Abstract port for CARE functionality."""

    @abstractmethod
    def get_readiness(self, user_id: str) -> ReadinessScore:
        """Get current cognitive readiness score."""
        pass

    @abstractmethod
    def log_session(
        self,
        session_id: str,
        user_id: str,
        facts_attempted: int,
        facts_supported: int,
        cognitive_state: Optional[Dict] = None,
    ) -> int:
        """Log research session outcome."""
        pass

    @abstractmethod
    def suggest_optimal_time(self, user_id: str) -> Dict:
        """Suggest optimal time for next session."""
        pass

    @abstractmethod
    def get_stats(self) -> Dict:
        """Get CARE system statistics."""
        pass
