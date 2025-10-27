"""
Personality Port (Hexagonal Architecture)
Creator: Joerg Bollwahn

This is the PORT interface for personality functionality.
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional, List
from dataclasses import dataclass


@dataclass
class PersonalityProfile:
    """Personality profile with 20 dimensions."""
    user_id: str
    
    # Big Five
    openness: float
    conscientiousness: float
    extraversion: float
    agreeableness: float
    neuroticism: float
    
    # HAK/GAL Specific
    truth_over_comfort: float
    iterative_rigor: float
    bullshit_tolerance: float
    formality_preference: float
    risk_tolerance: float
    emoji_tolerance: float
    detail_level: float
    directness: float
    question_style: float
    systems_thinking: float
    pattern_recognition: float
    abstract_vs_concrete: float
    precision_priority: float
    honesty_absoluteness: float
    evidence_requirement: float
    
    # Metadata
    confidence_score: float
    interaction_count: int
    context_tags: List[str]


class PersonalityPort(ABC):
    """Abstract port for personality functionality."""
    
    @abstractmethod
    def get_personality_profile(self, user_id: str) -> Optional[PersonalityProfile]:
        """Get personality profile for user."""
        pass
    
    @abstractmethod
    def log_interaction(
        self,
        user_id: str,
        interaction_type: str,
        content: str,
        outcome: str
    ) -> int:
        """Log interaction for profile learning."""
        pass
    
    @abstractmethod
    def adapt_response(
        self,
        user_id: str,
        draft_response: str,
        context: Optional[str] = None
    ) -> str:
        """Adapt response based on personality profile."""
        pass

