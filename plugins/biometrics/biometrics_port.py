"""
Cultural Biometrics Port (Hexagonal Architecture)
Creator: Joerg Bollwahn

27-Dimensional behavioral authentication for Human/LLM interfaces.
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class BiometricProfile:
    """
    27-Dimensional Cultural Biometrics Profile.
    
    WORLD-FIRST: Behavioral authentication for LLM interfaces.
    """
    user_id: str
    
    # Surface Features (6D)
    typo_rate: float
    message_length_mean: float
    message_length_std: float
    punctuation_density: float
    capitalization_rate: float
    emoji_rate: float
    
    # Temporal Features (3D)
    inter_message_time_mean: float
    inter_message_time_std: float
    session_duration_mean: float
    
    # VAD (Valence-Arousal-Dominance) Features (6D)
    valence_mean: float
    valence_std: float
    arousal_mean: float
    arousal_std: float
    dominance_mean: float
    dominance_std: float
    
    # Vocabulary Features (6D)
    vocabulary_size: int
    unique_word_ratio: float
    avg_word_length: float
    sentence_complexity: float
    technical_term_rate: float
    slang_rate: float
    
    # Interaction Pattern Features (6D)
    question_rate: float
    directive_rate: float
    approval_rate: float
    correction_rate: float
    code_snippet_rate: float
    link_share_rate: float
    
    # Metadata
    baseline_n: int  # Number of messages in baseline
    last_updated: datetime
    confidence_score: float


@dataclass
class AuthenticationResult:
    """Result of biometric authentication."""
    authenticated: bool
    confidence: float
    anomaly_score: float
    anomaly_features: list  # Which features triggered anomaly
    threshold: float
    recommendation: str  # PASS, CHALLENGE, BLOCK


class BiometricsPort(ABC):
    """Abstract port for cultural biometrics functionality."""
    
    @abstractmethod
    def authenticate(
        self,
        user_id: str,
        message: str,
        context: Optional[Dict] = None
    ) -> AuthenticationResult:
        """Authenticate user based on behavioral patterns."""
        pass
    
    @abstractmethod
    def update_baseline(
        self,
        user_id: str,
        force: bool = False
    ) -> Dict:
        """Update behavioral baseline."""
        pass
    
    @abstractmethod
    def get_profile(self, user_id: str) -> Optional[BiometricProfile]:
        """Get biometric profile for user."""
        pass
    
    @abstractmethod
    def log_message(
        self,
        user_id: str,
        message: str,
        metadata: Optional[Dict] = None
    ) -> int:
        """Log message for behavioral analysis."""
        pass

