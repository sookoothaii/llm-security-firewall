"""
Spatial CAPTCHA Domain Entities
================================

Pure business logic for spatial reasoning challenges.
No dependencies on infrastructure (PIL, numpy, etc.).

Based on: "Spatial CAPTCHA: Generatively Benchmarking Spatial Reasoning
          for Human-Machine Differentiation" (2025)

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Tuple


class DifficultyLevel(Enum):
    """Challenge difficulty levels."""

    EASY = "easy"  # 2D rotation, 1-2 objects, no occlusion
    MEDIUM = "medium"  # Mental rotation, 2-3 objects, partial occlusion
    HARD = "hard"  # Complex rotation, 5+ objects, full occlusion


class ObjectType(Enum):
    """3D object types for challenges."""

    CUBE = "cube"
    SPHERE = "sphere"
    CYLINDER = "cylinder"
    PYRAMID = "pyramid"
    TORUS = "torus"


@dataclass
class SpatialObject:
    """3D object in challenge scene."""

    object_type: ObjectType
    position: Tuple[float, float, float]  # (x, y, z)
    rotation: Tuple[float, float, float]  # (roll, pitch, yaw) in degrees
    color: str  # RGB hex (e.g., "#FF0000")
    size: float = 1.0  # Scale factor

    def to_dict(self) -> dict:
        """Serialize to dict."""
        return {
            "type": self.object_type.value,
            "position": self.position,
            "rotation": self.rotation,
            "color": self.color,
            "size": self.size,
        }


@dataclass
class Challenge:
    """
    Spatial reasoning challenge.

    Business Rules:
    - Each challenge has deterministic ground truth
    - Seed makes generation reproducible
    - Parameters define difficulty
    """

    challenge_id: str
    seed: int
    difficulty: DifficultyLevel
    question_type: str  # "which_behind", "which_above", "rotation_match", etc.

    # Scene
    objects: List[SpatialObject]
    rotation_angle: float  # Degrees
    occlusion_enabled: bool

    # Question
    question_text: str
    options: List[str]  # Multiple choice answers
    correct_answer: str

    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    presented_at: Optional[datetime] = None

    def __post_init__(self):
        """Validate challenge parameters."""
        if not self.objects:
            raise ValueError("Challenge must have at least one object")
        if not self.options:
            raise ValueError("Challenge must have options")
        if self.correct_answer not in self.options:
            raise ValueError(f"Correct answer '{self.correct_answer}' not in options")
        if not (0 <= self.rotation_angle <= 360):
            raise ValueError(
                f"Rotation angle must be in [0, 360], got {self.rotation_angle}"
            )

    def to_dict(self) -> dict:
        """Serialize to dict for storage."""
        return {
            "challenge_id": self.challenge_id,
            "seed": self.seed,
            "difficulty": self.difficulty.value,
            "question_type": self.question_type,
            "objects": [obj.to_dict() for obj in self.objects],
            "rotation_angle": self.rotation_angle,
            "occlusion_enabled": self.occlusion_enabled,
            "question_text": self.question_text,
            "options": self.options,
            "correct_answer": self.correct_answer,
            "created_at": self.created_at.isoformat(),
            "presented_at": self.presented_at.isoformat()
            if self.presented_at
            else None,
        }

    def compute_hash(self) -> str:
        """
        Compute deterministic hash for challenge.

        Used for:
        - Deduplication
        - Integrity verification
        - Audit trail
        """
        # Hash seed + parameters (not timing)
        data = {
            "seed": self.seed,
            "difficulty": self.difficulty.value,
            "question_type": self.question_type,
            "rotation_angle": self.rotation_angle,
            "occlusion_enabled": self.occlusion_enabled,
        }
        content = json.dumps(data, sort_keys=True)
        return hashlib.blake2b(content.encode(), digest_size=16).hexdigest()


@dataclass
class ChallengeResponse:
    """User response to challenge."""

    challenge_id: str
    user_id: str
    selected_answer: str
    response_time_ms: int
    is_correct: bool

    # Metadata
    device_info: Optional[dict] = None  # Screen size, input method
    session_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        """Validate response."""
        if self.response_time_ms < 0:
            raise ValueError(f"Response time must be >= 0, got {self.response_time_ms}")

    def is_suspicious(self) -> bool:
        """
        Business rule: Detect suspicious response patterns.

        Bots typically:
        - Respond too fast (<500ms)
        - Respond too slow (>30s timeout)
        - Have no device info
        """
        if self.response_time_ms < 500:
            return True  # Too fast for human
        if self.response_time_ms > 30000:
            return True  # Timeout suspicious
        if self.device_info is None:
            return True  # Missing context
        return False


@dataclass
class UserSpatialProfile:
    """
    User's spatial reasoning profile.

    Tracks performance over time for adaptive difficulty.
    """

    user_id: str
    challenges_completed: int = 0
    challenges_passed: int = 0
    average_response_time_ms: float = 0.0

    # Difficulty performance
    easy_accuracy: float = 0.0
    medium_accuracy: float = 0.0
    hard_accuracy: float = 0.0

    last_updated: datetime = field(default_factory=datetime.now)

    def pass_rate(self) -> float:
        """Calculate overall pass rate."""
        if self.challenges_completed == 0:
            return 0.0
        return self.challenges_passed / self.challenges_completed

    def recommend_difficulty(self) -> DifficultyLevel:
        """
        Business rule: Recommend next difficulty level.

        - Start with MEDIUM (balanced baseline)
        - If passing MEDIUM consistently (>80%), try HARD
        - If failing MEDIUM consistently (<50%), drop to EASY
        """
        if self.challenges_completed < 3:
            return DifficultyLevel.MEDIUM  # Baseline

        if self.medium_accuracy > 0.8 and self.challenges_completed >= 5:
            return DifficultyLevel.HARD

        if self.medium_accuracy < 0.5:
            return DifficultyLevel.EASY

        return DifficultyLevel.MEDIUM


# Business Constants
DEFAULT_TIME_BUDGET_MS = 8000  # 8 seconds (from paper: human avg 2-8s)
MIN_RESPONSE_TIME_MS = 500  # Faster = likely bot
MAX_RESPONSE_TIME_MS = 30000  # Slower = timeout/suspicious

# Target performance (from paper)
TARGET_HUMAN_PASS_RATE = 0.90  # 90%+ for humans
TARGET_MLLM_PASS_RATE = 0.31  # <31% for SoTA MLLMs

