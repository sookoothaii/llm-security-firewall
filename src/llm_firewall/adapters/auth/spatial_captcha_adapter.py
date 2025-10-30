"""
Spatial CAPTCHA Adapter
========================

Hexagonal Architecture Adapter for Spatial CAPTCHA authentication.

Integrates:
- SpatialCaptchaGenerator (domain logic)
- PNG rendering (infrastructure)
- PostgreSQL storage (persistence)
- AuthenticationPort (port interface)

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

import time
from typing import Any, Dict, Optional

from llm_firewall.core.domain.spatial_captcha import (
    DEFAULT_TIME_BUDGET_MS,
    Challenge,
    ChallengeResponse,
    DifficultyLevel,
    UserSpatialProfile,
)
from llm_firewall.core.ports.auth_port import AuthenticationPort, AuthenticationResult
from llm_firewall.spatial.generator import SpatialCaptchaGenerator, verify_response
from llm_firewall.spatial.renderer import SpatialCaptchaRenderer


class SpatialCaptchaAdapter(AuthenticationPort):
    """
    Adapter for Spatial CAPTCHA authentication.

    Workflow:
    1. Generate challenge (procedural, seed-based)
    2. Render to PNG (via OCR pipeline)
    3. Present to user (external UI)
    4. Verify response (deterministic)
    5. Update user profile (adaptive difficulty)
    6. Return confidence score
    """

    def __init__(
        self,
        renderer: Optional[SpatialCaptchaRenderer] = None,
        db_connection=None,  # PostgreSQL connection
        default_difficulty: DifficultyLevel = DifficultyLevel.MEDIUM,
        time_budget_ms: int = DEFAULT_TIME_BUDGET_MS,
    ):
        """
        Initialize adapter.

        Args:
            renderer: PNG renderer (optional, graceful degradation)
            db_connection: PostgreSQL connection for logging
            default_difficulty: Starting difficulty level
            time_budget_ms: Max response time allowed
        """
        self.generator = SpatialCaptchaGenerator()
        self.renderer = renderer
        self.db = db_connection
        self.default_difficulty = default_difficulty
        self.time_budget_ms = time_budget_ms

        # Cache for active challenges (in-memory)
        self._active_challenges: Dict[str, Challenge] = {}

    def authenticate(
        self, user_id: str, context: Dict[str, Any]
    ) -> AuthenticationResult:
        """
        Authenticate user via spatial challenge.

        Args:
            user_id: User identifier
            context: Must contain either:
                     - 'challenge_response': User's answer to existing challenge
                     - 'request_challenge': True to generate new challenge

        Returns:
            AuthenticationResult with confidence score
        """
        # Case 1: User responding to challenge
        if "challenge_response" in context:
            return self._verify_challenge_response(user_id, context)

        # Case 2: Generate new challenge
        if context.get("request_challenge", False):
            return self._generate_new_challenge(user_id, context)

        # Case 3: No challenge interaction (passive mode not supported)
        return AuthenticationResult(
            confidence=0.5,  # Neutral (no evidence)
            method="spatial_captcha",
            metadata={"error": "No challenge interaction"},
            is_human=False,
        )

    def _generate_new_challenge(
        self, user_id: str, context: Dict[str, Any]
    ) -> AuthenticationResult:
        """Generate and present new challenge."""
        # Get user profile for adaptive difficulty
        profile = self._get_user_profile(user_id)
        difficulty = (
            profile.recommend_difficulty() if profile else self.default_difficulty
        )

        # Generate challenge
        seed = int(time.time() * 1000000) % (2**31)  # Pseudo-random seed
        challenge = self.generator.generate(seed, difficulty)

        # Store challenge
        self._active_challenges[challenge.challenge_id] = challenge

        # Render PNG if renderer available
        png_path = None
        if self.renderer and self.renderer.is_available():
            png_path = self.renderer.render(challenge)

        # Log to DB
        if self.db:
            self._log_challenge_presented(challenge, user_id)

        return AuthenticationResult(
            confidence=0.5,  # Pending response
            method="spatial_captcha_pending",
            metadata={
                "challenge_id": challenge.challenge_id,
                "question": challenge.question_text,
                "options": challenge.options,
                "png_path": png_path,
                "time_budget_ms": self.time_budget_ms,
                "difficulty": difficulty.value,
            },
            is_human=False,  # Not yet verified
        )

    def _verify_challenge_response(
        self, user_id: str, context: Dict[str, Any]
    ) -> AuthenticationResult:
        """Verify user's challenge response."""
        challenge_id: Optional[str] = context.get("challenge_id")
        user_answer: Optional[str] = context.get("user_answer")
        response_time_ms: int = context.get("response_time_ms", 0)

        # Validate inputs
        if not challenge_id or not user_answer:
            return AuthenticationResult(
                confidence=0.0,
                method="spatial_captcha",
                metadata={"error": "Missing challenge_id or user_answer"},
                is_human=False,
            )

        # Get challenge
        challenge = self._active_challenges.get(challenge_id)
        if not challenge:
            return AuthenticationResult(
                confidence=0.0,
                method="spatial_captcha",
                metadata={"error": "Challenge not found or expired"},
                is_human=False,
            )

        # Verify answer
        is_correct = verify_response(challenge, user_answer)

        # Create response record
        response = ChallengeResponse(
            challenge_id=challenge_id,
            user_id=user_id,
            selected_answer=user_answer,
            response_time_ms=response_time_ms,
            is_correct=is_correct,
            device_info=context.get("device_info"),
            session_id=context.get("session_id"),
        )

        # Check for suspicious patterns
        is_suspicious = response.is_suspicious()

        # Compute confidence
        confidence = self._compute_confidence(response, challenge, is_suspicious)

        # Update user profile
        self._update_user_profile(user_id, challenge, response)

        # Log to DB
        if self.db:
            self._log_challenge_response(response)

        # Cleanup
        del self._active_challenges[challenge_id]

        return AuthenticationResult(
            confidence=confidence,
            method="spatial_captcha",
            metadata={
                "is_correct": is_correct,
                "response_time_ms": response_time_ms,
                "is_suspicious": is_suspicious,
                "difficulty": challenge.difficulty.value,
            },
            is_human=confidence >= 0.7,
        )

    def _compute_confidence(
        self, response: ChallengeResponse, challenge: Challenge, is_suspicious: bool
    ) -> float:
        """
        Compute human confidence score.

        Rules:
        - Correct answer: Base 0.9
        - Incorrect answer: Base 0.1
        - Suspicious timing: -0.5
        - Difficulty bonus: +0.1 for HARD
        """
        if is_suspicious:
            return 0.1  # Likely bot

        base = 0.9 if response.is_correct else 0.1

        # Difficulty bonus
        if response.is_correct and challenge.difficulty == DifficultyLevel.HARD:
            base = min(1.0, base + 0.1)

        return base

    def _get_user_profile(self, user_id: str) -> Optional[UserSpatialProfile]:
        """Fetch user profile from DB (simplified - real impl would query PostgreSQL)."""
        # TODO: Query from DB
        return None

    def _update_user_profile(
        self, user_id: str, challenge: Challenge, response: ChallengeResponse
    ):
        """Update user profile with new response."""
        # TODO: Update in DB
        pass

    def _log_challenge_presented(self, challenge: Challenge, user_id: str):
        """Log challenge presentation to DB."""
        # TODO: INSERT into spatial_challenges
        pass

    def _log_challenge_response(self, response: ChallengeResponse):
        """Log challenge response to DB."""
        # TODO: UPDATE spatial_challenges
        pass

    # AuthenticationPort interface methods

    def get_name(self) -> str:
        """Return adapter name."""
        return "spatial_captcha"

    def get_latency_budget_ms(self) -> int:
        """Return latency budget (includes human response time)."""
        return self.time_budget_ms + 500  # Challenge time + processing overhead

    def supports_challenge(self) -> bool:
        """This adapter requires user interaction."""
        return True

    def is_available(self) -> bool:
        """Check if adapter dependencies are met."""
        # Spatial CAPTCHA requires renderer (PIL/matplotlib)
        if self.renderer is None:
            return False
        return self.renderer.is_available()
