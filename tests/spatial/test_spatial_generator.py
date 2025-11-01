"""
Tests for Spatial CAPTCHA Generator
====================================

Creator: Joerg Bollwahn
Date: 2025-10-30
"""

from llm_firewall.core.domain.spatial_captcha import DifficultyLevel
from llm_firewall.spatial.generator import SpatialCaptchaGenerator, verify_response


class TestSpatialCaptchaGenerator:
    """Test procedural challenge generation."""

    def test_generator_initialization(self):
        """Test generator can be created."""
        generator = SpatialCaptchaGenerator()
        assert generator is not None
        assert len(generator.colors) > 0

    def test_generate_easy_challenge(self):
        """Test EASY challenge generation."""
        generator = SpatialCaptchaGenerator()
        challenge = generator.generate(seed=42, difficulty=DifficultyLevel.EASY)

        assert challenge is not None
        assert challenge.difficulty == DifficultyLevel.EASY
        assert challenge.seed == 42
        assert len(challenge.objects) >= 1
        assert len(challenge.options) >= 2
        assert challenge.correct_answer in challenge.options
        assert challenge.occlusion_enabled is False

    def test_generate_medium_challenge(self):
        """Test MEDIUM challenge generation."""
        generator = SpatialCaptchaGenerator()
        challenge = generator.generate(seed=123, difficulty=DifficultyLevel.MEDIUM)

        assert challenge.difficulty == DifficultyLevel.MEDIUM
        assert challenge.seed == 123
        assert len(challenge.objects) >= 2
        assert challenge.occlusion_enabled is True

    def test_generate_hard_challenge(self):
        """Test HARD challenge generation."""
        generator = SpatialCaptchaGenerator()
        challenge = generator.generate(seed=999, difficulty=DifficultyLevel.HARD)

        assert challenge.difficulty == DifficultyLevel.HARD
        assert len(challenge.objects) >= 5
        assert challenge.occlusion_enabled is True

    def test_deterministic_generation(self):
        """Test same seed produces same challenge."""
        generator = SpatialCaptchaGenerator()

        challenge1 = generator.generate(seed=100, difficulty=DifficultyLevel.MEDIUM)
        challenge2 = generator.generate(seed=100, difficulty=DifficultyLevel.MEDIUM)

        assert challenge1.rotation_angle == challenge2.rotation_angle
        assert len(challenge1.objects) == len(challenge2.objects)
        assert challenge1.correct_answer == challenge2.correct_answer

    def test_verify_correct_answer(self):
        """Test verification accepts correct answer."""
        generator = SpatialCaptchaGenerator()
        challenge = generator.generate(seed=50, difficulty=DifficultyLevel.EASY)

        is_correct = verify_response(challenge, challenge.correct_answer)
        assert is_correct is True

    def test_verify_wrong_answer(self):
        """Test verification rejects wrong answer."""
        generator = SpatialCaptchaGenerator()
        challenge = generator.generate(seed=50, difficulty=DifficultyLevel.EASY)

        # Find a wrong answer
        wrong_answer = [
            opt for opt in challenge.options if opt != challenge.correct_answer
        ][0]

        is_correct = verify_response(challenge, wrong_answer)
        assert is_correct is False

    def test_challenge_hash_deterministic(self):
        """Test challenge hash is deterministic."""
        generator = SpatialCaptchaGenerator()
        challenge = generator.generate(seed=77, difficulty=DifficultyLevel.MEDIUM)

        hash1 = challenge.compute_hash()
        hash2 = challenge.compute_hash()

        assert hash1 == hash2
        assert len(hash1) == 32  # BLAKE2b digest_size=16 → 32 hex chars

    def test_different_seeds_different_challenges(self):
        """Test different seeds produce different challenges."""
        generator = SpatialCaptchaGenerator()

        challenge1 = generator.generate(seed=1, difficulty=DifficultyLevel.MEDIUM)
        challenge2 = generator.generate(seed=2, difficulty=DifficultyLevel.MEDIUM)

        assert challenge1.compute_hash() != challenge2.compute_hash()


class TestChallengeResponse:
    """Test challenge response validation."""

    def test_response_suspicious_too_fast(self):
        """Test response flagged if too fast."""
        from llm_firewall.core.domain.spatial_captcha import ChallengeResponse

        response = ChallengeResponse(
            challenge_id="test",
            user_id="user1",
            selected_answer="A",
            response_time_ms=100,  # Too fast
            is_correct=True,
        )

        assert response.is_suspicious() is True

    def test_response_suspicious_too_slow(self):
        """Test response flagged if too slow."""
        from llm_firewall.core.domain.spatial_captcha import ChallengeResponse

        response = ChallengeResponse(
            challenge_id="test",
            user_id="user1",
            selected_answer="A",
            response_time_ms=35000,  # Too slow
            is_correct=True,
        )

        assert response.is_suspicious() is True

    def test_response_not_suspicious_normal_time(self):
        """Test normal response time not flagged."""
        from llm_firewall.core.domain.spatial_captcha import ChallengeResponse

        response = ChallengeResponse(
            challenge_id="test",
            user_id="user1",
            selected_answer="A",
            response_time_ms=3000,  # Normal
            is_correct=True,
            device_info={"screen": "1920x1080"},
        )

        assert response.is_suspicious() is False


class TestUserSpatialProfile:
    """Test user profile and adaptive difficulty."""

    def test_profile_pass_rate(self):
        """Test pass rate calculation."""
        from llm_firewall.core.domain.spatial_captcha import UserSpatialProfile

        profile = UserSpatialProfile(
            user_id="user1", challenges_completed=10, challenges_passed=7
        )

        assert profile.pass_rate() == 0.7

    def test_recommend_difficulty_baseline(self):
        """Test difficulty recommendation for new users."""
        from llm_firewall.core.domain.spatial_captcha import UserSpatialProfile

        profile = UserSpatialProfile(user_id="user1", challenges_completed=0)

        assert profile.recommend_difficulty() == DifficultyLevel.MEDIUM

    def test_recommend_difficulty_promote_to_hard(self):
        """Test promotion to HARD after consistent success."""
        from llm_firewall.core.domain.spatial_captcha import UserSpatialProfile

        profile = UserSpatialProfile(
            user_id="user1", challenges_completed=5, medium_accuracy=0.85
        )

        assert profile.recommend_difficulty() == DifficultyLevel.HARD

    def test_recommend_difficulty_demote_to_easy(self):
        """Test demotion to EASY after failures."""
        from llm_firewall.core.domain.spatial_captcha import UserSpatialProfile

        profile = UserSpatialProfile(
            user_id="user1", challenges_completed=5, medium_accuracy=0.3
        )

        assert profile.recommend_difficulty() == DifficultyLevel.EASY
