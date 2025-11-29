"""
HAK_GAL v2.2-ALPHA: Unit Tests for SessionTrajectory and SemanticVectorCheck

Tests semantic drift detection with normal conversation flow vs. topic switch.

Creator: Joerg Bollwahn
License: MIT
"""

import pytest
import numpy as np

from hak_gal.layers.inbound.vector_guard import SessionTrajectory, SemanticVectorCheck
from hak_gal.core.exceptions import PolicyViolation
from hak_gal.core.session_manager import SessionManager


class TestSessionTrajectory:
    """Test SessionTrajectory rolling window buffer and drift detection."""

    def test_empty_trajectory_allows_first_embedding(self):
        """First embedding should always be allowed (no centroid yet)."""
        trajectory = SessionTrajectory(window_size=10)
        embedding = [0.1, 0.2, 0.3, 0.4, 0.5]

        is_safe, distance = trajectory.check_drift(embedding, drift_threshold=0.5)
        assert is_safe is True
        assert distance == 0.0
        assert trajectory.size() == 0  # Not added yet (centroid was None)

    def test_normal_conversation_flow(self):
        """Normal conversation should have low drift (similar embeddings)."""
        trajectory = SessionTrajectory(window_size=10)
        drift_threshold = 0.7

        # Simulate normal conversation: embeddings close to each other
        # Start with base vector
        base_vector = np.array([0.5, 0.5, 0.5, 0.5, 0.5])
        trajectory.add_embedding(base_vector.tolist())

        # Add similar vectors (small variations)
        for i in range(5):
            # Add small random noise to base vector
            noise = np.random.normal(0, 0.05, size=5)
            similar_vector = (base_vector + noise).tolist()
            is_safe, distance = trajectory.check_drift(similar_vector, drift_threshold)

            assert is_safe is True, (
                f"Normal conversation should pass (distance={distance:.3f})"
            )
            assert distance < drift_threshold, (
                f"Distance {distance:.3f} should be < threshold"
            )
            trajectory.add_embedding(similar_vector)

        assert trajectory.size() == 6  # base + 5 similar

    def test_topic_switch_detection(self):
        """Sudden topic switch should trigger drift detection."""
        trajectory = SessionTrajectory(window_size=10)
        drift_threshold = 0.7

        # Build trajectory with consistent topic (all vectors pointing in similar direction)
        base_vector = np.array([1.0, 0.0, 0.0, 0.0, 0.0])  # Unit vector in x-direction
        for i in range(5):
            # Small variations around base
            noise = np.random.normal(0, 0.1, size=5)
            similar_vector = base_vector + noise
            similar_vector = similar_vector / np.linalg.norm(
                similar_vector
            )  # Normalize
            trajectory.add_embedding(similar_vector.tolist())

        # Now add completely different topic (orthogonal vector)
        opposite_vector = np.array(
            [0.0, 1.0, 0.0, 0.0, 0.0]
        )  # Unit vector in y-direction

        # This should trigger drift detection
        with pytest.raises(PolicyViolation) as exc_info:
            trajectory.check_drift(opposite_vector.tolist(), drift_threshold)

        assert "semantic_drift" in exc_info.value.detected_threats
        assert exc_info.value.risk_score > drift_threshold

    def test_rolling_window_behavior(self):
        """Test that buffer respects window_size limit."""
        window_size = 5
        trajectory = SessionTrajectory(window_size=window_size)

        # Add more embeddings than window_size
        for i in range(10):
            embedding = [float(i), 0.0, 0.0, 0.0, 0.0]
            trajectory.add_embedding(embedding)

        # Buffer should only contain last window_size embeddings
        assert trajectory.size() == window_size

        # Centroid should be computed from last window_size embeddings
        centroid = trajectory.get_centroid()
        assert centroid is not None
        # Centroid should be around the mean of last 5 embeddings (5, 6, 7, 8, 9)
        assert abs(centroid[0] - 7.0) < 0.1  # Mean of [5,6,7,8,9] = 7.0

    def test_cosine_distance_calculation(self):
        """Test cosine distance calculation accuracy."""
        trajectory = SessionTrajectory(window_size=10)

        # Add base vector
        base = np.array([1.0, 0.0, 0.0])
        trajectory.add_embedding(base.tolist())

        # Identical vector should have distance 0.0
        identical = np.array([1.0, 0.0, 0.0])
        is_safe, distance = trajectory.check_drift(
            identical.tolist(), drift_threshold=1.0
        )
        assert is_safe is True
        assert abs(distance) < 0.001  # Should be ~0.0

        # Orthogonal vector should have distance ~1.0
        orthogonal = np.array([0.0, 1.0, 0.0])
        is_safe, distance = trajectory.check_drift(
            orthogonal.tolist(), drift_threshold=1.0
        )
        assert is_safe is True  # Threshold is 1.0, so it passes
        assert abs(distance - 1.0) < 0.001  # Should be ~1.0

    def test_centroid_update(self):
        """Test that centroid updates correctly as embeddings are added."""
        trajectory = SessionTrajectory(window_size=10)

        # Add first embedding
        vec1 = [1.0, 0.0, 0.0]
        trajectory.add_embedding(vec1)
        centroid1 = trajectory.get_centroid()
        assert centroid1 is not None
        assert np.allclose(centroid1, [1.0, 0.0, 0.0])

        # Add second embedding
        vec2 = [0.0, 1.0, 0.0]
        trajectory.add_embedding(vec2)
        centroid2 = trajectory.get_centroid()
        assert centroid2 is not None
        # Centroid should be mean of [1,0,0] and [0,1,0] = [0.5, 0.5, 0.0]
        assert np.allclose(centroid2, [0.5, 0.5, 0.0], atol=0.001)


class TestSemanticVectorCheckIntegration:
    """Integration tests for SemanticVectorCheck with SessionManager."""

    @pytest.fixture
    def session_manager(self):
        """Create SessionManager instance."""
        return SessionManager(hmac_secret=b"test_secret_32_bytes_long_for_hmac")

    @pytest.fixture
    def vector_check(self, session_manager):
        """Create SemanticVectorCheck instance (if sentence-transformers available)."""
        try:
            return SemanticVectorCheck(
                session_manager=session_manager,
                model_name="all-MiniLM-L6-v2",
                drift_threshold=0.7,
                window_size=10,
            )
        except Exception as e:
            pytest.skip(f"sentence-transformers not available: {e}")

    @pytest.mark.asyncio
    async def test_normal_conversation_flow(self, vector_check, session_manager):
        """Test normal conversation flow (low drift)."""
        session_id = await session_manager.create_session("test_user")

        # Normal conversation: similar topics
        texts = [
            "What is machine learning?",
            "How does neural networks work?",
            "Tell me about deep learning.",
            "What are the applications of AI?",
            "Explain supervised learning.",
        ]

        distances = []
        for text in texts:
            is_safe, distance, error = await vector_check.check(text, session_id)
            assert is_safe is True, f"Normal conversation should pass: {error}"
            distances.append(distance)

        # Distances should be relatively low (similar topics)
        avg_distance = sum(distances) / len(distances)
        assert avg_distance < 0.5, (
            f"Average distance {avg_distance:.3f} should be low for normal conversation"
        )

    @pytest.mark.asyncio
    async def test_topic_switch_detection(self, vector_check, session_manager):
        """Test that sudden topic switch triggers drift detection."""
        session_id = await session_manager.create_session("test_user")

        # Build normal conversation
        normal_texts = [
            "What is machine learning?",
            "How does neural networks work?",
            "Tell me about deep learning.",
        ]

        for text in normal_texts:
            is_safe, _, _ = await vector_check.check(text, session_id)
            assert is_safe is True

        # Sudden topic switch: completely different domain
        topic_switch_text = "How do I cook pasta? What ingredients do I need?"

        # This should trigger drift detection
        with pytest.raises(PolicyViolation) as exc_info:
            await vector_check.check(topic_switch_text, session_id)

        assert "semantic_drift" in exc_info.value.detected_threats
        assert exc_info.value.risk_score > vector_check.drift_threshold

    @pytest.mark.asyncio
    async def test_check_drift_low_level_api(self, vector_check, session_manager):
        """Test low-level check_drift API with pre-computed embeddings."""
        session_id = await session_manager.create_session("test_user")

        # Build trajectory with normal conversation
        normal_embedding = [0.5, 0.5, 0.5, 0.5, 0.5]
        for _ in range(3):
            is_safe, distance = await vector_check.check_drift(
                normal_embedding, session_id
            )
            assert is_safe is True

        # Now check with orthogonal embedding (should trigger drift)
        orthogonal_embedding = [0.0, 1.0, 0.0, 0.0, 0.0]

        with pytest.raises(PolicyViolation):
            await vector_check.check_drift(orthogonal_embedding, session_id)
