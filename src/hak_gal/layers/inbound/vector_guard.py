"""
HAK_GAL v2.2-ALPHA: Semantic Vector Check (SessionTrajectory)

Detects semantic drift by computing cosine distance between current prompt
and SessionCentroid (running average of last N turns).

Creator: Joerg Bollwahn
License: MIT
"""

import asyncio
import logging
from typing import Optional, List, Tuple
from collections import deque

import numpy as np

from hak_gal.core.exceptions import PolicyViolation, SystemError
from hak_gal.core.session_manager import SessionManager

logger = logging.getLogger(__name__)

# Try to import sentence-transformers (required for embeddings)
try:
    from sentence_transformers import SentenceTransformer

    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False
    SentenceTransformer = None  # type: ignore[misc,assignment]
    logger.warning(
        "sentence-transformers not available. SemanticVectorCheck will be disabled."
    )


class SessionTrajectory:
    """
    Rolling Window Buffer for session embeddings with drift detection.

    Manages a fixed-size buffer of embedding vectors and computes the
    session centroid using Exponential Moving Average (EMA) to prevent gradual drift attacks.

    SECURITY: EMA makes the system more resistant to slow poisoning attacks.
    """

    def __init__(
        self,
        window_size: int = 50,
        alpha: float = 0.3,
        cusum_baseline: float = 0.1,
        cusum_tolerance: float = 0.05,
        cusum_threshold: float = 0.3,
    ):
        """
        Initialize SessionTrajectory with rolling window buffer and EMA.

        CRITICAL FIX (v2.3.3): CUSUM Changepoint Detection replaces variance-based detection.
        CUSUM detects Rate-of-Change of centroid drift, not static variance patterns.

        Args:
            window_size: Maximum number of embeddings to keep in buffer
            alpha: EMA smoothing factor (0.0 = no update, 1.0 = only new vector).
                   Default: 0.3 (gives newer prompts less weight, makes system slower to drift)
            cusum_baseline: Expected normal drift distance (default: 0.1 for normal conversation)
            cusum_tolerance: CUSUM tolerance parameter k (slack, default: 0.05)
            cusum_threshold: CUSUM decision threshold h (default: 0.3)
        """
        self.window_size = window_size
        self.alpha = alpha  # EMA smoothing factor
        self._buffer: deque = deque(maxlen=window_size)
        self._centroid: Optional[np.ndarray] = None

        # CRITICAL FIX (v2.3.3): CUSUM Changepoint Detection
        # Detects Rate-of-Change of centroid drift (not static variance)
        # Formula: cusum_score = max(0, cusum_score + drift_distance - baseline - k)
        # Block if: cusum_score > h
        self.cusum_baseline = cusum_baseline  # Expected normal drift
        self.cusum_tolerance = cusum_tolerance  # k: tolerance/slack
        self.cusum_threshold = cusum_threshold  # h: decision threshold
        self.cusum_score = 0.0  # Current CUSUM cumulative score

        # CRITICAL FIX (Solo-Dev): False-Positive Tracking
        # Track CUSUM false positives to detect legitimate topic switches
        self.cusum_false_positives = 0  # Count of false positives
        self.cusum_total_checks = 0  # Total drift checks
        self.cusum_last_user_message = ""  # For heuristic detection

    def add_embedding(self, embedding: List[float]) -> None:
        """
        Add embedding vector to rolling window buffer.

        Args:
            embedding: Embedding vector (list of floats)
        """
        vec = np.array(embedding, dtype=np.float32)
        self._buffer.append(vec)
        self._update_centroid()

    def _update_centroid(self) -> None:
        """
        Update centroid using Exponential Moving Average (EMA).

        SECURITY: EMA prevents gradual drift attacks by giving newer vectors less weight.
        Formula: NewCentroid = Alpha * NewVector + (1 - Alpha) * OldCentroid

        If no centroid exists yet, use mean of all vectors in buffer.
        """
        if len(self._buffer) == 0:
            self._centroid = None
            return

        # Get the newest vector (last in buffer)
        new_vector = self._buffer[-1]

        if self._centroid is None:
            # First vector: use it as centroid
            self._centroid = new_vector.copy()
        else:
            # EMA Update: NewCentroid = Alpha * NewVector + (1 - Alpha) * OldCentroid
            # Alpha = 0.3 means: 30% weight to new vector, 70% to old centroid
            # This makes the system slower to drift (more resistant to gradual poisoning)
            self._centroid = (
                self.alpha * new_vector + (1.0 - self.alpha) * self._centroid
            )

    def get_centroid(self) -> Optional[np.ndarray]:
        """
        Get current session centroid (running average).

        Returns:
            Centroid vector as numpy array, or None if buffer is empty
        """
        return self._centroid.copy() if self._centroid is not None else None

    def check_drift(
        self, current_embedding: List[float], drift_threshold: float
    ) -> Tuple[bool, float]:
        """
        Check if current embedding drifts too far from session centroid.

        CRITICAL FIX (v2.3.3): CUSUM Changepoint Detection replaces variance-based detection.
        CUSUM detects Rate-of-Change of centroid drift, making it resistant to:
        - 2-value oscillation (0.7 → 0.1)
        - 3-value oscillation (0.7 → 0.1 → 0.5)
        - Any alternating attack pattern

        CUSUM Formula:
            cusum_score = max(0, cusum_score + drift_distance - baseline - k)
            Block if: cusum_score > h

        Args:
            current_embedding: Current embedding vector to check
            drift_threshold: Cosine distance threshold (0.0 = identical, 1.0 = orthogonal)

        Returns:
            Tuple of (is_safe, cosine_distance)
            - is_safe: True if cosine_distance <= drift_threshold AND cusum_score <= threshold
            - cosine_distance: Cosine distance to centroid (0.0 = identical, 1.0 = orthogonal)

        Raises:
            PolicyViolation: If drift detected (cosine_distance > drift_threshold) OR CUSUM threshold exceeded
        """
        if self._centroid is None:
            # No trajectory yet - allow first embedding
            return True, 0.0

        current_vec = np.array(current_embedding, dtype=np.float32)
        cosine_distance = self._cosine_distance(current_vec, self._centroid)

        # CRITICAL FIX (v2.3.3): CUSUM Changepoint Detection
        # Detects Rate-of-Change of centroid drift (not static variance)
        # This is resistant to oscillation attacks (2-value, 3-value, etc.)
        # Formula: cusum_score = max(0, cusum_score + drift_distance - baseline - k)
        self.cusum_total_checks += 1
        self.cusum_score = max(
            0.0,
            self.cusum_score
            + cosine_distance
            - self.cusum_baseline
            - self.cusum_tolerance,
        )

        # Check CUSUM threshold (h)
        if self.cusum_score > self.cusum_threshold:
            # CRITICAL FIX (Solo-Dev): Check if this is a false positive
            # Heuristic: If user explicitly requested topic switch, it's likely legitimate
            is_legitimate = self._is_legitimate_topic_switch()

            if is_legitimate:
                # False positive detected - track and auto-tune
                self.cusum_false_positives += 1
                fp_rate = self.cusum_false_positives / max(self.cusum_total_checks, 1)

                logger.warning(
                    f"CUSUM False Positive detected: fp_rate={fp_rate:.2%}, "
                    f"cusum_score={self.cusum_score:.3f}, threshold={self.cusum_threshold}"
                )

                # Auto-tune threshold if FP rate > 1%
                if fp_rate > 0.01:
                    old_threshold = self.cusum_threshold
                    self.cusum_threshold += 0.05  # Increase threshold by 0.05
                    logger.warning(
                        f"CUSUM Auto-tuning: threshold {old_threshold:.3f} -> {self.cusum_threshold:.3f} "
                        f"(FP rate {fp_rate:.2%} > 1%)"
                    )

                # Allow legitimate topic switch (reset CUSUM score)
                self.cusum_score = 0.0
                # Don't raise PolicyViolation - allow legitimate topic switch
                logger.info("CUSUM: Allowing legitimate topic switch (FP detected)")
            else:
                # CHANGEPOINT DETECTED: Rapid drift accumulation indicates attack
                raise PolicyViolation(
                    f"Changepoint detected (CUSUM): cusum_score={self.cusum_score:.3f} > threshold={self.cusum_threshold} "
                    f"(cosine_distance={cosine_distance:.3f}, baseline={self.cusum_baseline})",
                    policy_name="SessionTrajectory",
                    risk_score=max(cosine_distance, self.cusum_score),
                    detected_threats=["semantic_drift", "changepoint_attack"],
                )

        # Standard drift check (absolute threshold)
        if cosine_distance > drift_threshold:
            raise PolicyViolation(
                f"Semantic drift detected: cosine_distance={cosine_distance:.3f} > threshold={drift_threshold}",
                policy_name="SessionTrajectory",
                risk_score=cosine_distance,
                detected_threats=["semantic_drift"],
            )

        return True, float(cosine_distance)

    @staticmethod
    def _cosine_distance(vec1: np.ndarray, vec2: np.ndarray) -> float:
        """
        Compute cosine distance between two vectors.

        Args:
            vec1: First vector (numpy array)
            vec2: Second vector (numpy array)

        Returns:
            Cosine distance (0.0 = identical, 1.0 = orthogonal)
        """
        # Cosine similarity = dot(v1, v2) / (||v1|| * ||v2||)
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)

        if norm1 == 0 or norm2 == 0:
            return 1.0  # Orthogonal if zero vector

        cosine_similarity = dot_product / (norm1 * norm2)
        # Cosine distance = 1 - cosine_similarity
        cosine_distance = 1.0 - cosine_similarity

        return float(cosine_distance)

    def size(self) -> int:
        """Get current buffer size."""
        return len(self._buffer)

    def clear(self) -> None:
        """Clear buffer and reset centroid."""
        self._buffer.clear()
        self._centroid = None
        # CRITICAL FIX (v2.3.3): Reset CUSUM score
        self.cusum_score = 0.0
        # CRITICAL FIX (Solo-Dev): Reset FP tracking (optional - keep for session stats)
        # self.cusum_false_positives = 0
        # self.cusum_total_checks = 0

    def _is_legitimate_topic_switch(self) -> bool:
        """
        Heuristic to detect legitimate topic switches.

        CRITICAL FIX (Solo-Dev): Simple heuristic to reduce false positives.
        In production, this should be more sophisticated (e.g., user intent classification).

        Returns:
            True if likely legitimate topic switch, False otherwise
        """
        # Simple heuristic: Check if last user message contains topic switch keywords
        message_lower = self.cusum_last_user_message.lower()
        switch_keywords = [
            "switch",
            "change topic",
            "new topic",
            "different",
            "let's talk about",
        ]
        return any(keyword in message_lower for keyword in switch_keywords)

    def set_last_user_message(self, message: str) -> None:
        """
        Set last user message for false-positive detection.

        CRITICAL FIX (Solo-Dev): Call this before check_drift() to enable FP detection.

        Args:
            message: Last user message text
        """
        self.cusum_last_user_message = message


class SemanticVectorCheck:
    """
    Semantic drift detection using SessionTrajectory.

    Architecture:
    - Computes embedding for current prompt
    - Retrieves SessionCentroid (running average of last N turns)
    - Computes cosine_distance(current, centroid)
    - Blocks if distance > threshold (semantic drift detected)
    """

    def __init__(
        self,
        session_manager: SessionManager,
        model_name: str = "all-MiniLM-L6-v2",
        drift_threshold: float = 0.7,
        timeout_seconds: float = 5.0,
        window_size: int = 50,
        runtime_config=None,
    ):
        """
        Initialize Semantic Vector Check.

        Args:
            session_manager: SessionManager instance for trajectory tracking
            model_name: SentenceTransformer model name
            drift_threshold: Cosine distance threshold (0.0 = identical, 1.0 = orthogonal)
            timeout_seconds: Embedding computation timeout (fail-closed)
            window_size: Rolling window size for SessionTrajectory buffer
            runtime_config: Optional RuntimeConfig instance (for dynamic threshold)

        Raises:
            SystemError: If sentence-transformers not available (fail-closed)
        """
        if not HAS_SENTENCE_TRANSFORMERS:
            raise SystemError(
                "sentence-transformers not available. Install: pip install sentence-transformers",
                component="SemanticVectorCheck",
            )

        self.session_manager = session_manager
        self.drift_threshold = drift_threshold  # Default/init-time threshold
        self.runtime_config = runtime_config  # For dynamic threshold updates
        self.timeout_seconds = timeout_seconds

        # Load embedding model (lazy loading on first use)
        self._model: Optional[SentenceTransformer] = None
        self._model_name = model_name

        # Per-session trajectory buffers
        self._trajectories: dict[str, SessionTrajectory] = {}
        self._window_size = window_size

    async def check(
        self, text: str, session_id: str
    ) -> Tuple[bool, float, Optional[str]]:
        """
        Check semantic drift against session trajectory.

        Args:
            text: Current prompt text
            session_id: Session identifier

        Returns:
            Tuple of (is_safe, cosine_distance, error_message)
            If is_safe=False, raises PolicyViolation (fail-closed)

        Raises:
            PolicyViolation: If semantic drift detected
            SystemError: If embedding computation fails or times out (fail-closed)
        """
        # Get session centroid
        centroid = await self.session_manager.get_session_centroid(session_id)

        if centroid is None:
            # No trajectory yet - allow first turn
            logger.debug(f"No trajectory for session {session_id}, allowing first turn")
            # Compute embedding for this turn
            vector = await self._compute_embedding(text)
            await self.session_manager.add_trajectory_vector(session_id, vector)
            return True, 0.0, None

        # Compute embedding for current prompt
        current_vector = await self._compute_embedding(text)

        # Use SessionTrajectory for drift detection
        # Get threshold from runtime config if available, else use init-time threshold
        threshold = (
            self.runtime_config.DRIFT_THRESHOLD
            if self.runtime_config is not None
            else self.drift_threshold
        )

        trajectory = self._get_trajectory(session_id)
        # CRITICAL FIX (Solo-Dev): Set last user message for FP detection
        trajectory.set_last_user_message(text)
        is_safe, cosine_distance = trajectory.check_drift(current_vector, threshold)

        logger.debug(
            f"Semantic drift check: distance={cosine_distance:.3f}, threshold={self.drift_threshold}"
        )

        # Add to trajectory buffer (if safe)
        trajectory.add_embedding(current_vector)

        # Also update SessionManager for backward compatibility
        await self.session_manager.add_trajectory_vector(session_id, current_vector)

        return is_safe, cosine_distance, None

    def _get_trajectory(self, session_id: str) -> SessionTrajectory:
        """
        Get or create SessionTrajectory for session.

        Args:
            session_id: Session identifier

        Returns:
            SessionTrajectory instance
        """
        if session_id not in self._trajectories:
            self._trajectories[session_id] = SessionTrajectory(
                window_size=self._window_size
            )
        return self._trajectories[session_id]

    async def check_drift(
        self, current_embedding: List[float], session_id: str
    ) -> Tuple[bool, float]:
        """
        Check drift for a pre-computed embedding (low-level API).

        This method allows checking drift without computing embeddings,
        useful when embeddings are already available.

        Args:
            current_embedding: Pre-computed embedding vector
            session_id: Session identifier

        Returns:
            Tuple of (is_safe, cosine_distance)
            If is_safe=False, raises PolicyViolation (fail-closed)

        Raises:
            PolicyViolation: If semantic drift detected
        """
        trajectory = self._get_trajectory(session_id)
        is_safe, cosine_distance = trajectory.check_drift(
            current_embedding, self.drift_threshold
        )

        # Add to trajectory buffer (if safe)
        trajectory.add_embedding(current_embedding)

        return is_safe, cosine_distance

    async def _compute_embedding(self, text: str) -> List[float]:
        """
        Compute embedding vector for text.

        Args:
            text: Input text

        Returns:
            Embedding vector (list of floats)

        Raises:
            SystemError: If embedding computation fails or times out (fail-closed)
        """
        # Lazy load model
        if self._model is None:
            try:
                self._model = SentenceTransformer(self._model_name)
                logger.info(f"Loaded embedding model: {self._model_name}")
            except Exception as e:
                raise SystemError(
                    f"Failed to load embedding model: {e}",
                    component="SemanticVectorCheck",
                ) from e

        # Compute embedding with timeout (fail-closed)
        try:
            embedding = await asyncio.wait_for(
                asyncio.to_thread(self._model.encode, text),
                timeout=self.timeout_seconds,
            )
            return embedding.tolist()
        except asyncio.TimeoutError:
            raise SystemError(
                f"Embedding computation timed out after {self.timeout_seconds}s",
                component="SemanticVectorCheck",
            )
        except Exception as e:
            raise SystemError(
                f"Embedding computation failed: {e}",
                component="SemanticVectorCheck",
            ) from e

    @staticmethod
    def _cosine_distance(vec1: List[float], vec2: List[float]) -> float:
        """
        Compute cosine distance between two vectors.

        Args:
            vec1: First vector
            vec2: Second vector

        Returns:
            Cosine distance (0.0 = identical, 1.0 = orthogonal)
        """
        v1 = np.array(vec1)
        v2 = np.array(vec2)

        # Cosine similarity = dot(v1, v2) / (||v1|| * ||v2||)
        dot_product = np.dot(v1, v2)
        norm1 = np.linalg.norm(v1)
        norm2 = np.linalg.norm(v2)

        if norm1 == 0 or norm2 == 0:
            return 1.0  # Orthogonal if zero vector

        cosine_similarity = dot_product / (norm1 * norm2)
        # Cosine distance = 1 - cosine_similarity
        cosine_distance = 1.0 - cosine_similarity

        return float(cosine_distance)
