"""
Ensemble Topic Fence - Multi-Model Adversarial Defense (The Hydra)

UPGRADE: P0 Fix for Chameleon Cascade (CC-2025)
Uses 3 diverse embedding models to detect adversarial vectors via uncertainty quantification.

Inspired by Kimi k2's ensemble defense strategy.
"""

# LAZY LOADING: ML-Libraries werden erst bei Bedarf importiert
# Dies reduziert die Baseline-Memory von ~1291 MB drastisch
import numpy as np
from typing import List, Optional
from itertools import combinations
import logging

logger = logging.getLogger(__name__)


class TopicFence:
    """
    Ensemble Topic Fence with uncertainty quantification.

    Uses 3 diverse models to detect adversarial perturbations:
    - Model 1: all-MiniLM-L6-v2 (The Fast One)
    - Model 2: paraphrase-albert-small-v2 (The Robust One)
    - Model 3: multi-qa-MiniLM-L6-cos-v1 (The Question Expert)

    If models disagree (high uncertainty), likely adversarial → BLOCK
    """

    _instance: Optional["TopicFence"] = None

    def __new__(cls):
        """Singleton pattern: only one instance with loaded models."""
        if cls._instance is None:
            cls._instance = super(TopicFence, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Load ensemble of 3 DIVERSE models (not 3x Mini)."""
        # LAZY IMPORT: Load ML libraries only when needed
        from sentence_transformers import SentenceTransformer
        import torch

        logger.info("[EnsembleFence] Loading Neural Ensemble (3 DIVERSE Models)...")
        device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"   Using device: {device}")

        try:
            # FIX: 3 DIVERSE Architekturen (nicht 3x Mini)
            # L2-Distanz ist empfindlicher für adversarial Perturbation als Cosine
            self.encoders = {
                "mini": SentenceTransformer(
                    "all-MiniLM-L6-v2", device=device
                ),  # Der Schnelle
                "mpnet": SentenceTransformer(
                    "all-mpnet-base-v2", device=device
                ),  # Komplett andere Architektur
                "e5": SentenceTransformer(
                    "intfloat/e5-small-v2", device=device
                ),  # Andere Trainingsdaten
            }

            # Backward compatibility: models list
            self.models = list(self.encoders.values())

            self.allowed_topics = [
                "Mathe",
                "Physik",
                "Chemie",
                "Biologie",
                "Informatik",
                "Schule",
            ]

            # Pre-compute Embeddings für alle Modelle
            self.topic_embeddings = []
            for model in self.models:
                self.topic_embeddings.append(
                    model.encode(self.allowed_topics, convert_to_tensor=True)
                )

            logger.info(
                "[EnsembleFence] Hydra System Armed (Gradient Disagreement Mode)."
            )
        except Exception as e:
            logger.error(f"Failed to load ensemble models: {e}")
            # Fallback to single model
            from sentence_transformers import SentenceTransformer

            self.encoders = {
                "mini": SentenceTransformer("all-MiniLM-L6-v2", device=device)
            }
            self.models = [self.encoders["mini"]]
            self.topic_embeddings = [
                self.models[0].encode(self.allowed_topics, convert_to_tensor=True)
            ]
            logger.warning("Falling back to single-model mode")

    def is_on_topic(
        self,
        user_input: str,
        allowed_topics: Optional[List[str]] = None,
        threshold: float = 0.25,
    ) -> bool:
        """
        Check if user input matches any of the allowed topics using ensemble.

        Args:
            user_input: The user's input text to validate
            allowed_topics: List of topic strings (uses default if None)
            threshold: Minimum average cosine similarity to consider a match

        Returns:
            True if the input is on-topic AND uncertainty is low, False otherwise
        """
        if not user_input or not user_input.strip():
            return False

        # Use provided topics or default
        topics = allowed_topics if allowed_topics else self.allowed_topics

        # Recompute embeddings if topics changed
        if topics != self.allowed_topics:
            self.allowed_topics = topics
            self.topic_embeddings = []
            for model in self.models:
                self.topic_embeddings.append(
                    model.encode(topics, convert_to_tensor=True)
                )

        # FIX: Gradient Disagreement via L2-Distanz (nicht stddev)
        # 1. Embed mit allen 3 DIVERSE Modellen
        embeddings = {}
        embedding_dims = {}
        for name, encoder in self.encoders.items():
            emb = encoder.encode(user_input, convert_to_tensor=False)  # NumPy array
            embeddings[name] = np.array(emb)
            embedding_dims[name] = emb.shape[0]

        # 2. Find minimum dimension and pad/truncate all embeddings to same size
        # This allows comparison between models with different dimensions
        min_dim = min(embedding_dims.values())
        normalized_embeddings = {}
        for name, emb in embeddings.items():
            if emb.shape[0] > min_dim:
                # Truncate to min_dim (take first min_dim elements)
                normalized_embeddings[name] = emb[:min_dim]
            elif emb.shape[0] < min_dim:
                # Pad with zeros (shouldn't happen, but safety)
                padded = np.zeros(min_dim)
                padded[: emb.shape[0]] = emb
                normalized_embeddings[name] = padded
            else:
                normalized_embeddings[name] = emb

        # 3. Berechne L2-Distanz zwischen Embeddings (nicht Cosine!)
        # L2 ist empfindlicher für adversarial Perturbation
        distances = []
        for (n1, e1), (n2, e2) in combinations(normalized_embeddings.items(), 2):
            dist = np.linalg.norm(e1 - e2)
            distances.append(dist)

        # 4. Relative Varianz als Unsicherheitsmaß (Gradient Disagreement)
        if len(distances) > 0:
            mean_dist = np.mean(distances)
            uncertainty = np.var(distances) / (mean_dist + 1e-8)  # Relative variance
        else:
            uncertainty = 0.0

        # 5. Crisis Brake bei hoher Unsicherheit (Adversarial Check)
        if len(self.encoders) > 1 and uncertainty > 0.12:
            logger.warning(
                f"[Ensemble] BLOCKED: Adversarial Perturbation Detected (Uncertainty: {uncertainty:.4f})"
            )
            return False

        # 6. Standard-Check für sichere Fälle (Cosine Similarity)
        from sentence_transformers import util

        scores = []
        for i, model in enumerate(self.models):
            emb = model.encode(user_input, convert_to_tensor=True)
            cos_scores = util.cos_sim(emb, self.topic_embeddings[i])
            scores.append(float(cos_scores.max()))

        avg_score = float(np.mean(scores))

        logger.debug(
            f"[Ensemble] Scores: {[round(x, 3) for x in scores]} | Avg: {avg_score:.3f} | Uncertainty: {uncertainty:.4f}"
        )

        # 7. Final Check
        if avg_score < threshold:
            return False

        return True

    def get_best_topic(
        self, user_input: str, allowed_topics: Optional[List[str]] = None
    ) -> tuple[Optional[str], float]:
        """
        Get the best matching topic and its similarity score (using first model for consistency).

        Args:
            user_input: The user's input text
            allowed_topics: List of topic strings

        Returns:
            Tuple of (best_topic, similarity_score) or (None, 0.0) if no topics
        """
        if not allowed_topics:
            allowed_topics = self.allowed_topics

        if not user_input or not user_input.strip():
            return None, 0.0

        # Use first model for consistency
        from sentence_transformers import util
        import torch

        model = self.models[0]
        user_embedding = model.encode(user_input, convert_to_tensor=True)
        topic_embeddings = model.encode(allowed_topics, convert_to_tensor=True)

        similarities = util.cos_sim(user_embedding, topic_embeddings)[0]
        best_idx = int(torch.argmax(similarities))
        best_score = float(similarities[best_idx])

        return allowed_topics[best_idx], best_score
