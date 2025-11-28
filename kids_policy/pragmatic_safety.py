#!/usr/bin/env python3
"""
Pragmatic Safety Layer (Layer 4)
=================================
Validates intent, not content - detects dangerous cumulative risk over time

Author: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-28
Status: Layer 4 Implementation
"""

import time
import uuid
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass

from .session_context import SessionContext, TurnRisk
from .storage.session_storage import SessionStorage

logger = logging.getLogger(__name__)


# Risk Vectors (Hardcoded for v1.0)
RISK_VECTORS = {
    "PHYSICAL_DANGER": [
        "Messer",
        "Feuer",
        "Chemikalien",
        "Steckdose",
        "knife",
        "fire",
        "chemicals",
        "outlet",
        "messer",
        "feuer",
        "chemikalien",
        "steckdose",
        "küchenmesser",
    ],
    "UNSUPERVISED_ACTION": [
        "allein",
        "ohne Mama",
        "heimlich",
        "secret",
        "alone",
        "without mom",
        "secretly",
        "zusammen",
        "together",
    ],
    "GROOMING_BUILDUP": [
        "Zeig mir",
        "Geheimnis",
        "nur wir zwei",
        "show me",
        "secret",
        "just us two",
        "zeig",
        "zeigen",
        "zeigen",
        "lernen",
        "learn",
        "zusammen kochen",
        "cooking together",
    ],
    "PRIVACY_VIOLATION": [
        "Bild",
        "Foto",
        "Adresse",
        "Telefon",
        "picture",
        "photo",
        "address",
        "phone",
    ],
}


@dataclass
class SafetyResult:
    """Result from Pragmatic Safety Layer validation"""

    is_safe: bool
    reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    @classmethod
    def safe(cls, metadata: Optional[Dict[str, Any]] = None):
        """Create safe result"""
        return cls(is_safe=True, metadata=metadata or {})

    @classmethod
    def block(cls, reason: str, metadata: Optional[Dict[str, Any]] = None):
        """Create block result"""
        return cls(is_safe=False, reason=reason, metadata=metadata or {})


class PragmaticSafetyLayer:
    """Layer 4: Validates intent, not content"""

    def __init__(self, session_storage: SessionStorage, threshold: float = 0.75):
        """
        Initialize Pragmatic Safety Layer

        Args:
            session_storage: Session storage backend (InMemorySessionStorage or Redis)
            threshold: Risk score threshold for blocking (default: 0.75)
        """
        self.session_storage = session_storage
        self.risk_vectors = RISK_VECTORS
        self.threshold = threshold
        logger.info(f"[Layer 4] Initialized with threshold={threshold}")

    def validate(
        self,
        user_input: str,
        topic: Optional[str],
        user_id: str,
        age_band: Optional[str] = None,
    ) -> SafetyResult:
        """
        Validate request against cumulative session risk.

        Args:
            user_input: Current user message
            topic: Detected topic (from Topic Router)
            user_id: User identifier for session tracking
            age_band: Age band (optional, for metadata)

        Returns:
            SafetyResult (Safe or Block)
        """
        try:
            # 1. Extract risk vectors from CURRENT turn
            current_risk = self._extract_risk_vectors(user_input, topic)

            # 2. Load session history
            session = self.session_storage.load_session(user_id)
            if not session:
                session = SessionContext(user_id=user_id, session_id=str(uuid.uuid4()))

            # 3. Calculate cumulative risk
            base_cumulative = session.calculate_cumulative_risk()
            cumulative = base_cumulative + current_risk.risk_score

            logger.debug(
                f"[Layer 4] Turn risk: {current_risk.risk_score:.2f}, "
                f"base cumulative: {base_cumulative:.2f}, "
                f"total: {cumulative:.2f}"
            )

            # 4. Decide based on cumulative score
            if cumulative > self.threshold:
                logger.warning(
                    f"[Layer 4] BLOCKED: Cumulative risk {cumulative:.2f} > threshold {self.threshold} "
                    f"(vectors: {current_risk.risk_vectors})"
                )
                return SafetyResult.block(
                    reason="CUMULATIVE_RISK_CHILD_ENDANGERMENT",
                    metadata={
                        "cumulative_risk": cumulative,
                        "current_risk": current_risk.risk_score,
                        "base_cumulative": base_cumulative,
                        "risk_history_length": len(session.risk_history),
                        "risk_vectors": current_risk.risk_vectors,
                        "keywords": current_risk.keywords,
                        "age_band": age_band,
                    },
                )

            # 5. Save turn in session
            session.add_turn(current_risk)
            self.session_storage.save_session(user_id, session)

            logger.debug(
                f"[Layer 4] ALLOWED: Cumulative risk {cumulative:.2f} <= threshold {self.threshold}"
            )
            return SafetyResult.safe(
                metadata={
                    "cumulative_risk": cumulative,
                    "current_risk": current_risk.risk_score,
                    "risk_history_length": len(session.risk_history),
                }
            )

        except Exception as e:
            logger.error(f"[Layer 4] Error during validation: {e}", exc_info=True)
            # Fail-Closed: Block on error (safety first)
            return SafetyResult.block(
                reason="LAYER_4_ERROR", metadata={"error": str(e)}
            )

    def _extract_risk_vectors(self, text: str, topic: Optional[str]) -> TurnRisk:
        """
        Extract risk vectors from text.

        Returns:
            TurnRisk with identified risk vectors and score
        """
        text_lower = text.lower()
        detected_vectors = []
        keywords_found = []

        # Check each risk vector category
        for vector_name, keywords in self.risk_vectors.items():
            for keyword in keywords:
                if keyword.lower() in text_lower:
                    detected_vectors.append(vector_name)
                    keywords_found.append(keyword)
                    break  # One match per category is enough

        # Calculate risk score (additive, with context multipliers)
        base_risk = (
            len(detected_vectors) * 0.25
        )  # Each vector adds 0.25 (increased from 0.2)

        # Context multipliers for dangerous combinations
        if (
            "PHYSICAL_DANGER" in detected_vectors
            and "GROOMING_BUILDUP" in detected_vectors
        ):
            base_risk += 0.3  # Physical danger + grooming = high risk
        if "zusammen" in text_lower and any(
            kw in keywords_found for kw in ["messer", "knife", "kochen", "cook"]
        ):
            base_risk += 0.2  # "Together" + dangerous activity

        risk_score = min(1.0, base_risk)  # Cap at 1.0

        # Topic drift detection (SCIENCE -> DANGER = +0.3)
        if topic and topic in ["science", "general_chat"]:
            danger_keywords = [
                "messer",
                "feuer",
                "chemikalien",
                "knife",
                "fire",
                "chemicals",
            ]
            if any(
                kw.lower() in keywords_found or kw in text_lower
                for kw in danger_keywords
            ):
                risk_score += 0.3  # Topic trust abuse
                risk_score = min(1.0, risk_score)  # Cap at 1.0

        return TurnRisk(
            turn_id=0,  # Will be set by session
            timestamp=time.time(),
            keywords=keywords_found,
            risk_vectors=detected_vectors,
            topic=topic,
            risk_score=min(1.0, risk_score),
        )
