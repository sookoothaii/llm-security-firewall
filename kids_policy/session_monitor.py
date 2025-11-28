#!/usr/bin/env python3
"""
SessionMonitor - TAG-4 Temporal Context Awareness
=================================================
Tracks accumulated risk across multiple requests to detect Salami Slicing Attacks.

Part of HAK/GAL Kids Policy Engine
Author: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-28
Status: Initial Implementation
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, List
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class SessionState:
    """State for a single user session."""

    accumulated_risk: float = 0.0
    last_interaction: float = field(default_factory=time.time)
    topic_history: List[str] = field(default_factory=list)
    request_count: int = 0


class SessionMonitor:
    """
    TAG-4: Temporal Context Awareness

    Tracks accumulated risk per user to detect Salami Slicing Attacks.
    Risk decays over time, but accumulates across suspicious requests.

    Singleton pattern for global state management.
    """

    # Decay rate: risk decreases by this amount per second
    DECAY_RATE = 0.05  # 0.05 per second

    # Risk multiplier for high-risk requests (escalation)
    HIGH_RISK_MULTIPLIER = 1.5  # Applied when current_score > 0.5

    # High-risk threshold
    HIGH_RISK_THRESHOLD = 0.5

    _instance = None
    _sessions: Dict[str, SessionState] = defaultdict(SessionState)

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SessionMonitor, cls).__new__(cls)
        return cls._instance

    def update(
        self,
        user_id: str,
        current_score: float,
        topic: Optional[str] = None,
    ) -> float:
        """
        Update accumulated risk for a user session.

        Args:
            user_id: Unique user identifier
            current_score: Current risk score (0.0-1.0) from semantic guard
            topic: Optional topic ID for history tracking

        Returns:
            Updated accumulated_risk value
        """
        now = time.time()
        session = self._sessions[user_id]

        # Apply decay based on time since last interaction
        time_delta = now - session.last_interaction
        decay_amount = time_delta * self.DECAY_RATE

        # Decay accumulated risk (but don't go below 0)
        session.accumulated_risk = max(0.0, session.accumulated_risk - decay_amount)

        # Apply risk multiplier for high-risk requests (escalation)
        if current_score > self.HIGH_RISK_THRESHOLD:
            adjusted_score = current_score * self.HIGH_RISK_MULTIPLIER
            logger.debug(
                f"[TAG-4] High-risk request detected (score={current_score:.2f}), "
                f"applying multiplier: {adjusted_score:.2f}"
            )
        else:
            adjusted_score = current_score

        # Add new risk to accumulated risk
        session.accumulated_risk += adjusted_score

        # Update metadata
        session.last_interaction = now
        session.request_count += 1
        if topic:
            session.topic_history.append(topic)
            # Keep only last 10 topics
            if len(session.topic_history) > 10:
                session.topic_history.pop(0)

        logger.debug(
            f"[TAG-4] User {user_id}: accumulated_risk={session.accumulated_risk:.2f} "
            f"(current={current_score:.2f}, decay={decay_amount:.2f}, requests={session.request_count})"
        )

        return session.accumulated_risk

    def get_risk(self, user_id: str) -> float:
        """Get current accumulated risk for a user."""
        session = self._sessions.get(user_id)
        if session is None:
            return 0.0

        # Apply decay if session exists but is stale
        now = time.time()
        time_delta = now - session.last_interaction
        if time_delta > 0:
            decay_amount = time_delta * self.DECAY_RATE
            session.accumulated_risk = max(0.0, session.accumulated_risk - decay_amount)
            session.last_interaction = now

        return session.accumulated_risk

    @staticmethod
    def get_dynamic_threshold(
        topic: Optional[str] = None, text: Optional[str] = None
    ) -> float:
        """
        Get dynamic risk threshold based on topic and content (v1.2).

        Args:
            topic: Optional topic ID from TopicRouter
            text: Optional text content for emotional keyword detection

        Returns:
            Threshold value (higher = more tolerant, lower = stricter)
        """
        # Mental Health / Self-Harm: Stricter (0.8) - fail-safe for emotional spirals
        # Check both topic and text content for emotional keywords
        emotional_keywords = [
            "sleep forever",
            "never wake up",
            "disappear",
            "end it",
            "give up",
            "no point",
            "tired of living",
            "want to die",
            "kill myself",
            "suicide",
            "depression",
            "hopeless",
            "sad",
            "lonely",
            "isolated",
        ]

        # Check topic first
        if topic:
            topic_lower = topic.lower()
            if any(
                keyword in topic_lower
                for keyword in [
                    "mental",
                    "health",
                    "self-harm",
                    "suicide",
                    "depression",
                    "emotional",
                ]
            ):
                return 0.8

        # Check text content for emotional keywords (even if topic is general_chat)
        if text:
            text_lower = text.lower()
            if any(keyword in text_lower for keyword in emotional_keywords):
                logger.debug(
                    "[TAG-4] Emotional content detected in text, using strict threshold 0.8"
                )
                return 0.8

        # Gaming: More tolerant (1.5) - fictional violence is acceptable
        if topic:
            topic_lower = topic.lower()
            if "gaming" in topic_lower or topic_lower == "gaming":
                return 1.5

        # Default: Standard threshold (1.2)
        return 1.2

    def reset(self, user_id: str):
        """Reset session state for a user (for testing)."""
        if user_id in self._sessions:
            del self._sessions[user_id]
            logger.debug(f"[TAG-4] Reset session for user {user_id}")

    @classmethod
    def clear_all(cls):
        """Clear all sessions (for testing)."""
        cls._sessions.clear()
        logger.debug("[TAG-4] Cleared all sessions")
