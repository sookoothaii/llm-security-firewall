#!/usr/bin/env python3
"""
Session Context Management for Layer 4 (Pragmatic Safety)
==========================================================
Eternal memory per user session for cumulative risk tracking

Author: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-28
Status: Layer 4 Implementation
"""

import time
from dataclasses import dataclass, field
from typing import List, Optional, Set
from enum import Enum


class Topic(Enum):
    """Topic enumeration for session tracking"""

    SCIENCE = "science"
    GENERAL_CHAT = "general_chat"
    HISTORY = "history"
    SAFETY = "safety"
    HEALTH = "health"
    OTHER = "other"


@dataclass
class RiskVector:
    """Risk vector categories for child endangerment detection"""

    PHYSICAL_DANGER = "PHYSICAL_DANGER"
    UNSUPERVISED_ACTION = "UNSUPERVISED_ACTION"
    GROOMING_BUILDUP = "GROOMING_BUILDUP"
    PRIVACY_VIOLATION = "PRIVACY_VIOLATION"


@dataclass
class TurnRisk:
    """Stores risk per conversation turn"""

    turn_id: int
    timestamp: float
    keywords: List[str]  # ["Messer", "Bruder"]
    risk_vectors: List[str]  # [PHYSICAL_DANGER, UNSUPERVISED_ACTION]
    topic: Optional[str]
    risk_score: float  # 0.0-1.0


@dataclass
class SessionContext:
    """Eternal memory per user session"""

    user_id: str
    session_id: str
    risk_history: List[TurnRisk] = field(default_factory=list)
    trusted_topics: Set[str] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)

    def calculate_cumulative_risk(self, current_time: Optional[float] = None) -> float:
        """
        Additive risk calculation with temporal decay.

        Example:
            Turn 1: 0.1 (harmless)
            Turn 2: 0.4 (Messer mentioned) + Session history -> 0.5
            Turn 3: 0.3 (Kochen) + 0.5 -> 0.8 (THRESHOLD EXCEEDED)

        Args:
            current_time: Current timestamp (default: time.time())

        Returns:
            Cumulative risk score (0.0-1.0)
        """
        if not self.risk_history:
            return 0.0

        if current_time is None:
            current_time = time.time()

        cumulative = 0.0

        # Apply temporal decay (older turns contribute less)
        # Decay factor: 1.0 for turns < 1 hour old, 0.5 for 1-2 hours, 0.2 for > 2 hours
        one_hour = 3600.0
        two_hours = 7200.0

        for turn_risk in self.risk_history:
            age_seconds = current_time - turn_risk.timestamp

            if age_seconds < one_hour:
                decay_factor = 1.0
            elif age_seconds < two_hours:
                decay_factor = 0.5
            else:
                decay_factor = 0.2

            # Weighted risk contribution
            cumulative += turn_risk.risk_score * decay_factor

        # Cap at 1.0
        return min(1.0, cumulative)

    def add_turn(self, turn_risk: TurnRisk):
        """Add turn to risk history"""
        # Set turn_id if not already set
        if turn_risk.turn_id == 0:
            turn_risk.turn_id = len(self.risk_history) + 1

        self.risk_history.append(turn_risk)
        self.last_activity = time.time()

        # Limit history to last 50 turns (FIFO eviction)
        if len(self.risk_history) > 50:
            self.risk_history = self.risk_history[-50:]

    def add_trusted_topic(self, topic: str):
        """Add topic to trusted set"""
        self.trusted_topics.add(topic)
