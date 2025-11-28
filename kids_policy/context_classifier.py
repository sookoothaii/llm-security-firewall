#!/usr/bin/env python3
"""
ContextClassifier - Layer 1.5 (HAK_GAL v1.2)
==============================================
Distinguishes between fictional violence (gaming) and real-world threats.

Mission: Allow "Kill the zombie" but block "Kill yourself".

Author: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-28
Status: v1.2 Implementation
"""

import re
import logging
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ContextResult:
    """Result from ContextClassifier analysis."""

    is_gaming_context: bool
    is_fictional_violence: bool
    confidence: float  # 0.0-1.0
    matched_indicators: list[str]
    risk_adjustment: float  # Multiplier for risk score (0.0-1.0, lower = safer)


class ContextClassifier:
    """
    Layer 1.5: Contextual Intelligence

    Detects gaming context to allow fictional violence while maintaining
    strict blocking for real-world threats.

    Critical: Grooming checks (Layer B) must remain active even in gaming context!
    """

    # Gaming-specific keywords (Safe Violence Indikatoren)
    GAMING_KEYWORDS = [
        # Game Names
        "minecraft",
        "fortnite",
        "roblox",
        "apex",
        "valorant",
        "csgo",
        "cs:go",
        "call of duty",
        "cod",
        "overwatch",
        "league of legends",
        "lol",
        "world of warcraft",
        "wow",
        "genshin impact",
        "among us",
        # Game Elements
        "zombie",
        "zombies",
        "skeleton",
        "skeletons",
        "creeper",
        "creepers",
        "boss",
        "bosses",
        "mob",
        "mobs",
        "enemy",
        "enemies",
        "npc",
        "npcs",
        "respawn",
        "respawned",
        "spawn",
        "spawned",
        "level",
        "levels",
        "quest",
        "quests",
        "dungeon",
        "dungeons",
        "raid",
        "raids",
        "headshot",
        "headshots",
        "killstreak",
        "killstreaks",
        # Gaming Actions
        "play",
        "playing",
        "game",
        "games",
        "gaming",
        "gamer",
        "gamers",
        "server",
        "servers",
        "lobby",
        "lobbies",
        "match",
        "matches",
        "ranked",
        "rank",
        "ranking",
        "elo",
        "mmr",
    ]

    # Real-World Violence Indicators (override gaming context)
    REAL_VIOLENCE_INDICATORS = [
        # Personal targeting
        "kill myself",
        "kill yourself",
        "kill my",
        "kill your",
        "hurt myself",
        "hurt yourself",
        "hurt my",
        "hurt your",
        "teacher",
        "parent",
        "mom",
        "dad",
        "family",
        "friend",
        # Explicit real-world context
        "in real life",
        "irl",
        "at school",
        "at home",
        "in person",
        "actually",
        "really want to",
        "seriously",
    ]

    def __init__(self):
        """Initialize ContextClassifier with compiled patterns."""
        # Compile gaming keyword pattern (case-insensitive, word boundaries)
        gaming_pattern_str = (
            r"\b(" + "|".join(re.escape(k) for k in self.GAMING_KEYWORDS) + r")\b"
        )
        self.gaming_pattern = re.compile(gaming_pattern_str, re.IGNORECASE)

        # Compile real-world violence pattern
        real_violence_pattern_str = (
            r"\b("
            + "|".join(re.escape(k) for k in self.REAL_VIOLENCE_INDICATORS)
            + r")\b"
        )
        self.real_violence_pattern = re.compile(
            real_violence_pattern_str, re.IGNORECASE
        )

        logger.info("ContextClassifier initialized (Layer 1.5)")

    def classify(
        self,
        text: str,
        detected_topic: Optional[str] = None,
    ) -> ContextResult:
        """
        Classify context for violence keywords.

        Args:
            text: Input text to analyze
            detected_topic: Optional topic ID from TopicRouter (e.g., "gaming", "unsafe")

        Returns:
            ContextResult with gaming context flag and risk adjustment
        """
        text_lower = text.lower()
        matched_indicators = []

        # Step 1: Check for real-world violence indicators (HIGH PRIORITY)
        real_violence_matches = self.real_violence_pattern.findall(text_lower)
        if real_violence_matches:
            logger.debug(
                f"[ContextClassifier] Real-world violence detected: {real_violence_matches}"
            )
            # Real-world violence overrides gaming context
            return ContextResult(
                is_gaming_context=False,
                is_fictional_violence=False,
                confidence=1.0,
                matched_indicators=real_violence_matches,
                risk_adjustment=1.0,  # No reduction - treat as real threat
            )

        # Step 2: Check for gaming keywords
        gaming_matches = self.gaming_pattern.findall(text_lower)

        # Step 3: Check topic from TopicRouter
        topic_is_gaming = detected_topic and (
            "gaming" in detected_topic.lower() or detected_topic.lower() == "gaming"
        )

        # Decision: Gaming context if (gaming keywords OR gaming topic) AND no real-world indicators
        is_gaming = (len(gaming_matches) > 0 or topic_is_gaming) and len(
            real_violence_matches
        ) == 0

        if is_gaming:
            matched_indicators = gaming_matches
            # Confidence based on number of gaming indicators
            confidence = min(1.0, 0.5 + (len(gaming_matches) * 0.15))

            logger.debug(
                f"[ContextClassifier] Gaming context detected: {len(gaming_matches)} indicators, "
                f"topic={detected_topic}, confidence={confidence:.2f}"
            )

            return ContextResult(
                is_gaming_context=True,
                is_fictional_violence=True,
                confidence=confidence,
                matched_indicators=matched_indicators,
                risk_adjustment=0.3,  # Reduce risk score by 70% for gaming context
            )
        else:
            # No gaming context detected
            return ContextResult(
                is_gaming_context=False,
                is_fictional_violence=False,
                confidence=1.0 if len(gaming_matches) == 0 else 0.5,
                matched_indicators=[],
                risk_adjustment=1.0,  # No reduction - normal risk assessment
            )

    def should_allow_unsafe_in_gaming(
        self,
        text: str,
        detected_topic: Optional[str] = None,
    ) -> bool:
        """
        Check if UNSAFE keywords should be allowed due to gaming context.

        This is the main decision function for the Gamer Exception.

        Args:
            text: Input text
            detected_topic: Optional topic ID from TopicRouter

        Returns:
            True if gaming context is confirmed and violence is fictional
        """
        result = self.classify(text, detected_topic)
        return result.is_fictional_violence and result.is_gaming_context
