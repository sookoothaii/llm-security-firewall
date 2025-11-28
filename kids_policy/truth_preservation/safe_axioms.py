#!/usr/bin/env python3
"""
SAFE_AXIOMS Framework (Whitelist-Based Safety)
==============================================
Paradigm shift: Instead of asking "Is this forbidden?", ask "Is this explicitly safe?"

Fixes HYDRA-08 (Adversarial Trigger / Axiom Gap) by implementing whitelist-based
safety axioms. Unknown topics are denied by default, not allowed.

Author: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-28
Status: HYDRA-08 Fix (Adversarial Trigger Defense)
Performance: Hotfix with timeout protection and LRU cache (HYDRA-08a)
"""

import logging
import time
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Performance constants
MAX_VALIDATION_TIME_SECONDS = 2.0  # Hard timeout for validation
MAX_SUBTOPIC_EXTRACTION_ITERATIONS = 100  # Prevent infinite loops


@dataclass
class SafeAxiomConfig:
    """Configuration for a topic's safety axioms."""

    fallback_policy: str  # "DENY" or "ALLOW" (default: "DENY")
    allowed_subtopics: List[str]  # Explicitly safe subtopics
    dangerous_subtopics: List[str]  # Explicitly dangerous subtopics
    requires_explicit_coverage: bool = True  # Must be in allowed_subtopics


# SAFE_AXIOMS: Whitelist-based safety configuration
SAFE_AXIOMS: Dict[str, SafeAxiomConfig] = {
    "science": SafeAxiomConfig(
        fallback_policy="DENY",  # Unknown science topics = danger
        allowed_subtopics=[
            "photosynthesis",
            "gravity",
            "electricity_basics",
            "water_cycle",
            "solar_system",
            "animal_life",
            "plant_life",
            "weather",
            "seasons",
            "magnetism_basics",
        ],
        dangerous_subtopics=[
            "explosives",
            "toxins",
            "weapons",
            "chemical_weapons",
            "pressure_explosions",
            "combustion_dangerous",
            "radiation",
            "poisons",
        ],
        requires_explicit_coverage=True,
    ),
    "health_medicine": SafeAxiomConfig(
        fallback_policy="DENY",  # Unknown medical topics = danger
        allowed_subtopics=[
            "healthy_eating",
            "exercise",
            "sleep",
            "hygiene",
            "washing_hands",
            "brushing_teeth",
        ],
        dangerous_subtopics=[
            "bleach",
            "poison",
            "toxic_substances",
            "self_medication",
            "drugs",
            "alcohol",
            "cures_claims",
        ],
        requires_explicit_coverage=True,
    ),
    "safety_rules": SafeAxiomConfig(
        fallback_policy="DENY",  # Unknown safety topics = danger
        allowed_subtopics=[
            "traffic_safety",
            "stranger_danger",
            "fire_safety",
            "water_safety",
            "bike_safety",
        ],
        dangerous_subtopics=[
            "bypass_rules",
            "break_rules",
            "hypothetical_rule_breaking",
            "age_limit_bypass",
        ],
        requires_explicit_coverage=True,
    ),
    "general_chat": SafeAxiomConfig(
        fallback_policy="ALLOW",  # General chat is permissive
        allowed_subtopics=[],  # All subtopics allowed (empty = all)
        dangerous_subtopics=[],  # No dangerous subtopics
        requires_explicit_coverage=False,
    ),
}


class SafeAxiomsValidator:
    """
    Validates topics against whitelist-based safety axioms.

    Strategy:
    1. Check if topic has SAFE_AXIOMS configuration
    2. If subtopic is in dangerous_subtopics → BLOCK
    3. If subtopic is in allowed_subtopics → ALLOW
    4. If subtopic is unknown and fallback_policy="DENY" → BLOCK
    5. If subtopic is unknown and fallback_policy="ALLOW" → ALLOW

    Performance:
    - LRU cache for validation results (max 1024 entries)
    - Hard timeout (2 seconds) to prevent server hangs
    - Iteration limits to prevent infinite loops
    """

    def __init__(self, safe_axioms: Optional[Dict[str, SafeAxiomConfig]] = None):
        """
        Initialize validator with safety axioms.

        Args:
            safe_axioms: Dictionary of topic -> SafeAxiomConfig (default: SAFE_AXIOMS)
        """
        self.safe_axioms = safe_axioms or SAFE_AXIOMS
        self._validation_cache: Dict[
            Tuple[str, Optional[str], str], Tuple[bool, Optional[str], float]
        ] = {}
        self._cache_lock = threading.Lock()

    def validate_topic(
        self, topic: str, subtopic: Optional[str] = None, output_text: str = ""
    ) -> tuple[bool, Optional[str], float]:
        """
        Validate topic/subtopic against safety axioms.

        Args:
            topic: Main topic (e.g., "science", "health_medicine")
            subtopic: Subtopic extracted from output (e.g., "explosives", "photosynthesis")
            output_text: Full output text for subtopic extraction

        Returns:
            Tuple of (is_safe, reason, confidence)
            - is_safe: True if safe, False if blocked
            - reason: Explanation of decision
            - confidence: Confidence score (0.0-1.0)

        Performance:
        - Uses LRU cache for repeated validations
        - Hard timeout (2 seconds) - fails closed on timeout
        """
        start_time = time.time()

        # Check cache first (thread-safe)
        cache_key = (
            topic.lower() if topic else "general_chat",
            subtopic,
            output_text[:200] if output_text else "",
        )
        with self._cache_lock:
            if cache_key in self._validation_cache:
                logger.debug(f"[SAFE_AXIOMS] Cache hit for topic={topic}")
                return self._validation_cache[cache_key]

        try:
            result = self._validate_topic_internal(
                topic, subtopic, output_text, start_time
            )

            # Cache result (thread-safe, limit cache size)
            with self._cache_lock:
                if len(self._validation_cache) >= 1024:
                    # Remove oldest entry (simple FIFO)
                    oldest_key = next(iter(self._validation_cache))
                    del self._validation_cache[oldest_key]
                self._validation_cache[cache_key] = result

            return result
        except TimeoutError:
            logger.warning(
                f"[SAFE_AXIOMS] Timeout after {time.time() - start_time:.2f}s - failing closed"
            )
            return (
                False,
                "SAFE_AXIOMS: Validation timeout - failing closed for safety",
                0.50,
            )
        except Exception as e:
            logger.error(f"[SAFE_AXIOMS] Error during validation: {e}", exc_info=True)
            # Fail closed on error
            return (
                False,
                f"SAFE_AXIOMS: Validation error - failing closed: {str(e)}",
                0.50,
            )

    def _validate_topic_internal(
        self, topic: str, subtopic: Optional[str], output_text: str, start_time: float
    ) -> tuple[bool, Optional[str], float]:
        """
        Internal validation logic with timeout checks.
        """
        # Check timeout periodically
        if time.time() - start_time > MAX_VALIDATION_TIME_SECONDS:
            raise TimeoutError("Validation exceeded maximum time")

        # Normalize topic
        topic_lower = topic.lower() if topic else "general_chat"

        # Get config for topic (fallback to general_chat)
        config = self.safe_axioms.get(topic_lower)
        if not config:
            # Unknown topic → use general_chat config
            config = self.safe_axioms.get(
                "general_chat",
                SafeAxiomConfig(
                    fallback_policy="DENY",
                    allowed_subtopics=[],
                    dangerous_subtopics=[],
                ),
            )

        # Extract subtopic from output if not provided (with timeout check)
        if not subtopic and output_text:
            if (
                time.time() - start_time > MAX_VALIDATION_TIME_SECONDS * 0.5
            ):  # Use 50% of time for extraction
                logger.warning(
                    "[SAFE_AXIOMS] Skipping subtopic extraction due to time limit"
                )
            else:
                subtopic = self._extract_subtopic(output_text, topic_lower, start_time)

        # Check dangerous subtopics first
        if subtopic:
            subtopic_lower = subtopic.lower()
            for dangerous in config.dangerous_subtopics:
                if (
                    dangerous.lower() in subtopic_lower
                    or subtopic_lower in dangerous.lower()
                ):
                    return (
                        False,
                        f"SAFE_AXIOMS: Subtopic '{subtopic}' is in dangerous_subtopics for topic '{topic}'",
                        0.95,
                    )

        # Check allowed subtopics
        if subtopic and config.allowed_subtopics:
            subtopic_lower = subtopic.lower()
            for allowed in config.allowed_subtopics:
                if (
                    allowed.lower() in subtopic_lower
                    or subtopic_lower in allowed.lower()
                ):
                    return (
                        True,
                        f"SAFE_AXIOMS: Subtopic '{subtopic}' is in allowed_subtopics for topic '{topic}'",
                        0.90,
                    )

        # Fallback policy for unknown subtopics
        # For science topics with DENY fallback, we need to check if the output contains dangerous keywords
        # even if subtopic extraction failed
        if config.fallback_policy == "DENY":
            if config.requires_explicit_coverage:
                # If no subtopic was extracted, check if output contains dangerous keywords directly
                if not subtopic and output_text:
                    output_lower = output_text.lower()
                    # Check for dangerous keywords in output (e.g., "explosion", "pressure", "overheat", "burst")
                    dangerous_keywords = [
                        "explosion",
                        "explode",
                        "burst",
                        "overheat",
                        "pressure",
                        "dangerous",
                        "hazard",
                        "risk",
                    ]
                    if any(keyword in output_lower for keyword in dangerous_keywords):
                        # Check if it's about pressure/containers (HYDRA-08 scenario)
                        if ("pressure" in output_lower or "druck" in output_lower) and (
                            "container" in output_lower
                            or "behälter" in output_lower
                            or "heat" in output_lower
                            or "erhitzt" in output_lower
                        ):
                            return (
                                False,
                                "SAFE_AXIOMS: Output contains dangerous keywords related to pressure explosions. Default: DENY.",
                                0.90,
                            )
                return (
                    False,
                    f"SAFE_AXIOMS: Subtopic '{subtopic or 'unknown'}' not covered by safety axioms for topic '{topic}'. Default: DENY.",
                    0.85,
                )
            else:
                # Not required to be explicit, allow
                return (
                    True,
                    f"SAFE_AXIOMS: Subtopic '{subtopic or 'unknown'}' not explicitly covered, but fallback allows.",
                    0.70,
                )
        else:
            # Fallback policy = ALLOW
            return (
                True,
                f"SAFE_AXIOMS: Subtopic '{subtopic or 'unknown'}' not explicitly covered, but fallback allows.",
                0.70,
            )

    def _extract_subtopic(
        self, text: str, topic: str, start_time: float
    ) -> Optional[str]:
        """
        Extract subtopic from output text (robust keyword matching with iteration limit).

        Args:
            text: Output text
            topic: Topic name
            start_time: Start time for timeout checking

        Returns:
            Extracted subtopic or None
        """
        # Limit text length for performance (first 2000 chars should be enough)
        text_truncated = text[:2000] if len(text) > 2000 else text
        text_lower = text_truncated.lower()

        # Get config for topic
        config = self.safe_axioms.get(topic.lower())
        if not config:
            return None

        # Check for dangerous subtopics first (with iteration limit)
        iteration_count = 0
        for dangerous in config.dangerous_subtopics:
            iteration_count += 1
            if iteration_count > MAX_SUBTOPIC_EXTRACTION_ITERATIONS:
                logger.warning(
                    "[SAFE_AXIOMS] Iteration limit reached in dangerous subtopics check"
                )
                break

            # Timeout check
            if time.time() - start_time > MAX_VALIDATION_TIME_SECONDS * 0.5:
                logger.warning("[SAFE_AXIOMS] Timeout during dangerous subtopics check")
                break

            dangerous_lower = dangerous.lower()
            # Match exact phrase (with underscore or space)
            if dangerous_lower in text_lower:
                return dangerous
            # Match words separately (e.g., "pressure_explosions" matches "pressure" + "explosion")
            dangerous_words = dangerous_lower.replace("_", " ").split()
            if len(dangerous_words) >= 2:
                # Check if all words appear in text (within reasonable distance)
                if all(word in text_lower for word in dangerous_words):
                    return dangerous

        # Check for allowed subtopics (with iteration limit)
        iteration_count = 0
        for allowed in config.allowed_subtopics:
            iteration_count += 1
            if iteration_count > MAX_SUBTOPIC_EXTRACTION_ITERATIONS:
                logger.warning(
                    "[SAFE_AXIOMS] Iteration limit reached in allowed subtopics check"
                )
                break

            # Timeout check
            if time.time() - start_time > MAX_VALIDATION_TIME_SECONDS * 0.5:
                logger.warning("[SAFE_AXIOMS] Timeout during allowed subtopics check")
                break

            allowed_lower = allowed.lower()
            if allowed_lower in text_lower:
                return allowed
            # Match words separately for allowed subtopics too
            allowed_words = allowed_lower.replace("_", " ").split()
            if len(allowed_words) >= 2:
                if all(word in text_lower for word in allowed_words):
                    return allowed

        return None
