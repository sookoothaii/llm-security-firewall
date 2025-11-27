#!/usr/bin/env python3
"""
Grooming Detector v1.1.0
========================
TAG-3: Behavioral Integrity & Grooming Prevention

Part of HAK/GAL Kids Policy Engine

Architecture:
- Layer A: Fast Regex Patterns (<10ms) for hard indicators
- Layer B: Semantic/NLI Check (v1.1.0) for soft manipulation (HYDRA-05 Fix)

Author: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-28
Status: Layer B Implementation Complete (Semantic Guard Integration)

Rationale:
A factually correct predator is still a predator.
This detector identifies manipulative behavioral patterns regardless of factual accuracy.
"""

import re
import yaml
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Import Semantic Guard (Infrastructure Adapter)
try:
    from .semantic_grooming_guard import SemanticGroomingGuard

    HAS_SEMANTIC_GUARD = True
except ImportError:
    HAS_SEMANTIC_GUARD = False
    SemanticGroomingGuard = None


@dataclass
class GroomingResult:
    """Result of grooming detection validation"""

    detected: bool
    category: Optional[str] = None
    confidence: float = 0.0
    matched_pattern: Optional[str] = None
    action: str = "allow"  # allow, block, flag
    safe_response: Optional[str] = None
    audit: Optional[Dict] = None


class GroomingDetector:
    """
    TAG-3: Behavioral Integrity & Grooming Prevention

    Detects manipulative patterns in child-directed text:
    - Isolation attempts
    - Gift/material incentives
    - Real-life transition attempts
    - Authority erosion
    - Boundary testing

    Architecture:
    - Hybrid approach: Regex (Layer A) + NLI (Layer B, future)
    - Fast-path regex for hard indicators (<10ms)
    - Semantic check for soft manipulation (placeholder)
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize Grooming Detector

        Args:
            config_path: Path to behavioral_integrity_v0_1.yaml
                        If None, uses default path relative to this file
        """
        if config_path is None:
            # Default path: gates/behavioral_integrity_v0_1.yaml relative to validators/
            base_path = Path(__file__).parent.parent
            config_path = str(base_path / "gates" / "behavioral_integrity_v0_1.yaml")

        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)

        self.gates_config = self.config.get("behavioral_integrity", {})
        self.version = self.gates_config.get("version", "0.1.0")

        # Compile regex patterns
        self.patterns = self._compile_patterns()

        # Load response templates
        self.responses = self.gates_config.get("responses", {})

        # Layer B: Semantic Guard (Infrastructure Adapter)
        semantic_layer_config = self.gates_config.get("semantic_layer", {})
        self.semantic_layer_enabled = semantic_layer_config.get(
            "enabled", True
        )  # Default: enabled
        self.semantic_threshold = semantic_layer_config.get("threshold", 0.65)

        # Initialize Semantic Guard (graceful degradation if not available)
        self.semantic_guard = None
        if self.semantic_layer_enabled and HAS_SEMANTIC_GUARD:
            try:
                self.semantic_guard = SemanticGroomingGuard()
            except Exception as e:
                logger.warning(
                    f"Semantic Guard initialization failed: {e}. Layer B disabled."
                )
                self.semantic_guard = None
                self.semantic_layer_enabled = False

    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns from config"""
        compiled = {}
        categories = self.gates_config.get("categories", {})

        for cat, data in categories.items():
            patterns = data.get("patterns", [])
            compiled[cat] = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]

        return compiled

    def validate(
        self, text: str, context_history: Optional[List[str]] = None
    ) -> GroomingResult:
        """
        Validate text against grooming patterns

        Args:
            text: Text to validate
            context_history: Optional list of previous messages in conversation
                           (for multi-turn grooming detection in v0.2.0)

        Returns:
            GroomingResult with detection status and metadata
        """
        # Normalize text (basic cleanup)
        normalized_text = self._normalize_text(text)

        # Layer A: Fast-path Regex Heuristics (<10ms)
        regex_result = self._check_regex_layer(normalized_text)
        if regex_result.detected:
            return regex_result

        # Layer B: Semantic/NLI Check (v1.1.0 - HYDRA-05 Fix)
        if self.semantic_layer_enabled and self.semantic_guard:
            semantic_result = self._check_semantic_layer(
                normalized_text, context_history
            )
            if semantic_result.detected:
                return semantic_result

        # No grooming detected
        return GroomingResult(
            detected=False,
            confidence=0.0,
            action="allow",
            audit={
                "detector_version": "1.0.0",
                "gates_version": self.version,
                "layer_a_checked": True,
                "layer_b_checked": self.semantic_layer_enabled
                and self.semantic_guard is not None,
                "pattern_matches": [],
                "category": None,
            },
        )

    def _normalize_text(self, text: str) -> str:
        """Basic text normalization"""
        # Remove extra whitespace
        text = " ".join(text.split())
        return text

    def _check_regex_layer(self, text: str) -> GroomingResult:
        """Layer A: Fast regex pattern matching"""
        categories = self.gates_config.get("categories", {})

        for category, patterns in self.patterns.items():
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    category_config = categories.get(category, {})
                    risk_weight = category_config.get("risk_weight", 1.0)
                    action = category_config.get("action", "block")

                    # Get appropriate safe response
                    response_key = (
                        f"{category}_block"
                        if f"{category}_block" in self.responses
                        else "default_block"
                    )
                    safe_response = self.responses.get(
                        response_key, self.responses.get("default_block", "")
                    )

                    return GroomingResult(
                        detected=True,
                        category=category,
                        confidence=risk_weight,  # Regex is deterministic, use risk_weight as confidence
                        matched_pattern=pattern.pattern,
                        action=action,
                        safe_response=safe_response,
                        audit={
                            "detector_version": "1.0.0",
                            "gates_version": self.version,
                            "layer_a_checked": True,
                            "layer_b_checked": False,
                            "pattern_matches": [pattern.pattern],
                            "category": category,
                            "matched_text": match.group(0)[
                                :100
                            ],  # First 100 chars of match
                        },
                    )

        return GroomingResult(detected=False)

    def _check_semantic_layer(
        self, text: str, context_history: Optional[List[str]] = None
    ) -> GroomingResult:
        """
        Layer B: Semantic/NLI-based detection (v1.1.0 - HYDRA-05 Fix)

        Detects soft manipulation patterns that regex cannot catch,
        such as: "That's our special thing" or "You understand, right?"

        Uses SemanticGroomingGuard (Infrastructure Adapter) for embedding-based similarity.
        """
        if not self.semantic_guard:
            return GroomingResult(detected=False)

        # Check semantic similarity to grooming concepts
        is_safe, risk_description, score = self.semantic_guard.check_semantic_risk(
            text, threshold=self.semantic_threshold
        )

        if not is_safe:
            # Get safe response (use semantic_grooming category if exists)
            response_key = (
                "semantic_grooming_block"
                if "semantic_grooming_block" in self.responses
                else "default_block"
            )
            safe_response = self.responses.get(
                response_key, self.responses.get("default_block", "")
            )

            return GroomingResult(
                detected=True,
                category="semantic_grooming",
                confidence=score,
                matched_pattern=risk_description or "semantic_match",
                action="block",
                safe_response=safe_response,
                audit={
                    "detector_version": "1.1.0",
                    "gates_version": self.version,
                    "layer_a_checked": True,
                    "layer_b_checked": True,
                    "semantic_score": score,
                    "matched_concept": risk_description,
                },
            )

        return GroomingResult(detected=False)

    def get_safe_response(self, category: str) -> str:
        """Get appropriate safe response for category"""
        response_key = f"{category}_block"
        return self.responses.get(
            response_key,
            self.responses.get("default_block", "I cannot continue this conversation."),
        )


# Convenience function for direct usage
def detect_grooming(text: str, config_path: Optional[str] = None) -> GroomingResult:
    """
    Convenience function for quick grooming detection

    Args:
        text: Text to check
        config_path: Optional path to config file

    Returns:
        GroomingResult
    """
    detector = GroomingDetector(config_path)
    return detector.validate(text)
