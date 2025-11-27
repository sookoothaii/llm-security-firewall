# -*- coding: utf-8 -*-
"""
Enhanced MSG Guard with Adaptive Stochasticity
==============================================

Based on DeepSeek v3.1:671b recommendations (2025-11-26).
Enhances Gray Zone Stochasticity with adaptive thresholds and content-aware decisions.

Creator: Joerg Bollwahn (with DeepSeek v3.1 collaboration)
License: MIT
"""

import hashlib
from typing import Any, Callable, Dict, Tuple
import numpy as np


class EnhancedMSGGuard:
    """Enhanced MSG Guard with adaptive stochasticity and content-aware decisions."""

    def __init__(
        self,
        safe_zone_max: float = 0.70,
        gray_zone_min: float = 0.71,
        gray_zone_max: float = 0.89,
        danger_zone_min: float = 0.90,
        adaptive_threshold: float = 0.80,
    ):
        """Initialize enhanced MSG guard.

        Args:
            safe_zone_max: Maximum score for Safe Zone (default: 0.70)
            gray_zone_min: Minimum score for Gray Zone (default: 0.71)
            gray_zone_max: Maximum score for Gray Zone (default: 0.89)
            danger_zone_min: Minimum score for Danger Zone (default: 0.90)
            adaptive_threshold: Base threshold for adaptive decisions (default: 0.80)
        """
        self.safe_zone_max = safe_zone_max
        self.gray_zone_min = gray_zone_min
        self.gray_zone_max = gray_zone_max
        self.danger_zone_min = danger_zone_min
        self.adaptive_threshold = adaptive_threshold

    def msg_decide_enhanced(
        self,
        scan_fn: Callable[[str, Dict], Tuple[str, float, Dict]],
        text: str,
        meta: Dict[str, Any],
    ) -> Tuple[str, float, Dict]:
        """
        Enhanced decision function with adaptive stochasticity.

        Args:
            scan_fn: Function that returns (action, risk_score, contributions)
            text: Input text
            meta: Context metadata

        Returns:
            (action, risk_score, contributions) with enhanced stability check
        """
        # Get initial score
        try:
            orig_action, orig_risk, orig_contrib = scan_fn(text, meta)
        except Exception as e:
            return ("PASS", 0.0, {"error": str(e)})

        # Validate risk score
        if not 0 <= orig_risk <= 1:
            return ("PASS", 0.0, {"error": f"Invalid risk score: {orig_risk}"})

        metadata = {
            "original_score": orig_risk,
            "zone": None,
            "stochastic_applied": False,
            "decision_reason": "",
        }

        # Fast deterministic decisions
        if orig_risk <= self.safe_zone_max:
            metadata.update(
                {
                    "zone": "safe",
                    "decision_reason": "Below safe zone threshold",
                }
            )
            return ("PASS", orig_risk, {**orig_contrib, **metadata})

        if orig_risk >= self.danger_zone_min:
            metadata.update(
                {
                    "zone": "danger",
                    "decision_reason": "Above danger zone threshold",
                }
            )
            return ("BLOCK", orig_risk, {**orig_contrib, **metadata})

        # Gray zone handling with adaptive stochasticity
        metadata["zone"] = "gray"

        # Calculate adaptive threshold
        effective_threshold = self._calculate_adaptive_threshold(orig_risk, text, meta)

        # Content-aware stochastic decision
        content_hash = self._content_fingerprint(text)
        deterministic_seed = int(content_hash[:8], 16)  # Use content-based seed
        np.random.seed(deterministic_seed)

        # Apply stochastic perturbation
        stochastic_score = self._apply_perturbation(orig_risk, text)
        metadata["stochastic_applied"] = True
        metadata["deterministic_seed"] = deterministic_seed
        metadata["effective_threshold"] = effective_threshold
        metadata["final_score"] = stochastic_score

        if stochastic_score <= effective_threshold:
            metadata["decision_reason"] = "Stochastic PASS after perturbation"
            return ("PASS", stochastic_score, {**orig_contrib, **metadata})
        else:
            metadata["decision_reason"] = "Stochastic BLOCK after perturbation"
            return ("BLOCK", stochastic_score, {**orig_contrib, **metadata})

    def _calculate_adaptive_threshold(
        self,
        risk_score: float,
        content: str = None,
        user_context: Dict[str, Any] = None,
    ) -> float:
        """Calculate dynamic threshold based on attack pattern analysis."""
        base_threshold = self.adaptive_threshold

        # Adjust based on risk score gradient (recent attacks)
        if risk_score > 0.85:
            # Higher sensitivity near danger zone
            base_threshold -= 0.05

        # Content-based adjustments
        if content:
            suspicious_patterns = self._analyze_content_patterns(content)
            if suspicious_patterns.get("suspicion_level", 0) > 0.7:
                base_threshold -= 0.03

        # Keep within gray zone bounds
        return max(self.gray_zone_min, min(self.gray_zone_max, base_threshold))

    def _apply_perturbation(self, risk_score: float, content: str = None) -> float:
        """Apply enhanced perturbation with pattern-aware noise."""
        # Base noise level
        noise_magnitude = 0.15

        # Reduce noise for scores near boundaries
        distance_to_safe = abs(risk_score - self.safe_zone_max)
        distance_to_danger = abs(risk_score - self.danger_zone_min)
        min_distance = min(distance_to_safe, distance_to_danger)

        if min_distance < 0.05:  # Very close to boundary
            noise_magnitude *= 0.3  # Reduce noise near boundaries

        # Apply carefully bounded perturbation
        perturbation = np.random.normal(0, noise_magnitude)
        perturbed_score = risk_score + perturbation

        # Ensure the score stays within [0, 1] bounds
        return max(0.0, min(1.0, perturbed_score))

    def _content_fingerprint(self, content: str) -> str:
        """Create deterministic fingerprint for content-based seeding."""
        normalized = content.lower().strip()
        return hashlib.sha256(normalized.encode()).hexdigest()

    def _analyze_content_patterns(self, content: str) -> Dict[str, float]:
        """Analyze content for suspicious patterns."""
        suspicion_level = 0.0

        # Check for obfuscation attempts
        obfuscation_patterns = [
            "base64",
            "unicode",
            "zero-width",
            "homoglyph",
            "leet",
        ]

        content_lower = content.lower()
        for pattern in obfuscation_patterns:
            if pattern in content_lower:
                suspicion_level += 0.2

        # Check for injection attempts
        injection_patterns = [
            "ignore previous",
            "system:",
            "assistant:",
            "user:",
        ]

        for pattern in injection_patterns:
            if pattern in content_lower:
                suspicion_level += 0.15

        return {
            "suspicion_level": min(1.0, suspicion_level),
            "patterns_detected": len(
                [
                    p
                    for p in obfuscation_patterns + injection_patterns
                    if p in content_lower
                ]
            ),
        }
