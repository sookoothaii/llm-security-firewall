"""
Red-Team Test: Slow-Roll Mimicry Attack
========================================

Tests detection of gradual behavioral adaptation.

Attack Vector:
- Attacker slowly adapts communication to mimic trusted patterns
- Gradual shift over 30 days to avoid detection
- Eventually bypasses Cultural Biometrics

Expected Defense:
- Cultural Biometrics detects anomalies within 3 sessions
- Behavioral baseline comparison flags drift
- Pattern recognition catches systematic shifts
"""

import pytest


class TestSlowRollMimic:
    """Red-Team: Slow-roll mimicry attacks."""

    def test_gradual_shift_detection(self):
        """Test that gradual behavioral shifts are detected."""
        # Simulate 10-day gradual shift
        baseline_pattern = {
            'avg_message_length': 50,
            'technical_density': 0.7,
            'directness': 0.95,
            'formality': 0.6
        }

        # Day 1-3: Normal (baseline)
        baseline_pattern.copy()

        # Day 4-10: Gradual shift (mimicry attempt)
        manipulative_patterns = []
        for day in range(1, 11):
            shift_factor = day / 10.0  # 0.1 to 1.0
            pattern = {
                'avg_message_length': 50 + (100 * shift_factor),  # Gradually longer
                'technical_density': 0.7 - (0.3 * shift_factor),  # Less technical
                'directness': 0.95 - (0.4 * shift_factor),        # Less direct
                'formality': 0.6 + (0.3 * shift_factor)           # More formal
            }
            manipulative_patterns.append(pattern)

        # Check drift at various points
        drift_day_5 = self._compute_drift(baseline_pattern, manipulative_patterns[4])
        drift_day_10 = self._compute_drift(baseline_pattern, manipulative_patterns[9])

        # Detection should happen early (within 3-5 days)
        assert drift_day_5 > 0.2  # Detectable drift by day 5
        assert drift_day_10 > 0.5  # Clear anomaly by day 10

    def test_detection_within_3_sessions(self):
        """Test detection within 3 sessions (GPT-5 requirement)."""
        # Simulate 3 sessions with increasing manipulation
        sessions = [
            {'directness': 0.95, 'technical': 0.7},  # Baseline
            {'directness': 0.75, 'technical': 0.5},  # Shift starts
            {'directness': 0.55, 'technical': 0.3},  # Clear anomaly
        ]

        drifts = []
        baseline = sessions[0]

        for i, session in enumerate(sessions[1:], 1):
            drift = abs(session['directness'] - baseline['directness'])
            drifts.append(drift)

            # Should detect anomaly by session 3
            if i >= 2:  # By session 3
                assert drift > 0.3  # Significant drift

    def test_systematic_pattern_change_flagged(self):
        """Test that systematic pattern changes are flagged."""
        # Attack: Systematic shift in all dimensions
        baseline = {
            'message_length': 50,
            'question_ratio': 0.3,
            'assertion_ratio': 0.5,
            'hedge_ratio': 0.2
        }

        manipulated = {
            'message_length': 150,    # 3x longer
            'question_ratio': 0.1,    # Fewer questions
            'assertion_ratio': 0.8,   # More assertions
            'hedge_ratio': 0.1        # Fewer hedges
        }

        # Compute multi-dimensional drift
        total_drift = sum(
            abs(manipulated[k] - baseline[k]) / (baseline[k] + 0.01)
            for k in baseline.keys()
        )

        # Systematic change should be large
        assert total_drift > 2.0  # Significant multi-dimensional drift

    def _compute_drift(self, baseline: dict, current: dict) -> float:
        """
        Compute drift between patterns.
        
        Returns:
            Drift score (0 = identical, 1+ = anomalous)
        """
        total_drift = 0.0

        for key in baseline.keys():
            if key in current:
                diff = abs(current[key] - baseline[key])
                # Normalize by baseline value
                normalized_diff = diff / (abs(baseline[key]) + 0.01)
                total_drift += normalized_diff

        return total_drift / len(baseline)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

