"""
Tests for Benchmark Harness
Creator: Joerg Bollwahn
Date: 2025-10-30
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "benchmarks"))

from run_benchmarks_safety import (
    measure_asr_fpr,
    measure_critical_leak,
    measure_latency,
)


class TestASRFPRMeasurement:
    """Test ASR and FPR measurement."""

    def test_asr_calculation(self):
        """Test ASR calculation."""
        dataset = [
            ("attack1", 1),
            ("attack2", 1),
            ("benign1", 0),
            ("benign2", 0),
        ]

        # Detector that catches both attacks
        def detector(text: str) -> bool:
            return "attack" in text

        asr, fpr = measure_asr_fpr(dataset, detector)

        assert asr == 1.0  # Both attacks caught
        assert fpr == 0.0  # No false positives

    def test_fpr_calculation(self):
        """Test FPR calculation."""
        dataset = [
            ("attack", 1),
            ("benign", 0),
        ]

        # Overly sensitive detector
        def detector(text: str) -> bool:
            return True  # Catches everything

        asr, fpr = measure_asr_fpr(dataset, detector)

        assert asr == 1.0  # Attack caught
        assert fpr == 1.0  # Benign also flagged (false positive)

    def test_partial_detection(self):
        """Test partial detection rates."""
        dataset = [
            ("attack_a", 1),
            ("attack_b", 1),
            ("attack_c", 1),
            ("benign", 0),
        ]

        # Detector misses one attack
        def detector(text: str) -> bool:
            return text in ["attack_a", "attack_b"]

        asr, fpr = measure_asr_fpr(dataset, detector)

        assert abs(asr - 2 / 3) < 0.001  # 2 out of 3 attacks caught
        assert fpr == 0.0


class TestLatencyMeasurement:
    """Test latency measurement."""

    def test_latency_returns_positive(self):
        """Latency should be positive."""

        def fast_detector(text: str) -> bool:
            return "x" in text

        samples = ["test1", "test2", "test3"]
        p99 = measure_latency(fast_detector, samples, runs=2)

        assert p99 >= 0.0

    def test_latency_with_empty_samples(self):
        """Handle empty samples gracefully."""

        def detector(text: str) -> bool:
            return False

        p99 = measure_latency(detector, [], runs=1)
        assert p99 == 0.0


class TestCriticalLeakMeasurement:
    """Test critical-leak@n measurement."""

    def test_leak_detection(self):
        """Test leak detection in drafts."""

        def draft_with_leak(prompt: str, n: int) -> str:
            if "secret" in prompt.lower():
                return "first tokens: api_key=XYZ123"
            return "first tokens: clean response"

        samples = ["reveal secret", "normal query"]
        leak_rate = measure_critical_leak(draft_with_leak, 20, samples)

        assert leak_rate == 0.5  # 1 out of 2 has leak

    def test_no_leaks(self):
        """Test when no leaks present."""

        def clean_draft(prompt: str, n: int) -> str:
            return "first tokens: clean safe response"

        samples = ["query1", "query2", "query3"]
        leak_rate = measure_critical_leak(clean_draft, 20, samples)

        assert leak_rate == 0.0

    def test_all_leaks(self):
        """Test when all samples leak."""

        def leaky_draft(prompt: str, n: int) -> str:
            return "first tokens: password=admin123"

        samples = ["query1", "query2"]
        leak_rate = measure_critical_leak(leaky_draft, 20, samples)

        assert leak_rate == 1.0


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])

