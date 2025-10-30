"""
Tests for Safety-Sandwich Decoding
Creator: Joerg Bollwahn
Date: 2025-10-30
"""

import pytest

from src.llm_firewall.gates.safety_sandwich import (
    ABORTED_MESSAGE,
    LeakDetector,
    guarded_decode,
    guarded_decode_with_details,
)


class MockSpeculativeModel:
    """Mock model for testing."""

    def __init__(self, draft: str, final: str):
        self._draft = draft
        self._final = final

    def spec_decode(self, prompt: str, max_new_tokens: int = 20) -> str:
        return self._draft

    def decode(self, prompt: str) -> str:
        return self._final


class TestLeakDetector:
    """Test LeakDetector patterns."""

    def test_detect_password_leak(self):
        """Detect password in text."""
        detector = LeakDetector()
        text = "The password: admin123 is hardcoded"
        assert detector.count_critical(text) > 0

    def test_detect_api_key_leak(self):
        """Detect API key."""
        detector = LeakDetector()
        text = "api_key=sk-1234567890abcdef"
        assert detector.count_critical(text) > 0

    def test_detect_private_key_leak(self):
        """Detect private key header."""
        detector = LeakDetector()
        text = "-----BEGIN RSA PRIVATE KEY-----"
        assert detector.count_critical(text) > 0

    def test_detect_secret_leak(self):
        """Detect secret marker."""
        detector = LeakDetector()
        text = "secret=my_confidential_data"
        assert detector.count_critical(text) > 0

    def test_clean_text_no_leak(self):
        """Clean text should have zero count."""
        detector = LeakDetector()
        text = "This is a safe response about general topics."
        assert detector.count_critical(text) == 0

    def test_find_leaks_returns_details(self):
        """Test find_leaks method."""
        detector = LeakDetector()
        text = "password: abc123 and api_key=xyz789"
        leaks = detector.find_leaks(text)
        assert len(leaks) >= 2  # Should find at least 2 patterns


class TestGuardedDecode:
    """Test guarded_decode function."""

    def test_aborts_on_critical_leak(self):
        """Should abort if draft contains leak."""
        model = MockSpeculativeModel(
            draft="First tokens: api_key=ABCD1234", final="SHOULD NOT REACH HERE"
        )
        output = guarded_decode("test prompt", model)
        assert output == ABORTED_MESSAGE

    def test_allows_clean_draft(self):
        """Should proceed if draft is clean."""
        model = MockSpeculativeModel(
            draft="Hello, this is safe.", final="Full safe response."
        )
        output = guarded_decode("test prompt", model)
        assert output == "Full safe response."

    def test_multiple_leaks_detected(self):
        """Multiple leaks should still abort."""
        model = MockSpeculativeModel(
            draft="password=admin and secret=xyz", final="NOT REACHED"
        )
        output = guarded_decode("test prompt", model)
        assert output == ABORTED_MESSAGE

    def test_custom_n_tokens(self):
        """Test custom n_tokens parameter."""
        model = MockSpeculativeModel(draft="safe preview", final="full output")
        output = guarded_decode("test prompt", model, n_tokens=10)
        assert output == "full output"


class TestGuardedDecodeWithDetails:
    """Test guarded_decode_with_details function."""

    def test_returns_details_on_abort(self):
        """Should return abort flag and leak details."""
        model = MockSpeculativeModel(draft="api_key=leaked", final="NOT REACHED")
        output, was_aborted, leaks = guarded_decode_with_details("test", model)

        assert output == ABORTED_MESSAGE
        assert was_aborted is True
        assert len(leaks) > 0

    def test_returns_clean_output_details(self):
        """Should return clean output with no leaks."""
        model = MockSpeculativeModel(draft="safe draft", final="safe final")
        output, was_aborted, leaks = guarded_decode_with_details("test", model)

        assert output == "safe final"
        assert was_aborted is False
        assert leaks == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
