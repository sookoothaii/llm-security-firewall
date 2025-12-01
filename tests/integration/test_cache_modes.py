"""
Test cache mode switching via CACHE_MODE env var.

This test suite validates that cache modes (exact, semantic, hybrid) work correctly.
"""

import pytest
from unittest.mock import patch
from llm_firewall.cache.decision_cache import get_cached


@pytest.mark.integration
class TestCacheModeSwitching:
    """Test CACHE_MODE=exact|semantic|hybrid switching."""

    def test_exact_cache_mode(self, cache_mode_exact):
        """Test exact cache mode (SHA-256 matching)."""
        with patch("llm_firewall.cache.decision_cache._get_exact_cached") as mock_exact:
            mock_exact.return_value = {
                "allowed": True,
                "reason": "cached",
                "risk_score": 0.0,
            }

            result = get_cached("tenant", "test input")

            assert result is not None
            assert result["allowed"] is True
            mock_exact.assert_called_once()

    def test_semantic_cache_mode(self, cache_mode_semantic):
        """Test semantic cache mode (miniLM cosine similarity)."""
        with patch(
            "llm_firewall.cache.decision_cache._get_semantic_cached"
        ) as mock_semantic:
            mock_semantic.return_value = {
                "allowed": False,
                "risk_score": 0.8,
                "reason": "semantic match",
            }

            result = get_cached("tenant", "test input")

            assert result is not None
            assert result["allowed"] is False
            mock_semantic.assert_called_once()

    def test_hybrid_cache_mode(self, cache_mode_hybrid):
        """Test hybrid cache mode (exact fallback to semantic)."""
        with patch("llm_firewall.cache.decision_cache._get_exact_cached") as mock_exact:
            with patch(
                "llm_firewall.cache.decision_cache._get_semantic_cached"
            ) as mock_semantic:
                # Exact cache miss -> semantic cache hit
                mock_exact.return_value = None
                mock_semantic.return_value = {
                    "allowed": True,
                    "reason": "semantic match",
                    "risk_score": 0.0,
                }

                result = get_cached("tenant", "test input")

                assert result is not None
                assert result["allowed"] is True
                mock_exact.assert_called_once()
                mock_semantic.assert_called_once()

    def test_cache_mode_zero_restart(self, monkeypatch):
        """Test cache mode switching without restart."""
        # Switch to semantic mode
        monkeypatch.setenv("CACHE_MODE", "semantic")

        # Should use semantic cache immediately
        with patch(
            "llm_firewall.cache.decision_cache._get_semantic_cached"
        ) as mock_semantic:
            mock_semantic.return_value = {
                "allowed": True,
                "reason": "dynamic switch",
                "risk_score": 0.0,
            }

            result = get_cached("tenant", "test input")

            assert result is not None
            mock_semantic.assert_called_once()

    def test_invalid_cache_mode_defaults_to_exact(self, monkeypatch):
        """Test that invalid CACHE_MODE defaults to 'exact'."""
        monkeypatch.setenv("CACHE_MODE", "invalid_mode")

        with patch("llm_firewall.cache.decision_cache._get_exact_cached") as mock_exact:
            mock_exact.return_value = {
                "allowed": True,
                "reason": "defaulted to exact",
                "risk_score": 0.0,
            }

            result = get_cached("tenant", "test input")

            assert result is not None
            # Should default to exact mode
            mock_exact.assert_called_once()

    def test_cache_mode_case_insensitive(self, monkeypatch):
        """Test that CACHE_MODE is case-insensitive."""
        monkeypatch.setenv("CACHE_MODE", "HYBRID")  # Uppercase

        with patch("llm_firewall.cache.decision_cache._get_exact_cached") as mock_exact:
            with patch(
                "llm_firewall.cache.decision_cache._get_semantic_cached"
            ) as mock_semantic:
                mock_exact.return_value = None
                mock_semantic.return_value = {
                    "allowed": True,
                    "reason": "case insensitive",
                    "risk_score": 0.0,
                }

                result = get_cached("tenant", "test input")

                assert result is not None
                # Should work with uppercase CACHE_MODE
                mock_semantic.assert_called_once()
