"""
Unit Tests for Hybrid Cache (Exact + Semantic)
==============================================

Tests hybrid cache mode with Redis (exact) and LangCache (semantic).
"""

import unittest
from unittest.mock import patch
import os
import sys
from pathlib import Path

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from llm_firewall.cache.decision_cache import (
    get_hybrid_cached,
    set_hybrid_cached,
    _get_cache_mode,
)


class TestHybridCache(unittest.TestCase):
    """Test hybrid cache functionality."""

    def setUp(self):
        """Set up test environment."""
        # Clear environment variables
        for key in ["CACHE_MODE", "LANGCACHE_API_KEY", "REDIS_CLOUD_HOST"]:
            if key in os.environ:
                del os.environ[key]

    def test_cache_mode_exact(self):
        """Test CACHE_MODE=exact uses only Redis."""
        with patch.dict(os.environ, {"CACHE_MODE": "exact"}):
            mode = _get_cache_mode()
            self.assertEqual(mode, "exact")

    def test_cache_mode_semantic(self):
        """Test CACHE_MODE=semantic uses only LangCache."""
        with patch.dict(os.environ, {"CACHE_MODE": "semantic"}):
            mode = _get_cache_mode()
            self.assertEqual(mode, "semantic")

    def test_cache_mode_hybrid(self):
        """Test CACHE_MODE=hybrid uses both."""
        with patch.dict(os.environ, {"CACHE_MODE": "hybrid"}):
            mode = _get_cache_mode()
            self.assertEqual(mode, "hybrid")

    def test_cache_mode_default(self):
        """Test default CACHE_MODE is exact."""
        mode = _get_cache_mode()
        self.assertEqual(mode, "exact")

    @patch("llm_firewall.cache.decision_cache._get_exact_cached")
    @patch("llm_firewall.cache.decision_cache.get_semantic_cached")
    def test_hybrid_get_exact_hit(self, mock_semantic, mock_exact):
        """Test hybrid get: exact hit returns immediately."""
        with patch.dict(os.environ, {"CACHE_MODE": "hybrid"}):
            mock_exact.return_value = {"allowed": True, "reason": "Cached"}
            mock_semantic.return_value = None

            result = get_hybrid_cached("test_tenant", "test text")

            self.assertEqual(result, {"allowed": True, "reason": "Cached"})
            mock_exact.assert_called_once_with("test_tenant", "test text")
            mock_semantic.assert_not_called()

    @patch("llm_firewall.cache.decision_cache._get_exact_cached")
    @patch("llm_firewall.cache.decision_cache.get_semantic_cached")
    def test_hybrid_get_semantic_hit(self, mock_semantic, mock_exact):
        """Test hybrid get: exact miss, semantic hit."""
        with patch.dict(os.environ, {"CACHE_MODE": "hybrid"}):
            mock_exact.return_value = None
            mock_semantic.return_value = {"allowed": True, "reason": "Semantic cached"}

            result = get_hybrid_cached("test_tenant", "test text")

            self.assertEqual(result, {"allowed": True, "reason": "Semantic cached"})
            mock_exact.assert_called_once()
            mock_semantic.assert_called_once_with("test text", "test_tenant")

    @patch("llm_firewall.cache.decision_cache._get_exact_cached")
    @patch("llm_firewall.cache.decision_cache.get_semantic_cached")
    def test_hybrid_get_miss(self, mock_semantic, mock_exact):
        """Test hybrid get: both miss."""
        with patch.dict(os.environ, {"CACHE_MODE": "hybrid"}):
            mock_exact.return_value = None
            mock_semantic.return_value = None

            result = get_hybrid_cached("test_tenant", "test text")

            self.assertIsNone(result)
            mock_exact.assert_called_once()
            mock_semantic.assert_called_once()

    @patch("llm_firewall.cache.decision_cache._set_exact_cached")
    @patch("llm_firewall.cache.decision_cache.set_semantic_cached")
    def test_hybrid_set_both(self, mock_semantic, mock_exact):
        """Test hybrid set: writes to both caches."""
        with patch.dict(os.environ, {"CACHE_MODE": "hybrid"}):
            decision = {"allowed": True, "reason": "Test"}

            set_hybrid_cached("test_tenant", "test text", decision)

            mock_exact.assert_called_once_with(
                "test_tenant", "test text", decision, None
            )
            mock_semantic.assert_called_once_with(
                "test text", decision, "test_tenant", None
            )

    @patch("llm_firewall.cache.decision_cache._set_exact_cached")
    @patch("llm_firewall.cache.decision_cache.set_semantic_cached")
    def test_exact_mode_only_redis(self, mock_semantic, mock_exact):
        """Test exact mode: only writes to Redis."""
        with patch.dict(os.environ, {"CACHE_MODE": "exact"}):
            decision = {"allowed": True, "reason": "Test"}

            set_hybrid_cached("test_tenant", "test text", decision)

            mock_exact.assert_called_once()
            mock_semantic.assert_not_called()

    @patch("llm_firewall.cache.decision_cache._set_exact_cached")
    @patch("llm_firewall.cache.decision_cache.set_semantic_cached")
    def test_semantic_mode_only_langcache(self, mock_semantic, mock_exact):
        """Test semantic mode: only writes to LangCache."""
        with patch.dict(os.environ, {"CACHE_MODE": "semantic"}):
            decision = {"allowed": True, "reason": "Test"}

            set_hybrid_cached("test_tenant", "test text", decision)

            mock_exact.assert_not_called()
            mock_semantic.assert_called_once()


if __name__ == "__main__":
    unittest.main()
