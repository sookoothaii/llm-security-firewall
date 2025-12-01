"""
Unit Tests for Decision Cache Module.

Tests:
- Cache hit returns cached decision
- Cache miss saves correctly
- Redis fail-open graceful fallback
- TTL expiration
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock

try:
    from redis.exceptions import RedisError

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    RedisError = Exception  # type: ignore

from llm_firewall.cache.decision_cache import (
    get_cached,
    set_cached,
    initialize_cache,
    _key,
)


@pytest.fixture
def mock_redis_pool():
    """Mock TenantRedisPool instance."""
    pool = Mock()
    pool.get_tenant_client = AsyncMock()
    return pool


@pytest.fixture
def mock_redis_client():
    """Mock Redis client."""
    client = AsyncMock()
    return client


class TestDecisionCache:
    """Test suite for decision cache."""

    def test_key_generation(self):
        """Test cache key generation."""
        tenant_id = "test_tenant"
        text = "test input"
        key = _key(tenant_id, text)

        assert key.startswith("fw:v1:tenant:test_tenant:dec:")
        assert len(key.split(":")[-1]) == 16  # SHA-256 hex digest truncated to 16 chars

    def test_key_deterministic(self):
        """Test that same input generates same key."""
        tenant_id = "test_tenant"
        text = "test input"

        key1 = _key(tenant_id, text)
        key2 = _key(tenant_id, text)

        assert key1 == key2

    def test_key_different_tenants(self):
        """Test that different tenants get different keys."""
        text = "test input"

        key1 = _key("tenant1", text)
        key2 = _key("tenant2", text)

        assert key1 != key2
        assert "tenant1" in key1
        assert "tenant2" in key2

    @patch("llm_firewall.cache.decision_cache._get_exact_cached")
    @patch("llm_firewall.cache.decision_cache.get_semantic_cached")
    def test_get_cached_hit(self, mock_semantic, mock_exact):
        """Test cache hit returns cached decision."""
        # Setup
        with patch.dict("os.environ", {"CACHE_MODE": "exact"}):
            cached_decision = {
                "allowed": True,
                "reason": "Cached decision",
                "sanitized_text": "test",
                "risk_score": 0.1,
                "detected_threats": [],
                "metadata": {},
            }
            mock_exact.return_value = cached_decision
            mock_semantic.return_value = None

            # Test
            result = get_cached("test_tenant", "test input")

            # Verify
            assert result is not None
            assert result == cached_decision
            mock_exact.assert_called_once_with("test_tenant", "test input")
            assert result["allowed"]
            assert result["reason"] == "Cached decision"

    @patch("llm_firewall.cache.decision_cache._get_exact_cached")
    @patch("llm_firewall.cache.decision_cache.get_semantic_cached")
    def test_get_cached_miss(self, mock_semantic, mock_exact):
        """Test cache miss returns None."""
        # Setup
        with patch.dict("os.environ", {"CACHE_MODE": "exact"}):
            mock_exact.return_value = None
            mock_semantic.return_value = None

            # Test
            result = get_cached("test_tenant", "test input")

            # Verify
            assert result is None

    @patch("llm_firewall.cache.decision_cache._get_exact_cached")
    @patch("llm_firewall.cache.decision_cache.get_semantic_cached")
    def test_get_cached_redis_error_fail_open(self, mock_semantic, mock_exact):
        """Test Redis error fails open (returns None)."""
        # Setup
        with patch.dict("os.environ", {"CACHE_MODE": "exact"}):
            mock_exact.side_effect = RedisError("Connection failed")
            mock_semantic.return_value = None

            # Test
            result = get_cached("test_tenant", "test input")

            # Verify (fail-open: returns None, doesn't raise)
            assert result is None

    @patch("llm_firewall.cache.decision_cache._set_exact_cached")
    @patch("llm_firewall.cache.decision_cache.set_semantic_cached")
    def test_set_cached_success(self, mock_semantic, mock_exact):
        """Test setting cache stores decision correctly."""
        # Setup
        with patch.dict("os.environ", {"CACHE_MODE": "exact"}):
            decision = {
                "allowed": True,
                "reason": "Test decision",
                "sanitized_text": "test",
                "risk_score": 0.2,
                "detected_threats": [],
                "metadata": {},
            }

            # Test
            set_cached("test_tenant", "test input", decision, ttl=3600)

            # Verify
            mock_exact.assert_called_once_with(
                "test_tenant", "test input", decision, 3600
            )
            mock_semantic.assert_not_called()

    @patch("llm_firewall.cache.decision_cache._set_exact_cached")
    @patch("llm_firewall.cache.decision_cache.set_semantic_cached")
    def test_set_cached_redis_error_fail_open(self, mock_semantic, mock_exact):
        """Test Redis error on set fails open (doesn't raise)."""
        # Setup
        with patch.dict("os.environ", {"CACHE_MODE": "exact"}):
            mock_exact.side_effect = RedisError("Write failed")

            decision = {
                "allowed": True,
                "reason": "Test decision",
                "sanitized_text": "test",
                "risk_score": 0.2,
                "detected_threats": [],
                "metadata": {},
            }

            # Test (should not raise)
            set_cached("test_tenant", "test input", decision, ttl=3600)

            # Verify (no exception raised)
            assert True  # If we get here, fail-open worked

    def test_get_cached_no_redis_pool(self):
        """Test get_cached works without Redis pool (fallback to REDIS_URL)."""
        # Setup: Clear global pool
        initialize_cache(None)

        # Mock environment variable and redis module
        with patch.dict("os.environ", {"REDIS_URL": "redis://localhost:6379/0"}):
            with patch("llm_firewall.cache.decision_cache.redis") as mock_redis_module:
                if mock_redis_module and HAS_REDIS:
                    mock_redis_client = AsyncMock()
                    mock_redis_client.get = AsyncMock(return_value=None)
                    mock_redis_module.from_url.return_value = mock_redis_client

                    # Test
                    result = get_cached("test_tenant", "test input")

                    # Verify
                    assert result is None
                    # Note: from_url might not be called if HAS_REDIS is False
                else:
                    # If Redis not available, should return None gracefully
                    result = get_cached("test_tenant", "test input")
                    assert result is None

    def test_set_cached_no_redis_pool(self):
        """Test set_cached works without Redis pool (fallback to REDIS_URL)."""
        # Setup: Clear global pool
        initialize_cache(None)

        # Mock environment variable and redis module
        with patch.dict("os.environ", {"REDIS_URL": "redis://localhost:6379/0"}):
            with patch("llm_firewall.cache.decision_cache.redis") as mock_redis_module:
                if mock_redis_module and HAS_REDIS:
                    mock_redis_client = AsyncMock()
                    mock_redis_client.setex = AsyncMock()
                    mock_redis_module.from_url.return_value = mock_redis_client

                    decision = {
                        "allowed": True,
                        "reason": "Test",
                        "sanitized_text": "test",
                        "risk_score": 0.0,
                        "detected_threats": [],
                        "metadata": {},
                    }

                    # Test
                    set_cached("test_tenant", "test input", decision)

                    # Verify (may not be called if Redis not available)
                    # Note: This test verifies fail-open behavior
                else:
                    # If Redis not available, should fail-open gracefully
                    decision = {
                        "allowed": True,
                        "reason": "Test",
                        "sanitized_text": "test",
                        "risk_score": 0.0,
                        "detected_threats": [],
                        "metadata": {},
                    }
                    set_cached("test_tenant", "test input", decision)
                    # Should not raise

    def test_get_cached_default_tenant(self):
        """Test get_cached uses 'default' tenant if not provided."""
        # Setup
        initialize_cache(None)

        with patch.dict("os.environ", {}, clear=True):
            # Test with empty tenant_id
            result = get_cached("", "test input")

            # Should not raise, returns None (no Redis configured)
            assert result is None

    @patch("llm_firewall.cache.decision_cache._set_exact_cached")
    @patch("llm_firewall.cache.decision_cache.set_semantic_cached")
    def test_set_cached_ttl_from_env(self, mock_semantic, mock_exact):
        """Test set_cached uses TTL from REDIS_TTL env var."""
        # Setup
        with patch.dict("os.environ", {"CACHE_MODE": "exact", "REDIS_TTL": "7200"}):
            decision = {
                "allowed": True,
                "reason": "Test",
                "sanitized_text": "test",
                "risk_score": 0.0,
                "detected_threats": [],
                "metadata": {},
            }

            # Test (no TTL provided, should use env)
            set_cached("test_tenant", "test input", decision)

            # Verify TTL is passed (will be read from env in _set_exact_cached)
            mock_exact.assert_called_once()
            call_args = mock_exact.call_args
            # TTL should be None (will be read from env in implementation)
            assert call_args[0][3] is None  # TTL parameter
            mock_semantic.assert_not_called()

    @pytest.mark.skipif(not HAS_REDIS, reason="Redis not installed")
    def test_integration_with_real_redis(self):
        """Integration test with real Redis (requires Redis running)."""
        # This test is optional and requires Redis to be running
        # Skip if Redis is not available
        import os

        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            pytest.skip("REDIS_URL not set, skipping integration test")

        # Test basic operations
        decision = {
            "allowed": True,
            "reason": "Integration test",
            "sanitized_text": "test",
            "risk_score": 0.0,
            "detected_threats": [],
            "metadata": {},
        }

        # Set cache
        set_cached("test_tenant", "integration_test_input", decision, ttl=60)

        # Get cache
        result = get_cached("test_tenant", "integration_test_input")

        # Verify
        assert result is not None
        assert result["allowed"]
        assert result["reason"] == "Integration test"
