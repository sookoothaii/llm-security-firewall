"""
Integration tests using MCP Firewall Monitor for Redis access.

These tests use the MCP tools to verify Redis functionality,
which may have credentials configured separately from environment variables.
"""

import pytest
import os


@pytest.mark.integration
class TestRedisViaMCP:
    """Test Redis functionality via MCP Firewall Monitor tools."""

    def test_redis_status_via_mcp(self):
        """
        Test Redis status using MCP firewall_redis_status tool.

        This test verifies that Redis is accessible via MCP tools,
        even if environment variables are not set in test context.
        """
        # This test requires MCP tools to be available in Cursor
        # The MCP tool will use its own configuration

        # Note: This is a placeholder test that documents the expected behavior
        # Actual MCP tool calls should be made from Cursor, not from pytest

        print("\nRedis Status via MCP:")
        print("  Use MCP tool 'firewall_redis_status' in Cursor to check Redis")
        print(
            "  Expected: Connected, host: redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com"
        )

        # Skip this test in pytest (MCP tools are called from Cursor)
        pytest.skip("MCP tools are called from Cursor, not from pytest")

    def test_redis_connection_with_env_fallback(self):
        """
        Test Redis connection with environment variable fallback.

        If env vars are set, use them. Otherwise, document that
        MCP tools have separate configuration.
        """
        redis_host = os.getenv("REDIS_CLOUD_HOST") or os.getenv("REDIS_HOST")

        if redis_host:
            print(f"\nRedis configured via environment: {redis_host}")
            # Run actual connection test
            from llm_firewall.cache.decision_cache import get_cached, set_cached

            test_data = {
                "allowed": True,
                "reason": "MCP integration test",
                "risk_score": 0.0,
            }

            set_cached("mcp_test", "test_key", test_data, ttl=10)
            result = get_cached("mcp_test", "test_key")

            assert result is not None
            assert result["allowed"] is True
            print("PASS: Redis connection via environment variables")
        else:
            print("\nRedis not configured via environment variables")
            print("Note: MCP tools may have Redis configured separately")
            print("Use MCP tool 'firewall_redis_status' to verify Redis access")
            pytest.skip("Redis credentials not in environment (may be in MCP config)")
