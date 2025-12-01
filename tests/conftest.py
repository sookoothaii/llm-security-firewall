"""
Central test fixtures for LLM Security Firewall.

This module provides shared fixtures for all test files.
"""

import pytest
import json
import os
from pathlib import Path
from unittest.mock import Mock, AsyncMock
from typing import List, Dict, Any

try:
    import fakeredis

    HAS_FAKEREDIS = True
except ImportError:
    HAS_FAKEREDIS = False
    fakeredis = None  # type: ignore


# Load adversarial test suite
@pytest.fixture(scope="session")
def adversarial_suite() -> List[Dict[str, Any]]:
    """Load all adversarial test vectors from JSONL file."""
    suite_path = Path(__file__).parent.parent / "data" / "gpt5_adversarial_suite.jsonl"

    if not suite_path.exists():
        pytest.skip(f"Adversarial suite not found: {suite_path}")

    test_cases = []
    with open(suite_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    test_cases.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    return test_cases


# Mock Redis fixtures
@pytest.fixture
def fake_redis():
    """In-memory Redis for unit tests (fakeredis)."""
    if not HAS_FAKEREDIS:
        pytest.skip("fakeredis not installed - run: pip install fakeredis")

    return fakeredis.FakeStrictRedis(decode_responses=True)


@pytest.fixture
def mock_redis_pool():
    """Mock TenantRedisPool for async tests."""
    pool = Mock()
    pool.get_tenant_client = AsyncMock()
    return pool


# Engine fixtures
@pytest.fixture
def firewall_engine():
    """FirewallEngineV2 instance with default config."""
    from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2

    return FirewallEngineV2()


@pytest.fixture
def firewall_engine_lenient():
    """FirewallEngineV2 instance in lenient mode."""
    from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2

    return FirewallEngineV2(strict_mode=False)


@pytest.fixture
def firewall_engine_with_tools():
    """FirewallEngineV2 instance with allowed tools."""
    from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2

    return FirewallEngineV2(allowed_tools=["read_file", "write_file"])


# Cache fixtures
@pytest.fixture
def cache_mode_exact(monkeypatch):
    """Set CACHE_MODE to 'exact'."""
    monkeypatch.setenv("CACHE_MODE", "exact")
    yield
    monkeypatch.delenv("CACHE_MODE", raising=False)


@pytest.fixture
def cache_mode_semantic(monkeypatch):
    """Set CACHE_MODE to 'semantic'."""
    monkeypatch.setenv("CACHE_MODE", "semantic")
    yield
    monkeypatch.delenv("CACHE_MODE", raising=False)


@pytest.fixture
def cache_mode_hybrid(monkeypatch):
    """Set CACHE_MODE to 'hybrid'."""
    monkeypatch.setenv("CACHE_MODE", "hybrid")
    yield
    monkeypatch.delenv("CACHE_MODE", raising=False)


# Test data fixtures
@pytest.fixture
def sample_malicious_inputs():
    """Sample malicious inputs for testing."""
    return [
        "'; DROP TABLE users; --",
        "<script>alert('XSS')</script>",
        "../../etc/passwd",
        "SELECT * FROM users WHERE id = 1 OR 1=1",
        "eval(base64_decode('...'))",
    ]


@pytest.fixture
def sample_legitimate_inputs():
    """Sample legitimate inputs for testing."""
    return [
        "What's the weather today?",
        "How do I reset my password?",
        "Tell me about machine learning",
        "What is Python?",
        "Explain recursion",
    ]


@pytest.fixture
def sample_tool_calls():
    """Sample tool calls for Protocol HEPHAESTUS testing."""
    return [
        {
            "type": "function",
            "function": {"name": "read_file", "arguments": '{"path": "test.txt"}'},
        },
        {
            "type": "function",
            "function": {
                "name": "write_file",
                "arguments": '{"path": "/etc/passwd", "content": "..."}',
            },
        },
    ]


# Environment fixtures
@pytest.fixture(autouse=True)
def reset_cache_mode(monkeypatch):
    """Reset CACHE_MODE to default after each test."""
    yield
    monkeypatch.delenv("CACHE_MODE", raising=False)


@pytest.fixture
def isolated_cache(monkeypatch):
    """Isolate cache by disabling it."""
    monkeypatch.setenv("CACHE_MODE", "none")
    yield
    monkeypatch.delenv("CACHE_MODE", raising=False)


# Redis Cloud fixtures
@pytest.fixture
def redis_cloud_available():
    """Check if Redis Cloud is available for integration tests."""
    return bool(os.getenv("REDIS_URL") or os.getenv("REDIS_CLOUD_HOST"))


@pytest.fixture(params=["exact", "semantic", "hybrid"])
def cache_mode(request, monkeypatch):
    """Parameterized fixture for testing all cache modes."""
    original_mode = os.getenv("CACHE_MODE")
    monkeypatch.setenv("CACHE_MODE", request.param)

    yield request.param

    # Restore original
    if original_mode:
        monkeypatch.setenv("CACHE_MODE", original_mode)
    else:
        monkeypatch.delenv("CACHE_MODE", raising=False)


# Test data fixtures (extended)
@pytest.fixture
def malicious_payloads():
    """Common malicious payloads for testing."""
    return {
        "sql_injection": "test' OR '1'='1",
        "path_traversal": "../../etc/passwd",
        "xss": "<script>alert('XSS')</script>",
        "command_injection": "; rm -rf /",
        "base64_encoded": "c2sgLWxpdmUgLUFCQ0RFRjEyMzQ1Njc4OTBhYmNkRUZHSA==",  # sk-live -ABCDEF1234567890abcdEFGH
    }


@pytest.fixture
def legitimate_payloads():
    """Common legitimate payloads for false positive testing."""
    return [
        "What's the weather today?",
        "How do I reset my password?",
        "Tell me about machine learning",
        "What is the capital of France?",
        "Can you help me with Python programming?",
    ]
