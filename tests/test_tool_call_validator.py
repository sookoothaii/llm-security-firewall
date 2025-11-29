"""
Tests for Protocol HEPHAESTUS: Tool Call Validator
===================================================

Tests the core functionality of the ToolCallValidator:
- Whitelist enforcement
- SQL Injection detection
- Path Traversal detection
- RCE detection
- Argument sanitization
"""

import pytest
from llm_firewall.detectors.tool_call_validator import (
    ToolCallValidator,
)


@pytest.fixture
def validator():
    """Create a validator with default safe tools."""
    return ToolCallValidator(
        allowed_tools=["web_search", "calculator", "text_analysis"],
        strict_mode=True,
        enable_sanitization=True,
    )


@pytest.fixture
def lenient_validator():
    """Create a validator in lenient mode (sanitizes instead of blocking)."""
    return ToolCallValidator(
        allowed_tools=["web_search", "calculator", "text_analysis"],
        strict_mode=False,
        enable_sanitization=True,
    )


def test_whitelist_enforcement(validator):
    """Test that only whitelisted tools are allowed."""
    # Allowed tool
    result = validator.validate_tool_call("web_search", {"query": "test"})
    assert result.allowed is True
    assert "whitelist" not in result.reason.lower()

    # Blocked tool (not in whitelist)
    result = validator.validate_tool_call("delete_file", {"path": "/tmp/test.txt"})
    assert result.allowed is False
    assert "whitelist" in result.reason.lower()
    assert "unauthorized_tool" in result.detected_threats


def test_sql_injection_detection(validator):
    """Test SQL injection detection in query arguments."""
    # SQL injection in query argument
    result = validator.validate_tool_call("web_search", {"query": "test' OR '1'='1"})
    assert result.allowed is False
    assert "sql_injection" in result.detected_threats

    # SQL injection with UNION
    result = validator.validate_tool_call(
        "web_search", {"query": "test UNION SELECT * FROM users"}
    )
    assert result.allowed is False
    assert "sql_injection" in result.detected_threats

    # Safe query (no SQL injection)
    result = validator.validate_tool_call(
        "web_search", {"query": "normal search query"}
    )
    assert result.allowed is True
    assert "sql_injection" not in result.detected_threats


def test_path_traversal_detection(validator):
    """Test path traversal detection in file/path arguments."""
    # Path traversal in file argument
    result = validator.validate_tool_call("text_analysis", {"file": "../../etc/passwd"})
    assert result.allowed is False
    assert "path_traversal" in result.detected_threats

    # Windows path traversal
    result = validator.validate_tool_call(
        "text_analysis", {"file": "..\\..\\Windows\\System32"}
    )
    assert result.allowed is False
    assert "path_traversal" in result.detected_threats

    # Safe path (no traversal)
    result = validator.validate_tool_call(
        "text_analysis", {"file": "/tmp/safe_file.txt"}
    )
    assert result.allowed is True
    assert "path_traversal" not in result.detected_threats


def test_rce_detection(validator):
    """Test RCE detection in code/command arguments."""
    # RCE in code argument
    result = validator.validate_tool_call(
        "calculator", {"code": "os.system('rm -rf /')"}
    )
    assert result.allowed is False
    assert "rce" in result.detected_threats

    # RCE with subprocess
    result = validator.validate_tool_call(
        "calculator", {"command": "subprocess.call(['rm', '-rf', '/'])"}
    )
    assert result.allowed is False
    assert "rce" in result.detected_threats

    # Safe code (no RCE)
    result = validator.validate_tool_call("calculator", {"expression": "2 + 2"})
    assert result.allowed is True
    assert "rce" not in result.detected_threats


def test_argument_sanitization(lenient_validator):
    """Test argument sanitization in lenient mode."""
    # SQL injection should be sanitized (not blocked)
    result = lenient_validator.validate_tool_call(
        "web_search", {"query": "test' OR '1'='1"}
    )
    assert result.allowed is True  # Lenient mode allows after sanitization
    assert "sql_injection" in result.detected_threats
    assert result.sanitized_args["query"] != "test' OR '1'='1"  # Should be sanitized

    # Path traversal should be sanitized
    result = lenient_validator.validate_tool_call(
        "text_analysis", {"file": "../../etc/passwd"}
    )
    assert result.allowed is True
    assert "path_traversal" in result.detected_threats
    assert "../" not in result.sanitized_args["file"]  # Should be removed


def test_no_arguments(validator):
    """Test tool call with no arguments."""
    result = validator.validate_tool_call("web_search", {})
    assert result.allowed is True
    assert result.risk_score == 0.0


def test_multiple_threats(validator):
    """Test tool call with multiple threat types."""
    result = validator.validate_tool_call(
        "web_search",
        {
            "query": "test' OR '1'='1",  # SQL injection
            "file": "../../etc/passwd",  # Path traversal
        },
    )
    assert result.allowed is False
    assert "sql_injection" in result.detected_threats
    assert "path_traversal" in result.detected_threats
    assert result.risk_score >= 0.8  # High risk due to multiple threats


def test_context_aware_detection(validator):
    """Test that detection is context-aware (checks argument names)."""
    # SQL injection in "query" argument (should be detected)
    result = validator.validate_tool_call("web_search", {"query": "test' OR '1'='1"})
    assert "sql_injection" in result.detected_threats

    # Same SQL pattern in non-SQL argument (should still be detected via generic check)
    result = validator.validate_tool_call("web_search", {"text": "test' OR '1'='1"})
    # Generic threat detection should still catch this
    assert result.risk_score > 0.0


def test_add_remove_tool(validator):
    """Test dynamic whitelist management."""
    # Initially blocked
    result = validator.validate_tool_call("new_tool", {"arg": "value"})
    assert result.allowed is False

    # Add to whitelist
    validator.add_allowed_tool("new_tool")
    result = validator.validate_tool_call("new_tool", {"arg": "value"})
    assert result.allowed is True

    # Remove from whitelist
    validator.remove_allowed_tool("new_tool")
    result = validator.validate_tool_call("new_tool", {"arg": "value"})
    assert result.allowed is False


def test_sanitized_args_structure(validator):
    """Test that sanitized_args has the same structure as input arguments."""
    result = validator.validate_tool_call(
        "web_search",
        {
            "query": "test' OR '1'='1",
            "limit": 10,
        },
    )
    # Even if blocked, sanitized_args should have the same keys
    assert "query" in result.sanitized_args
    assert "limit" in result.sanitized_args


def test_default_safe_tools():
    """Test that default safe tools are used when no whitelist provided."""
    validator = ToolCallValidator()  # No whitelist provided
    result = validator.validate_tool_call("web_search", {"query": "test"})
    assert result.allowed is True  # web_search is in default safe tools

    result = validator.validate_tool_call("delete_file", {"path": "/tmp/test.txt"})
    assert result.allowed is False  # delete_file is not in default safe tools
