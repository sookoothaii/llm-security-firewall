"""
Tests for HAK_GAL Core Engine v2 - Protocol HEPHAESTUS Integration
===================================================================

Tests the tool call validation in process_output() method.
"""

import pytest
from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2


@pytest.fixture
def engine():
    """Create a firewall engine with default safe tools."""
    return FirewallEngineV2(
        allowed_tools=["web_search", "calculator", "text_analysis"],
        strict_mode=True,
        enable_sanitization=True,
    )


@pytest.fixture
def lenient_engine():
    """Create a firewall engine in lenient mode."""
    return FirewallEngineV2(
        allowed_tools=["web_search", "calculator"],
        strict_mode=False,
        enable_sanitization=True,
    )


def test_rce_tool_call_blocked(engine):
    """
    Test that RCE tool calls are blocked (Protocol HEPHAESTUS).

    Scenario:
    - LLM Output: "I will run this command: {"tool": "execute", "arguments": {"cmd": "rm -rf /"}}"
    - Expected: BLOCK (RCE detection in ToolCallValidator)
    """
    llm_output = (
        'I will run this command: {"tool": "execute", "arguments": {"cmd": "rm -rf /"}}'
    )

    decision = engine.process_output(llm_output, user_id="test_user")

    assert decision.allowed is False
    assert "blocked" in decision.reason.lower() or "rce" in decision.reason.lower()
    assert decision.risk_score > 0.0
    assert len(decision.detected_threats) > 0
    assert "execute" in decision.metadata.get("blocked_tool", "")


def test_unauthorized_tool_blocked(engine):
    """Test that unauthorized tools are blocked."""
    llm_output = '{"tool": "delete_file", "arguments": {"path": "/tmp/test.txt"}}'

    decision = engine.process_output(llm_output, user_id="test_user")

    assert decision.allowed is False
    assert "whitelist" in decision.reason.lower() or "not in" in decision.reason.lower()
    assert "delete_file" in decision.metadata.get("blocked_tool", "")


def test_allowed_tool_passes(engine):
    """Test that allowed tools with safe arguments pass validation."""
    llm_output = '{"tool": "web_search", "arguments": {"query": "Python tutorial"}}'

    decision = engine.process_output(llm_output, user_id="test_user")

    assert decision.allowed is True
    assert decision.risk_score == 0.0
    assert len(decision.detected_threats) == 0
    assert "web_search" in decision.metadata.get("tool_calls", [{}])[0].get(
        "tool_name", ""
    )


def test_sql_injection_in_tool_args_blocked(engine):
    """Test that SQL injection in tool arguments is blocked."""
    llm_output = '{"tool": "web_search", "arguments": {"query": "test\' OR \'1\'=\'1"}}'

    decision = engine.process_output(llm_output, user_id="test_user")

    assert decision.allowed is False
    assert "sql" in decision.reason.lower() or "injection" in decision.reason.lower()
    assert decision.risk_score > 0.0


def test_path_traversal_in_tool_args_blocked(engine):
    """Test that path traversal in tool arguments is blocked."""
    llm_output = '{"tool": "text_analysis", "arguments": {"file": "../../etc/passwd"}}'

    decision = engine.process_output(llm_output, user_id="test_user")

    assert decision.allowed is False
    assert "path" in decision.reason.lower() or "traversal" in decision.reason.lower()
    assert decision.risk_score > 0.0


def test_multiple_tool_calls_all_blocked(engine):
    """Test that if any tool call is blocked, entire response is blocked."""
    llm_output = """
    First: {"tool": "web_search", "arguments": {"query": "test"}}
    Second: {"tool": "execute", "arguments": {"cmd": "rm -rf /"}}
    """

    decision = engine.process_output(llm_output, user_id="test_user")

    assert decision.allowed is False
    # Should block on the second (malicious) tool call
    assert "execute" in decision.metadata.get("blocked_tool", "")


def test_multiple_tool_calls_all_allowed(engine):
    """Test that multiple allowed tool calls all pass."""
    llm_output = """
    First: {"tool": "web_search", "arguments": {"query": "test1"}}
    Second: {"tool": "calculator", "arguments": {"expression": "2+2"}}
    """

    decision = engine.process_output(llm_output, user_id="test_user")

    assert decision.allowed is True
    assert len(decision.metadata.get("tool_calls", [])) == 2


def test_plain_text_output_allowed(engine):
    """Test that plain text output (no tool calls) is allowed."""
    llm_output = "This is just regular text with no tool calls."

    decision = engine.process_output(llm_output, user_id="test_user")

    assert decision.allowed is True
    assert decision.risk_score == 0.0
    assert "no tool calls" in decision.reason.lower()


def test_tool_call_in_markdown_blocked(engine):
    """Test that tool calls in Markdown code blocks are detected and blocked."""
    llm_output = """
    Here is the tool call:
    ```json
    {"tool": "execute", "arguments": {"cmd": "rm -rf /"}}
    ```
    """

    decision = engine.process_output(llm_output, user_id="test_user")

    assert decision.allowed is False
    assert "execute" in decision.metadata.get("blocked_tool", "")


def test_sanitized_args_replacement(lenient_engine):
    """Test that sanitized arguments are replaced in lenient mode."""
    # Use lenient engine (sanitizes instead of blocking)
    llm_output = '{"tool": "web_search", "arguments": {"query": "test\' OR \'1\'=\'1"}}'

    decision = lenient_engine.process_output(llm_output, user_id="test_user")

    # In lenient mode, should allow but sanitize
    assert decision.allowed is True
    assert decision.sanitized_text is not None
    # Sanitized text should not contain SQL injection pattern
    assert "' OR '1'='1" not in decision.sanitized_text


def test_empty_output(engine):
    """Test that empty output is allowed."""
    decision = engine.process_output("", user_id="test_user")

    assert decision.allowed is True
    assert decision.sanitized_text == ""


def test_input_processing(engine):
    """Test that process_input() works (basic test)."""
    decision = engine.process_input(user_id="test_user", text="Hello, world!")

    assert decision.allowed is True
    assert decision.sanitized_text is not None
    assert "Hello" in decision.sanitized_text
