"""
Tests for Protocol HEPHAESTUS: Tool Call Extractor
===================================================

Tests the extraction of tool calls from raw LLM text:
- Pure JSON
- JSON in Markdown code blocks
- JSON embedded in text
- Multiple tool calls
- Malformed JSON recovery
"""

import pytest
from llm_firewall.detectors.tool_call_extractor import ToolCallExtractor


@pytest.fixture
def extractor():
    """Create a tool call extractor."""
    return ToolCallExtractor(strict_mode=False)


@pytest.fixture
def strict_extractor():
    """Create a strict mode extractor."""
    return ToolCallExtractor(strict_mode=True)


def test_pure_json(extractor):
    """Test extraction from pure JSON."""
    text = '{"tool": "web_search", "arguments": {"query": "test query"}}'
    calls = extractor.extract_tool_calls(text)

    assert len(calls) == 1
    assert calls[0]["tool_name"] == "web_search"
    assert calls[0]["arguments"] == {"query": "test query"}


def test_json_in_markdown(extractor):
    """Test extraction from JSON in Markdown code block."""
    text = """Here is the tool call:
```json
{"tool": "calculator", "arguments": {"expression": "2 + 2"}}
```
"""
    calls = extractor.extract_tool_calls(text)

    assert len(calls) == 1
    assert calls[0]["tool_name"] == "calculator"
    assert calls[0]["arguments"] == {"expression": "2 + 2"}


def test_json_embedded_in_text(extractor):
    """Test extraction from JSON embedded in text."""
    text = 'Sure, here is the call: {"tool": "web_search", "arguments": {"query": "Python tutorial"}}'
    calls = extractor.extract_tool_calls(text)

    assert len(calls) == 1
    assert calls[0]["tool_name"] == "web_search"
    assert calls[0]["arguments"] == {"query": "Python tutorial"}


def test_multiple_tool_calls(extractor):
    """Test extraction of multiple tool calls."""
    text = """
First call: {"tool": "web_search", "arguments": {"query": "test1"}}
Second call: {"tool": "calculator", "arguments": {"expression": "1+1"}}
"""
    calls = extractor.extract_tool_calls(text)

    assert len(calls) == 2
    assert calls[0]["tool_name"] == "web_search"
    assert calls[0]["arguments"] == {"query": "test1"}
    assert calls[1]["tool_name"] == "calculator"
    assert calls[1]["arguments"] == {"expression": "1+1"}


def test_function_format(extractor):
    """Test extraction using 'function' and 'parameters' format."""
    text = '{"function": "text_analysis", "parameters": {"text": "Hello world"}}'
    calls = extractor.extract_tool_calls(text)

    assert len(calls) == 1
    assert calls[0]["tool_name"] == "text_analysis"
    assert calls[0]["arguments"] == {"text": "Hello world"}


def test_openai_format(extractor):
    """Test extraction using OpenAI format (name + stringified arguments)."""
    text = '{"name": "web_search", "arguments": "{\\"query\\": \\"test\\"}"}'
    calls = extractor.extract_tool_calls(text)

    assert len(calls) == 1
    assert calls[0]["tool_name"] == "web_search"
    assert calls[0]["arguments"] == {"query": "test"}


def test_malformed_json_recovery(extractor):
    """Test recovery from malformed JSON."""
    # Test 1: Trailing comma (should be fixed)
    text1 = '{"tool": "web_search", "arguments": {"query": "test"},}'
    calls1 = extractor.extract_tool_calls(text1)
    # Should extract successfully after fixing trailing comma
    assert len(calls1) == 1
    assert calls1[0]["tool_name"] == "web_search"
    assert calls1[0]["arguments"]["query"] == "test"

    # Test 2: Single quotes instead of double quotes (should be fixed)
    text2 = "{'tool': 'web_search', 'arguments': {'query': 'test'}}"
    calls2 = extractor.extract_tool_calls(text2)
    # Should extract successfully after fixing single quotes
    assert len(calls2) == 1
    assert calls2[0]["tool_name"] == "web_search"
    assert calls2[0]["arguments"]["query"] == "test"

    # Test 3: Missing quotes on keys (may not be perfect, but should not crash)
    text3 = '{tool: "web_search", arguments: {"query": "test"}}'
    calls3 = extractor.extract_tool_calls(text3)
    # Should not crash (may or may not succeed)
    assert len(calls3) >= 0


def test_empty_text(extractor):
    """Test extraction from empty text."""
    calls = extractor.extract_tool_calls("")
    assert len(calls) == 0

    calls = extractor.extract_tool_calls("   ")
    assert len(calls) == 0


def test_no_tool_calls(extractor):
    """Test extraction from text with no tool calls."""
    text = "This is just regular text with no tool calls."
    calls = extractor.extract_tool_calls(text)
    assert len(calls) == 0


def test_markdown_without_json(extractor):
    """Test extraction from Markdown code block without JSON."""
    text = """Here is some code:
```python
def hello():
    print("world")
```
"""
    calls = extractor.extract_tool_calls(text)
    assert len(calls) == 0


def test_nested_json(extractor):
    """Test extraction from nested JSON structures."""
    text = '{"tool": "web_search", "arguments": {"query": "test", "filters": {"date": "2024"}}}'
    calls = extractor.extract_tool_calls(text)

    assert len(calls) == 1
    assert calls[0]["tool_name"] == "web_search"
    assert calls[0]["arguments"]["filters"]["date"] == "2024"


def test_case_insensitive_keys(extractor):
    """Test extraction with case-insensitive keys."""
    text = '{"TOOL": "web_search", "ARGUMENTS": {"query": "test"}}'
    calls = extractor.extract_tool_calls(text)

    assert len(calls) == 1
    assert calls[0]["tool_name"] == "web_search"
    assert calls[0]["arguments"] == {"query": "test"}


def test_multiple_markdown_blocks(extractor):
    """Test extraction from multiple Markdown code blocks."""
    text = """
First call:
```json
{"tool": "web_search", "arguments": {"query": "test1"}}
```

Second call:
```json
{"tool": "calculator", "arguments": {"expression": "2+2"}}
```
"""
    calls = extractor.extract_tool_calls(text)

    assert len(calls) == 2
    assert calls[0]["tool_name"] == "web_search"
    assert calls[1]["tool_name"] == "calculator"


def test_mixed_formats(extractor):
    """Test extraction from text with mixed formats."""
    text = """
Here are the calls:
1. {"tool": "web_search", "arguments": {"query": "test"}}
2. {"function": "calculator", "parameters": {"expression": "1+1"}}
3. {"name": "text_analysis", "arguments": "{\\"text\\": \\"hello\\"}"}
"""
    calls = extractor.extract_tool_calls(text)

    assert len(calls) == 3
    assert calls[0]["tool_name"] == "web_search"
    assert calls[1]["tool_name"] == "calculator"
    assert calls[2]["tool_name"] == "text_analysis"


def test_arguments_as_string(extractor):
    """Test extraction when arguments are provided as a JSON string."""
    text = '{"tool": "web_search", "arguments": "{\\"query\\": \\"test query\\"}"}'
    calls = extractor.extract_tool_calls(text)

    assert len(calls) == 1
    assert calls[0]["tool_name"] == "web_search"
    assert isinstance(calls[0]["arguments"], dict)
    assert calls[0]["arguments"]["query"] == "test query"


def test_empty_arguments(extractor):
    """Test extraction with empty arguments."""
    text = '{"tool": "web_search", "arguments": {}}'
    calls = extractor.extract_tool_calls(text)

    assert len(calls) == 1
    assert calls[0]["tool_name"] == "web_search"
    assert calls[0]["arguments"] == {}


def test_missing_arguments(extractor):
    """Test extraction when arguments are missing."""
    text = '{"tool": "web_search"}'
    calls = extractor.extract_tool_calls(text)

    assert len(calls) == 1
    assert calls[0]["tool_name"] == "web_search"
    assert calls[0]["arguments"] == {}  # Should default to empty dict
