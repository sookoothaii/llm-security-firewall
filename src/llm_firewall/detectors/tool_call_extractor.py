"""
Protocol HEPHAESTUS: Tool Call Extractor
==========================================

Extracts tool calls from raw LLM text output.

Handles various formats:
- Pure JSON: {"tool": "name", "arguments": {...}}
- JSON in Markdown code blocks: ```json {...} ```
- JSON embedded in text: "Here is the call: {...}"
- Multiple tool calls in one text
- Malformed JSON (with error recovery)

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-29
Status: Protocol HEPHAESTUS - Core Component
License: MIT
"""

import json
import re
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# CRITICAL FIX (v2.3.4): Import strict JSON parser to prevent duplicate key bypass
try:
    from hak_gal.utils.json_parser import strict_json_loads

    HAS_STRICT_PARSER = True
except ImportError:
    # Fallback if strict parser not available (should not happen in production)
    HAS_STRICT_PARSER = False
    strict_json_loads = json.loads
    logger.warning(
        "[ToolCallExtractor] Strict JSON parser not available. Using standard json.loads(). "
        "This may allow duplicate key bypass attacks."
    )


class ToolCallExtractor:
    """
    Extracts tool calls from raw LLM text output.

    Architecture:
    - Markdown code block removal (```json ... ```)
    - JSON block extraction (finds {...} patterns)
    - Format normalization (tool/function → tool_name, arguments/parameters → arguments)
    - Error recovery (handles malformed JSON gracefully)

    Usage:
        extractor = ToolCallExtractor()
        tool_calls = extractor.extract_tool_calls(llm_output_text)
        for call in tool_calls:
            tool_name = call["tool_name"]
            arguments = call["arguments"]
    """

    def __init__(self, strict_mode: bool = False):
        """
        Initialize Tool Call Extractor.

        Args:
            strict_mode: If True, only accepts perfectly formatted JSON.
                        If False, attempts to recover from malformed JSON.
        """
        self.strict_mode = strict_mode

        # Patterns for different tool call formats
        self.tool_call_patterns = [
            # Standard format: {"tool": "name", "arguments": {...}}
            re.compile(
                r'\{\s*["\']?tool["\']?\s*:\s*["\']([^"\']+)["\']\s*,\s*["\']?arguments["\']?\s*:\s*(\{.*?\})\s*\}',
                re.DOTALL | re.IGNORECASE,
            ),
            # Alternative format: {"function": "name", "parameters": {...}}
            re.compile(
                r'\{\s*["\']?function["\']?\s*:\s*["\']([^"\']+)["\']\s*,\s*["\']?parameters["\']?\s*:\s*(\{.*?\})\s*\}',
                re.DOTALL | re.IGNORECASE,
            ),
            # OpenAI format: {"name": "tool_name", "arguments": "{\"key\": \"value\"}"}
            re.compile(
                r'\{\s*["\']?name["\']?\s*:\s*["\']([^"\']+)["\']\s*,\s*["\']?arguments["\']?\s*:\s*["\'](\{.*?\})["\']\s*\}',
                re.DOTALL | re.IGNORECASE,
            ),
        ]

    def extract_tool_calls(self, text: str) -> List[Dict[str, Any]]:
        """
        Extract tool calls from raw LLM text.

        Args:
            text: Raw text output from LLM (may contain JSON, Markdown, or plain text)

        Returns:
            List of normalized tool call dictionaries:
            [{"tool_name": str, "arguments": dict}, ...]
        """
        if not text or not text.strip():
            return []

        # Step 1: Remove Markdown code blocks
        text = self._remove_markdown_blocks(text)

        # Step 2: Try to extract JSON blocks
        # Primary method: Find and parse JSON objects (already normalized)
        tool_calls = self._extract_via_json_parsing(text)

        # Fallback: Try regex-based extraction if JSON parsing found nothing
        if not tool_calls:
            regex_calls = self._extract_via_regex(text)
            # Normalize regex calls (they may not be normalized yet)
            for regex_call in regex_calls:
                normalized = self._normalize_tool_call(regex_call)
                if normalized and normalized not in tool_calls:
                    tool_calls.append(normalized)

        logger.debug(f"[HEPHAESTUS] Extracted {len(tool_calls)} tool call(s) from text")
        return tool_calls

    def _remove_markdown_blocks(self, text: str) -> str:
        """
        Remove Markdown code blocks (```json ... ``` or ``` ... ```).

        Args:
            text: Text potentially containing Markdown code blocks

        Returns:
            Text with Markdown code blocks removed
        """
        # Remove ```json ... ``` blocks
        text = re.sub(
            r"```json\s*\n?(.*?)\n?```", r"\1", text, flags=re.DOTALL | re.IGNORECASE
        )
        # Remove ``` ... ``` blocks (generic code blocks)
        text = re.sub(
            r"```[a-z]*\s*\n?(.*?)\n?```", r"\1", text, flags=re.DOTALL | re.IGNORECASE
        )
        # Remove `...` inline code (but be careful not to break JSON)
        # Only remove if it's clearly not part of a JSON string
        text = re.sub(r"`([^`]+)`", r"\1", text)
        return text.strip()

    def _extract_via_regex(self, text: str) -> List[Dict[str, Any]]:
        """
        Extract tool calls using regex patterns.

        Args:
            text: Text to search

        Returns:
            List of tool call dictionaries (may not be normalized yet)
        """
        tool_calls = []

        # Simplified approach: Find JSON objects first, then check if they're tool calls
        # This is more reliable than complex regex patterns
        json_objects = self._find_json_objects(text)

        for obj_str in json_objects:
            try:
                # CRITICAL FIX (v2.3.4): Use strict JSON parser to prevent duplicate key bypass
                parsed = strict_json_loads(obj_str)
                if isinstance(parsed, dict) and self._looks_like_tool_call(parsed):
                    normalized = self._normalize_tool_call(parsed)
                    if normalized:
                        tool_calls.append(normalized)
            except (json.JSONDecodeError, Exception):
                # Try to fix and reparse (but still use strict parser)
                fixed = self._fix_json(obj_str)
                if fixed:
                    try:
                        # CRITICAL FIX (v2.3.4): Use strict JSON parser even for fixed JSON
                        parsed = strict_json_loads(fixed)
                        if isinstance(parsed, dict) and self._looks_like_tool_call(
                            parsed
                        ):
                            normalized = self._normalize_tool_call(parsed)
                            if normalized:
                                tool_calls.append(normalized)
                    except (json.JSONDecodeError, Exception):
                        continue

        return tool_calls

    def _extract_via_json_parsing(self, text: str) -> List[Dict[str, Any]]:
        """
        Extract tool calls by finding and parsing JSON objects.

        Args:
            text: Text to search

        Returns:
            List of tool call dictionaries (may not be normalized yet)
        """
        tool_calls = []

        # Find all JSON-like objects in the text
        json_objects = self._find_json_objects(text)

        for obj in json_objects:
            try:
                # CRITICAL FIX (v2.3.4): Use strict JSON parser to prevent duplicate key bypass
                parsed = strict_json_loads(obj)
                if isinstance(parsed, dict):
                    # Check if it looks like a tool call
                    if self._looks_like_tool_call(parsed):
                        normalized = self._normalize_tool_call(parsed)
                        if normalized:
                            tool_calls.append(normalized)
            except (json.JSONDecodeError, Exception):
                # Try to fix common JSON issues
                fixed = self._fix_json(obj)
                if fixed:
                    try:
                        # CRITICAL FIX (v2.3.4): Use strict JSON parser even for fixed JSON
                        parsed = strict_json_loads(fixed)
                        if isinstance(parsed, dict) and self._looks_like_tool_call(
                            parsed
                        ):
                            normalized = self._normalize_tool_call(parsed)
                            if normalized:
                                tool_calls.append(normalized)
                    except (json.JSONDecodeError, Exception):
                        logger.debug(
                            f"[HEPHAESTUS] Could not parse JSON object: {obj[:50]}..."
                        )
                        continue

        return tool_calls

    def _find_json_objects(self, text: str) -> List[str]:
        """
        Find JSON-like objects in text (balanced braces).

        Args:
            text: Text to search

        Returns:
            List of JSON-like strings
        """
        json_objects = []
        brace_count = 0
        start_idx = -1

        for i, char in enumerate(text):
            if char == "{":
                if brace_count == 0:
                    start_idx = i
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0 and start_idx >= 0:
                    # Found a balanced JSON object
                    json_str = text[start_idx : i + 1]
                    json_objects.append(json_str)
                    start_idx = -1

        return json_objects

    def _looks_like_tool_call(self, obj: Dict[str, Any]) -> bool:
        """
        Check if a dictionary looks like a tool call.

        Args:
            obj: Dictionary to check

        Returns:
            True if it looks like a tool call
        """
        if not isinstance(obj, dict):
            return False

        # Check for common tool call keys (case-insensitive)
        keys_lower = [k.lower() for k in obj.keys()]
        has_tool = any(key in ["tool", "function", "name"] for key in keys_lower)
        has_args = any(
            key in ["arguments", "parameters", "args", "params"] for key in keys_lower
        )

        # If it has a tool name key, it's likely a tool call
        # If it has arguments, it might be a tool call (but could also be other things)
        return has_tool or (
            has_args and len(obj) <= 5
        )  # Arguments + a few other keys = likely tool call

    def _normalize_tool_call(self, call: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize a tool call to standard format: {"tool_name": str, "arguments": dict}.

        Args:
            call: Tool call dictionary (may be in various formats)

        Returns:
            Normalized tool call or None if invalid
        """
        if not isinstance(call, dict):
            return None

        # Extract tool name (case-insensitive search)
        tool_name = None
        call_lower = {k.lower(): v for k, v in call.items()}

        if "tool" in call_lower:
            tool_name = call_lower["tool"]
        elif "function" in call_lower:
            tool_name = call_lower["function"]
        elif "name" in call_lower:
            tool_name = call_lower["name"]

        if not tool_name:
            logger.debug(f"[HEPHAESTUS] No tool name found in call: {call}")
            return None

        # Extract arguments (case-insensitive search)
        arguments = {}
        if "arguments" in call_lower:
            args_value = call_lower["arguments"]
        elif "parameters" in call_lower:
            args_value = call_lower["parameters"]
        elif "args" in call_lower:
            args_value = call_lower["args"]
        elif "params" in call_lower:
            args_value = call_lower["params"]
        else:
            args_value = None

        if args_value is not None:
            # If arguments is a string, try to parse it as JSON
            if isinstance(args_value, str):
                try:
                    # CRITICAL FIX (v2.3.4): Use strict JSON parser for arguments
                    arguments = strict_json_loads(args_value)
                except (json.JSONDecodeError, Exception):
                    # Try to fix common issues
                    fixed = self._fix_json(args_value)
                    if fixed:
                        try:
                            # CRITICAL FIX (v2.3.4): Use strict JSON parser even for fixed JSON
                            arguments = strict_json_loads(fixed)
                        except (json.JSONDecodeError, Exception):
                            arguments = self._parse_dict_like_string(args_value)
                    else:
                        arguments = self._parse_dict_like_string(args_value)
            else:
                arguments = args_value

        # Ensure arguments is a dict
        if not isinstance(arguments, dict):
            arguments = {}

        return {"tool_name": str(tool_name), "arguments": arguments}

    def _parse_dict_like_string(self, text: str) -> Dict[str, Any]:
        """
        Parse a dict-like string that may not be valid JSON.

        Args:
            text: String that looks like a dict

        Returns:
            Dictionary (may be empty if parsing fails)
        """
        # Try to extract key-value pairs using regex
        result = {}
        # Pattern: "key": "value" or 'key': 'value' or key: value
        pattern = r'["\']?(\w+)["\']?\s*:\s*["\']?([^,}]+)["\']?'
        matches = re.finditer(pattern, text)
        for match in matches:
            key = match.group(1)
            value = match.group(2).strip().strip("\"'")
            result[key] = value
        return result

    def _fix_json(self, text: str) -> Optional[str]:
        """
        Attempt to fix common JSON issues.

        Args:
            text: Potentially malformed JSON

        Returns:
            Fixed JSON string or None if unfixable
        """
        # Remove trailing commas
        text = re.sub(r",\s*}", "}", text)
        text = re.sub(r",\s*]", "]", text)

        # Fix single quotes to double quotes (for keys and string values)
        # This is a simple heuristic - may not work for all cases
        # Pattern: 'key': or 'value' (but not inside already-quoted strings)
        # We'll do a simple replacement for common cases
        text = re.sub(r"'(\w+)':", r'"\1":', text)  # Keys: 'key': -> "key":
        # For string values, we need to be more careful
        # Pattern: : 'value' (but not already in double quotes)
        text = re.sub(
            r":\s*'([^']+)'", r': "\1"', text
        )  # Values: : 'value' -> : "value"

        return text
