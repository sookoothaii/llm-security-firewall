# -*- coding: utf-8 -*-
"""
Executability Probe
Parse code in fences (JSON, YAML, Python) - parse-OK → dampen MED/WEAK
"""

import ast
import json
import re
from typing import Dict, Tuple


def _extract_code_fence(text: str) -> Tuple[str, str]:
    """
    Extract code from fences

    Returns:
        (code_content, language_tag)
    """
    # Match ```lang ... ``` or ``` ... ```
    fence_pattern = r"```(\w+)?\s*\n(.*?)\n```"
    matches = re.findall(fence_pattern, text, re.DOTALL)

    if matches:
        lang, code = matches[0]
        return code.strip(), lang.strip() if lang else ""

    return "", ""


def _parse_json(code: str) -> bool:
    """Try to parse as JSON"""
    try:
        json.loads(code)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def _parse_yaml_heuristic(code: str) -> bool:
    """Simple YAML heuristic (key: value patterns)"""
    lines = code.split("\n")
    key_value_count = 0
    for line in lines[:20]:  # Check first 20 lines
        stripped = line.strip()
        if ":" in stripped and not stripped.startswith("#"):
            key_value_count += 1

    return key_value_count >= 2  # At least 2 key:value pairs


def _parse_python(code: str) -> bool:
    """Try to parse as Python AST"""
    try:
        ast.parse(code)
        return True
    except (SyntaxError, ValueError):
        return False


def is_parseable(code: str, language: str) -> bool:
    """
    Check if code is parseable

    Args:
        code: Code content
        language: Language tag (json, yaml, python, etc.)

    Returns:
        True if code parses successfully
    """
    if not code:
        return False

    lang_lower = language.lower() if language else ""

    if "json" in lang_lower:
        return _parse_json(code)
    elif "yaml" in lang_lower or "yml" in lang_lower:
        return _parse_yaml_heuristic(code)
    elif "python" in lang_lower or "py" in lang_lower:
        return _parse_python(code)

    # Default: try JSON, then YAML heuristic
    if _parse_json(code):
        return True

    return _parse_yaml_heuristic(code)


def check_executability(text: str, has_strong: bool) -> Dict[str, any]:
    """
    Check if code in fences is parseable

    Args:
        text: Input text
        has_strong: Whether STRONG signals are present

    Returns:
        {'parseable': bool, 'dampen_factor': float, 'reason': str}
    """
    code, lang = _extract_code_fence(text)

    if not code:
        return {
            "parseable": False,
            "dampen_factor": 1.0,
            "reason": "No code fence found",
        }

    parse_ok = is_parseable(code, lang)

    if parse_ok and not has_strong:
        # Parseable code without STRONG → dampen MED/WEAK (less aggressive)
        return {
            "parseable": True,
            "dampen_factor": 0.8,  # Was 0.6 - less aggressive after bypass attack
            "reason": f"Code in {lang or 'unknown'} fence parses successfully, dampening MED/WEAK",
        }

    return {
        "parseable": False,
        "dampen_factor": 1.0,
        "reason": "Not parseable or STRONG present",
    }
