"""
HAK_GAL v2.3.4: Strict JSON Parser

CRITICAL FIX (v2.3.4): Prevents JSON Duplicate Key Bypass.
Python's json.loads() takes the last value for duplicate keys, which can bypass security checks.

Creator: Joerg Bollwahn
Date: 2025-11-29
Status: Emergency Fix v2.3.4
License: MIT
"""

import json
import logging
from typing import Any, Dict, List, Tuple

from hak_gal.core.exceptions import SecurityException

logger = logging.getLogger(__name__)


def prevent_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """
    Object hook for json.loads() that raises ValueError on duplicate keys.

    CRITICAL FIX (v2.3.4): This prevents the "JSON Duplicate Key Bypass" attack.

    Example attack:
        {"cmd": "echo safe", "cmd": "rm -rf /"}
        Standard json.loads() takes last value ("rm -rf /")
        This hook detects duplicate and raises SecurityException

    Args:
        pairs: List of (key, value) tuples from json.loads()

    Returns:
        Dict with unique keys

    Raises:
        SecurityException: If duplicate key detected
    """
    result = {}
    seen_keys = set()

    for key, value in pairs:
        if key in seen_keys:
            # CRITICAL: Duplicate key detected - security violation
            logger.warning(
                f"[JSON Parser] Duplicate key detected: '{key}'. "
                "This may be a bypass attempt."
            )
            raise SecurityException(
                message=f"JSON duplicate key detected: '{key}'. This is a security violation.",
                code="JSON_DUPLICATE_KEY",
                metadata={
                    "duplicate_key": key,
                    "total_keys": len(pairs),
                    "attack_type": "parser_differential_bypass",
                },
            )
        seen_keys.add(key)
        result[key] = value

    return result


def strict_json_loads(text: str) -> Dict[str, Any]:
    """
    Parse JSON with strict duplicate key detection.

    CRITICAL FIX (v2.3.4): Replaces standard json.loads() for security-critical parsing.

    Usage:
        # Instead of: data = json.loads(text)
        # Use: data = strict_json_loads(text)

    Args:
        text: JSON string to parse

    Returns:
        Parsed dictionary

    Raises:
        SecurityException: If duplicate key detected
        json.JSONDecodeError: If JSON is invalid
    """
    try:
        return json.loads(text, object_pairs_hook=prevent_duplicate_keys)
    except SecurityException:
        # Re-raise security exceptions
        raise
    except json.JSONDecodeError as e:
        # Re-raise JSON decode errors
        raise
    except Exception as e:
        # Wrap unexpected errors
        logger.error(f"[JSON Parser] Unexpected error: {e}")
        raise SecurityException(
            message=f"JSON parsing failed: {e}",
            code="JSON_PARSE_ERROR",
        ) from e
