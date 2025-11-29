"""
HAK_GAL v2.2-ALPHA: Regex Gate

Fast-fail regex patterns for common attack vectors (jailbreak attempts, command injection, etc.).

Creator: Joerg Bollwahn
License: MIT
"""

import re
import logging
from typing import List, Tuple, Optional

from hak_gal.core.exceptions import SecurityException

logger = logging.getLogger(__name__)


class RegexGate:
    """
    Fast-fail regex gate for jailbreak and attack patterns.

    NO simulated security: Uses real regex patterns.
    """

    def __init__(self, patterns: Optional[List[Tuple[str, str]]] = None):
        """
        Initialize regex gate.

        Args:
            patterns: Optional list of (pattern, threat_name) tuples.
                     If None, uses default patterns (jailbreak + attacks).
        """
        if patterns is None:
            patterns = self._default_patterns()

        self.patterns = [
            (re.compile(pattern, re.IGNORECASE), name) for pattern, name in patterns
        ]

    def check(self, text: str) -> bool:
        """
        Check text for attack patterns.

        Args:
            text: Input text

        Returns:
            True if text is safe

        Raises:
            SecurityException: If pattern match detected (fail-closed)
        """
        for pattern, threat_name in self.patterns:
            if pattern.search(text):
                raise SecurityException(
                    message=f"Regex pattern match detected: {threat_name}",
                    code="REGEX_GATE_VIOLATION",
                    metadata={"threat_name": threat_name, "pattern": pattern.pattern},
                )

        return True

    @staticmethod
    def _default_patterns() -> List[Tuple[str, str]]:
        """
        Default regex patterns for jailbreak and attacks.

        Returns:
            List of (pattern, threat_name) tuples
        """
        return [
            # Jailbreak attempts
            (
                r"ignore\s+(previous|prior|all)\s+instructions?",
                "jailbreak_ignore_instructions",
            ),
            (r"system\s+prompt", "jailbreak_system_prompt"),
            (r"forget\s+(everything|all|previous)", "jailbreak_forget"),
            (r"act\s+as\s+(if|though)", "jailbreak_roleplay"),
            # Command injection
            (
                r"[;&|`]\s*(rm|del|delete|format|mkfs|shutdown|reboot)",
                "command_injection",
            ),
            (r"\$\{.*\}", "command_injection_shell_expansion"),
            # SQL injection (basic)
            (
                r"(['\"]?)\s*(union|select|insert|update|delete|drop|alter|exec|execute)\s+",
                "sql_injection",
            ),
            # Path traversal
            (r"\.\./", "path_traversal"),
            # XSS (basic)
            (r"<script[^>]*>", "xss_script_tag"),
            (r"javascript:", "xss_javascript_protocol"),
        ]


# Alias for backward compatibility
RegexScanner = RegexGate
