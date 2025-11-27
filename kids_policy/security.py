"""
Security Utilities: Layer 0 Technical Security
==============================================
Hard gatekeeper for technical attacks (XSS, SQLi) before NLP/logic layers.

Author: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-28
Status: HYDRA-04 Fix
"""

import re


class SecurityUtils:
    """
    Layer 0: Technical Security

    Blocks technical attacks (XSS, SQLi) before NLP/logic layers kick in.
    """

    # Hard signatures for injections
    INJECTION_PATTERNS = [
        r"<script.*?>",  # XSS
        r"javascript:",  # URI Scheme
        r"union\s+select",  # SQLi
        r"drop\s+table",  # SQLi
        r"alert\(",  # JS Execution
        r"exec\(",  # Code Execution
        r"system\(",  # System Calls
        r"\{\{.*?\}\}",  # Template Injection
        r"onerror\s*=",  # Event Handler Injection
        r"onclick\s*=",  # Event Handler Injection
        r"eval\(",  # Code Evaluation
        r"<iframe",  # IFrame Injection
        r"<object",  # Object Injection
        r"<embed",  # Embed Injection
    ]

    @staticmethod
    def detect_injection(text: str) -> bool:
        """
        Detect technical injection attacks.

        Args:
            text: Input text to check

        Returns:
            True if injection detected, False otherwise
        """
        text_lower = text.lower()
        for pattern in SecurityUtils.INJECTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def normalize_text(text: str) -> str:
        """
        Normalize text for pattern matching.
        Removes formatting, line breaks, extra whitespace.

        This helps regex patterns match across line breaks and formatting
        (e.g., poetry, obfuscated text).

        Args:
            text: Input text to normalize

        Returns:
            Normalized text (single line, lowercase, single spaces)
        """
        # Convert to lowercase
        normalized = text.lower()
        # Replace all whitespace (including newlines, tabs) with single space
        normalized = " ".join(normalized.split())
        return normalized
