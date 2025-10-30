"""
Safety-Sandwich Decoding - Early Abort for Critical Leaks
Purpose: Prevent critical-leak@n by speculative dual decoding
Creator: Joerg Bollwahn
Date: 2025-10-30

Key Innovation: Don't just MEASURE critical-leak@n - PREVENT it.
Speculative fast decode → leak check → abort OR full decode.

Target: critical-leak@20 <= 0.2% (GPT-5 spec)
"""

from __future__ import annotations

import re
from typing import Protocol

# Abort message (policy-compliant wrap)
ABORTED_MESSAGE = "[ABORTED: safety leak detected in early tokens]"


class SpeculativeModel(Protocol):
    """
    Protocol for models supporting speculative decoding.

    Required methods:
        spec_decode: Fast draft generation (first N tokens)
        decode: Full generation
    """

    def spec_decode(self, prompt: str, max_new_tokens: int = 20) -> str:
        """Generate draft output (first N tokens only)."""
        ...

    def decode(self, prompt: str) -> str:
        """Generate full output."""
        ...


class LeakDetector:
    """
    Deterministic detector for critical content leaks.

    Detects high-risk patterns in generated text:
    - Credentials (passwords, API keys, tokens)
    - Private keys (RSA, SSH, certificates)
    - Personally identifiable information (PII)
    - Secret/confidential markers

    Design: Fast regex-based (O(n) per pattern).
    Production: Extend with domain-specific patterns.
    """

    # Critical leak patterns (case-insensitive)
    _PATTERNS = [
        # Credentials
        r"\bpassword\s*[:=]\s*\S+",
        r"\bapi[_-]?key\s*[:=]\s*\S+",
        r"\btoken\s*[:=]\s*[A-Za-z0-9_-]{20,}",
        r"\bauth[_-]?token\b",
        # Private keys
        r"BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY",
        r"-----BEGIN PRIVATE KEY-----",
        # Secrets
        r"\bmaster[_-]?key\b",
        r"\bsecret\s*[:=]\s*\S+",
        r"\bcredential[s]?\s*[:=]",
        # PII markers
        r"\b(SSN|social\s*security)\s*[:=]",
        r"\bcredit\s*card\s*[:=]",
        # High-risk instructions
        r"\bhow\s+to\s+(hack|exploit|bypass)",
        r"\bstep\s+1\s*:\s*(inject|poison|compromise)",
    ]

    def __init__(self) -> None:
        """Compile patterns for efficiency."""
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self._PATTERNS]

    def count_critical(self, text: str) -> int:
        """
        Count critical leak patterns in text.

        Args:
            text: Generated text to check

        Returns:
            Number of critical patterns detected (0 = clean)
        """
        count = 0
        for pattern in self._compiled:
            if pattern.search(text):
                count += 1
        return count

    def find_leaks(self, text: str) -> list[str]:
        """
        Find all critical leak patterns.

        Args:
            text: Generated text to check

        Returns:
            List of matched pattern descriptions
        """
        leaks = []
        for i, pattern in enumerate(self._compiled):
            match = pattern.search(text)
            if match:
                leaks.append(f"Pattern {i}: {self._PATTERNS[i]} at pos {match.start()}")
        return leaks


# Global detector instance (reuse compiled regexes)
leak_detector: LeakDetector = LeakDetector()


def guarded_decode(
    prompt: str,
    model: SpeculativeModel,
    n_tokens: int = 20,
    detector: LeakDetector | None = None,
) -> str:
    """
    Safety-sandwich decoding with early abort.

    Workflow:
    1. Generate draft (first N tokens) via spec_decode
    2. Check draft for critical leaks
    3. If leak detected: abort and return safe message
    4. If clean: proceed with full decode

    Args:
        prompt: Input prompt
        model: Model supporting speculative decoding
        n_tokens: Number of tokens to check in draft (default: 20)
        detector: Custom leak detector (default: global instance)

    Returns:
        Full decoded text OR abort message if leak detected

    Performance:
    - Draft generation: ~10-30% of full decode time
    - Leak check: O(n) per pattern, < 1ms typical
    - Total overhead: < 50ms for n=20

    Example:
        >>> model = MySpeculativeModel()
        >>> output = guarded_decode("How to reset password", model)
        >>> if output == ABORTED_MESSAGE:
        ...     log_security_event("critical_leak_prevented")
    """
    if detector is None:
        detector = leak_detector

    # Step 1: Speculative draft generation (fast)
    draft = model.spec_decode(prompt, max_new_tokens=n_tokens)

    # Step 2: Leak detection (deterministic)
    if detector.count_critical(draft) > 0:
        # ABORT: Critical leak detected in early tokens
        return ABORTED_MESSAGE

    # Step 3: Full decode (no leak detected)
    return model.decode(prompt)


def guarded_decode_with_details(
    prompt: str, model: SpeculativeModel, n_tokens: int = 20
) -> tuple[str, bool, list[str]]:
    """
    Safety-sandwich with detailed leak information.

    Returns:
        Tuple of (output, was_aborted, leak_patterns)
    """
    draft = model.spec_decode(prompt, max_new_tokens=n_tokens)
    leaks = leak_detector.find_leaks(draft)

    if leaks:
        return ABORTED_MESSAGE, True, leaks

    full_output = model.decode(prompt)
    return full_output, False, []
