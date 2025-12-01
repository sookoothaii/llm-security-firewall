"""
HAK_GAL v2.2-ALPHA: Normalization Layer (Layer 0.25)

Recursive URL/percent encoding normalization to prevent double-encoding bypasses.

Creator: Joerg Bollwahn
License: MIT
Date: 2025-11-30
"""

import urllib.parse
import logging
from typing import Tuple

logger = logging.getLogger(__name__)


class NormalizationLayer:
    """
    Normalization Layer (Layer 0.25) - Recursive URL/Percent Decoding.

    Purpose: Prevent double-encoding bypasses (e.g., %252e%252e%252f -> ../)

    Strategy:
    1. Recursively decode URL/percent encoding (max 3 levels)
    2. Detect encoding anomalies (double-encoding score)
    3. Return normalized text + anomaly score
    """

    def __init__(self, max_decode_depth: int = 3):
        """
        Initialize normalization layer.

        Args:
            max_decode_depth: Maximum recursion depth for URL decoding (default: 3)
        """
        self.max_decode_depth = max_decode_depth

    def normalize(self, text: str) -> Tuple[str, float]:
        """
        Normalize input text by recursively decoding URL/percent encoding and Base64.

        Args:
            text: Input text (may contain encoded sequences)

        Returns:
            Tuple of (normalized_text, encoding_anomaly_score)
            - normalized_text: Fully decoded text
            - encoding_anomaly_score: 0.0 to 1.0 (higher = more suspicious encoding)
        """
        if not text:
            return text, 0.0

        import base64

        decoded = text
        decode_count = 0
        base64_decode_count = 0

        # Step 1: Try Base64 decoding first (if looks like Base64)
        if self._looks_like_base64(text):
            try:
                base64_decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
                if base64_decoded != text and len(base64_decoded) > 0:
                    decoded = base64_decoded
                    base64_decode_count = 1
                    logger.warning("[NormalizationLayer] Base64 decoding applied")
            except:
                pass

        # Step 2: Recursive URL/percent decoding (max depth)
        for depth in range(self.max_decode_depth):
            prev = decoded
            try:
                decoded = urllib.parse.unquote(decoded)
                if decoded == prev:
                    # No more decoding possible
                    break
                decode_count += 1
            except Exception as e:
                logger.warning(
                    f"[NormalizationLayer] Decode error at depth {depth}: {e}"
                )
                break

            # After URL decode, check if result is Base64
            if self._looks_like_base64(decoded) and base64_decode_count == 0:
                try:
                    base64_decoded = base64.b64decode(decoded).decode(
                        "utf-8", errors="ignore"
                    )
                    if base64_decoded != decoded and len(base64_decoded) > 0:
                        decoded = base64_decoded
                        base64_decode_count = 1
                        logger.warning(
                            "[NormalizationLayer] Base64 decoding after URL decode"
                        )
                except:
                    pass

        # Calculate encoding anomaly score
        # Higher score = more suspicious (double/triple encoding, Base64 cascades)
        total_decode_count = decode_count + base64_decode_count
        anomaly_score = min(total_decode_count / 2.0, 1.0)  # 0.0-1.0 scale

        if total_decode_count > 1:
            logger.warning(
                f"[NormalizationLayer] Detected {total_decode_count}-level encoding "
                f"(URL: {decode_count}, Base64: {base64_decode_count}, anomaly_score: {anomaly_score:.2f})"
            )

        return decoded, anomaly_score

    @staticmethod
    def _looks_like_base64(text: str) -> bool:
        """Check if text looks like Base64 encoded (ENHANCED - detects Base64 in scientific context)."""
        if not text or len(text) < 4:
            return False
        # Base64 chars: A-Z, a-z, 0-9, +, /, = (padding)
        base64_chars = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        )

        # ENHANCED: Look for Base64 patterns even in longer text (e.g., scientific context)
        # Look for Base64-like substrings (at least 16 chars, typical minimum for commands)
        import re

        base64_pattern = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
        matches = base64_pattern.findall(text)

        if matches:
            # Check if any match is valid Base64 (length % 4 == 0, high ratio)
            for match in matches:
                if len(match) >= 16:  # Minimum length for suspicious Base64
                    base64_ratio = sum(1 for c in match if c in base64_chars) / len(
                        match
                    )
                    if base64_ratio > 0.9 and len(match) % 4 == 0:
                        return True

        # Original check: at least 80% of chars are Base64
        base64_ratio = sum(1 for c in text if c in base64_chars) / len(text)
        return base64_ratio > 0.8 and len(text) % 4 == 0

    def detect_encoding_anomalies(self, text: str) -> float:
        """
        Detect encoding anomalies without full normalization.

        Useful for quick anomaly detection before full normalization.

        Args:
            text: Input text

        Returns:
            Encoding anomaly score (0.0 to 1.0)
        """
        if not text:
            return 0.0

        # Count percent-encoded sequences
        percent_encoded_count = text.count("%")

        # Count double-encoded patterns (%25xx)
        double_encoded_count = text.count("%25")

        # Calculate anomaly score
        if percent_encoded_count == 0:
            return 0.0

        # Ratio of double-encoded to single-encoded
        double_ratio = double_encoded_count / max(percent_encoded_count, 1)

        # Anomaly score: higher if double-encoding ratio is high
        anomaly_score = min(double_ratio * 2.0, 1.0)

        return anomaly_score
