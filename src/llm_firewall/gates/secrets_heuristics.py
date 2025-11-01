"""
Secrets Heuristics - Pattern + Entropy Based Secret Detection
==============================================================
Purpose: Detect credentials, API keys, tokens in text
Creator: GPT-5 (External Contributor)
Date: 2025-10-30

Design: PASTA-like approach (low FP, high recall)
- Pattern matching for common secret formats
- Entropy analysis for random-looking strings
- Base64 detection for encoded secrets
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, cast


@dataclass(frozen=True)
class SecretsFindings:
    """Results from secrets analysis"""

    severity: float  # 0..1 bounded
    hits: List[Dict[str, Any]]  # List of detected secrets with metadata
    patterns_matched: int
    high_entropy_spans: int
    base64_candidates: int


def _shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of string

    Args:
        s: Input string

    Returns:
        Entropy in bits per character (0 to ~4.7 for ASCII)
    """
    if not s:
        return 0.0

    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1

    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def analyze_secrets(
    text: str, entropy_threshold: float = 3.5, min_length: int = 16
) -> SecretsFindings:
    """
    Analyze text for secrets using pattern + entropy heuristics

    Args:
        text: Text to analyze
        entropy_threshold: Entropy threshold for high-entropy detection
            (default 3.5 bits)
        min_length: Minimum length for entropy analysis (default 16 chars)

    Returns:
        SecretsFindings with severity score and hits
    """
    hits = []

    # Pattern 1: API Keys (provider-specific formats - ENHANCED)
    api_key_patterns = [
        # OpenAI
        (r"\bsk-[A-Za-z0-9]{20,}", "openai_api_key"),
        (r"\bsk-proj-[A-Za-z0-9]{20,}", "openai_project_key"),
        # Google
        (r"\bAIza[A-Za-z0-9_-]{35,}", "google_api_key"),
        # GitHub
        (r"\bghp_[A-Za-z0-9]{36,}", "github_token"),
        (r"\bgho_[A-Za-z0-9]{36,}", "github_oauth"),
        (r"\bghs_[A-Za-z0-9]{36,}", "github_server_token"),
        # GitLab
        (r"\bglpat-[A-Za-z0-9_-]{20,}", "gitlab_token"),
        # Slack
        (r"\bxoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}", "slack_bot_token"),
        (r"\bxoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}", "slack_user_token"),
        # HuggingFace
        (r"\bhf_[A-Za-z0-9]{32,}", "huggingface_token"),
        # AWS
        (r"\bAKIA[A-Z0-9]{16}", "aws_access_key"),
        # Azure
        (r"\b[A-Za-z0-9/+]{88}==", "azure_storage_key"),
        # Stripe
        (r"\b(sk|pk)_(test|live)_[A-Za-z0-9]{24,}", "stripe_key"),
        # JWT (short form)
        (
            r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
            "jwt_token",
        ),
        # Generic high-entropy uppercase
        (r"\b[A-Z0-9]{32,}", "generic_token_uppercase"),
    ]

    for pattern, secret_type in api_key_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            matched_text = match.group(0)
            # Verify entropy (avoid false positives on repeated chars)
            if len(matched_text) >= min_length:
                ent = _shannon_entropy(matched_text)
                if ent >= entropy_threshold:
                    hits.append(
                        {
                            "type": secret_type,
                            "pattern": "api_key",
                            "span": match.span(),
                            "text": matched_text[:8] + "...",  # Don't log full secret
                            "entropy": round(ent, 2),
                            "severity": 0.9,
                        }
                    )

    # Pattern 2: Password assignments
    password_patterns = [
        r'\bpassword\s*[:=]\s*[\'"]?([A-Za-z0-9!@#$%^&*()_+-]{8,})[\'"]?',
        r'\bpwd\s*[:=]\s*[\'"]?([A-Za-z0-9!@#$%^&*()_+-]{8,})[\'"]?',
        r'\bpw\s*[:=]\s*[\'"]?([A-Za-z0-9!@#$%^&*()_+-]{8,})[\'"]?',
    ]

    for pattern in password_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            hits.append(
                {
                    "type": "password_assignment",
                    "pattern": "password",
                    "span": match.span(),
                    "text": match.group(1)[:3] + "...",
                    "severity": 0.8,
                }
            )

    # Pattern 3: Private Keys (PEM format)
    pem_patterns = [
        r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
        r"-----BEGIN RSA PRIVATE KEY-----",
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        r"-----BEGIN CERTIFICATE-----",
    ]

    for pattern in pem_patterns:
        if re.search(pattern, text):
            hits.append(
                {
                    "type": "private_key_pem",
                    "pattern": "pem_header",
                    "severity": 1.0,  # Maximum severity
                }
            )

    # Pattern 4: Base64 Candidates (high entropy)
    base64_pattern = r"\b[A-Za-z0-9+/]{24,}={0,2}\b"
    base64_candidates = 0

    for match in re.finditer(base64_pattern, text):
        candidate = match.group(0)
        if len(candidate) >= min_length:
            ent = _shannon_entropy(candidate)
            if ent >= entropy_threshold:
                base64_candidates += 1
                hits.append(
                    {
                        "type": "base64_high_entropy",
                        "pattern": "base64",
                        "span": match.span(),
                        "entropy": round(ent, 2),
                        "severity": 0.6,
                    }
                )

    # Pattern 4b: Base32 Candidates (RFC 4648)
    base32_pattern = r"\b[A-Z2-7]{24,}={0,6}\b"
    for match in re.finditer(base32_pattern, text):
        candidate = match.group(0)
        if len(candidate) >= min_length:
            ent = _shannon_entropy(candidate)
            if ent >= entropy_threshold:
                hits.append(
                    {
                        "type": "base32_high_entropy",
                        "pattern": "base32",
                        "span": match.span(),
                        "entropy": round(ent, 2),
                        "severity": 0.6,
                    }
                )

    # Pattern 4c: Base58 Candidates (Bitcoin/IPFS style - no 0OIl)
    base58_pattern = (
        r"\b[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{24,}\b"
    )
    for match in re.finditer(base58_pattern, text):
        candidate = match.group(0)
        if len(candidate) >= min_length:
            ent = _shannon_entropy(candidate)
            if ent >= entropy_threshold:
                hits.append(
                    {
                        "type": "base58_high_entropy",
                        "pattern": "base58",
                        "span": match.span(),
                        "entropy": round(ent, 2),
                        "severity": 0.6,
                    }
                )

    # Pattern 4d: Hex Strings with High Entropy
    hex_pattern = r"\b[0-9a-fA-F]{32,}\b"
    for match in re.finditer(hex_pattern, text):
        candidate = match.group(0)
        if len(candidate) >= min_length:
            ent = _shannon_entropy(candidate)
            if ent >= 3.0:  # Lower threshold for hex (less alphabet)
                hits.append(
                    {
                        "type": "hex_high_entropy",
                        "pattern": "hex",
                        "span": match.span(),
                        "entropy": round(ent, 2),
                        "severity": 0.7,
                    }
                )

    # Pattern 5: High-Entropy Alphanumeric Spans (generic secrets)
    # Look for continuous alphanumeric strings with high entropy
    alphanum_pattern = r"\b[A-Za-z0-9]{20,}\b"
    high_entropy_spans = 0

    for match in re.finditer(alphanum_pattern, text):
        candidate = match.group(0)
        if len(candidate) >= min_length:
            ent = _shannon_entropy(candidate)
            if ent >= 4.0:  # Higher threshold for generic spans
                high_entropy_spans += 1
                # Skip if already caught by specific patterns
                if not any(h["span"] == match.span() for h in hits):
                    hits.append(
                        {
                            "type": "high_entropy_alphanumeric",
                            "pattern": "entropy",
                            "span": match.span(),
                            "entropy": round(ent, 2),
                            "severity": 0.5,
                        }
                    )

    # Calculate aggregate severity
    if not hits:
        severity = 0.0
    else:
        # Weighted max (highest severity dominates, but multiple hits increase)
        severities: List[float] = [float(cast(float, h["severity"])) for h in hits]
        max_severity: float = max(severities)
        count_boost = min(0.1 * len(hits), 0.2)  # Up to +0.2 for multiple hits
        severity = min(1.0, max_severity + count_boost)

    return SecretsFindings(
        severity=severity,
        hits=hits,
        patterns_matched=len([h for h in hits if h["pattern"] != "entropy"]),
        high_entropy_spans=high_entropy_spans,
        base64_candidates=base64_candidates,
    )


def redact_text(text: str, hits: List[Dict[str, Any]], mask: str = "[SECRET]") -> str:
    """
    Redact secrets from text using hit list

    Args:
        text: Original text
        hits: List of secret hits from analyze_secrets
        mask: Replacement mask string

    Returns:
        Text with secrets replaced by mask
    """
    if not hits:
        return text

    # Sort hits by span position (reverse order for safe replacement)
    sorted_hits = sorted(hits, key=lambda h: h.get("span", (0, 0))[0], reverse=True)

    result = text
    for hit in sorted_hits:
        span = hit.get("span")
        if span:
            start, end = span
            result = result[:start] + mask + result[end:]

    return result
