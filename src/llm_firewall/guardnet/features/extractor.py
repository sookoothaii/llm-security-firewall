"""
GuardNet Feature Extractor - Deterministic Feature Computation

Computes engineered features for guard model training and inference.
Integrates with existing firewall components (canonicalization, regex, temporal gate).

Features:
- Obfuscation signals: ZWC density, base64 fraction, mixed-script ratio, punct burst
- Temporal features: TTL delta, trust tier
- OOD detection: embedding energy (external input)
- Regex/Trie hits: intent and evasion patterns (external input)

All features are deterministic and reproducible for given inputs.

Creator: Joerg Bollwahn
Date: 2025-10-30
"""

from __future__ import annotations
import re
from typing import Dict, Any

# Regex patterns for obfuscation detection
_ZWC_PATTERN = re.compile(r"[\u200B-\u200D\uFEFF]")  # Zero-Width Characters
_BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{16,}={0,2})")  # Base64 sequences


def zwc_density(text: str) -> float:
    """
    Compute zero-width character density (count / length).
    
    Zero-width characters (ZWC, ZWNJ, ZWJ, ZWNBSP) are invisible and
    commonly used for obfuscation attacks.
    
    Args:
        text: Input text (normalized or raw)
    
    Returns:
        Density in [0, 1], 0 if empty text
    """
    if not text:
        return 0.0
    zwc_count = len(_ZWC_PATTERN.findall(text))
    return zwc_count / len(text)


def base64_fraction(text: str) -> float:
    """
    Compute fraction of text that appears to be base64 encoded.
    
    Detects long alphanumeric sequences with optional padding (=).
    Minimum length: 16 characters (to reduce false positives).
    
    Args:
        text: Input text
    
    Returns:
        Fraction in [0, 1], 0 if empty text
    """
    if not text:
        return 0.0
    base64_chars = sum(len(m.group(0)) for m in _BASE64_PATTERN.finditer(text))
    return base64_chars / len(text)


def mixed_script_ratio(text: str) -> float:
    """
    Compute ratio of non-Latin alphabetic characters to all alphabetic characters.
    
    High ratio indicates script mixing (e.g., Cyrillic/Greek homoglyphs mixed with Latin).
    Common obfuscation technique to bypass pattern matching.
    
    Args:
        text: Input text
    
    Returns:
        Ratio in [0, 1], 0 if no alphabetic characters
    """
    latin_count = sum(1 for c in text if "A" <= c <= "z")  # includes A-Z, a-z
    non_latin_alpha = sum(1 for c in text if c.isalpha() and not ("A" <= c <= "z"))
    total_alpha = latin_count + non_latin_alpha
    
    if total_alpha == 0:
        return 0.0
    
    return non_latin_alpha / total_alpha


def punct_burst_score(text: str) -> float:
    """
    Compute maximum consecutive punctuation burst length.
    
    Detects unusual punctuation patterns (e.g., "!?!?!?", "...---...").
    Can indicate obfuscation or encoding attempts.
    
    Punctuation set: ! ? : ; , . — - –
    
    Args:
        text: Input text
    
    Returns:
        Maximum consecutive punctuation count (unbounded, but typically < 10)
    """
    punct_chars = set("!?:;,.—-–")
    runs = []
    current_run = 0
    
    for char in text:
        if char in punct_chars:
            current_run += 1
        elif current_run > 0:
            runs.append(current_run)
            current_run = 0
    
    if current_run > 0:
        runs.append(current_run)
    
    return float(max(runs, default=0))


def compute_features(
    text_norm: str,
    regex_hits: Dict[str, int],
    lid: str,
    emb_ood_energy: float,
    ttl_delta_days: int,
    trust_tier: float,
) -> Dict[str, Any]:
    """
    Compute full feature vector for guard model.
    
    Args:
        text_norm: Normalized text (after canonicalization)
        regex_hits: Dict of pattern category -> hit count (e.g., {"intent/jailbreak": 2, "evasion/base64": 1})
        lid: Language ID (ISO code, e.g., "en", "de", "unknown")
        emb_ood_energy: Out-of-distribution energy score from embedding space (higher = more OOD)
        ttl_delta_days: Days until TTL expiry (from Temporal Gate, can be negative if expired)
        trust_tier: Domain trust score from Domain Trust Scoring (0.0 - 1.0)
    
    Returns:
        Feature dict with keys:
            - zwc_density: float [0, 1]
            - base64_frac: float [0, 1]
            - mixed_script_ratio: float [0, 1]
            - punct_burst: float (unbounded)
            - emb_ood_energy: float (unbounded, but typically [-10, 10])
            - ttl_delta_days: int (can be negative)
            - trust_tier: float [0, 1]
            - lid: str (language ID)
            - regex_hits: Dict[str, int] (pattern hits)
    """
    return {
        "zwc_density": zwc_density(text_norm),
        "base64_frac": base64_fraction(text_norm),
        "mixed_script_ratio": mixed_script_ratio(text_norm),
        "punct_burst": punct_burst_score(text_norm),
        "emb_ood_energy": float(emb_ood_energy),
        "ttl_delta_days": int(ttl_delta_days),
        "trust_tier": float(trust_tier),
        "lid": lid,
        "regex_hits": dict(regex_hits),
    }


# Utility functions for feature expansion (e.g., for ML input)

def expand_regex_hits(regex_hits: Dict[str, int], category_keys: list[str]) -> list[float]:
    """
    Expand regex_hits dict to fixed-length vector.
    
    Args:
        regex_hits: Dict of pattern category -> count
        category_keys: Ordered list of expected categories (e.g., ["intent/jailbreak", "evasion/base64"])
    
    Returns:
        List of floats (counts as floats, 0.0 if category not present)
    """
    return [float(regex_hits.get(k, 0)) for k in category_keys]


def features_to_vector(
    features: Dict[str, Any],
    category_keys: list[str],
) -> list[float]:
    """
    Convert feature dict to flat numeric vector for ML model.
    
    Args:
        features: Output from compute_features()
        category_keys: Ordered list of regex hit categories
    
    Returns:
        Flat list of floats:
            [zwc_density, base64_frac, mixed_script_ratio, punct_burst,
             emb_ood_energy, ttl_delta_days, trust_tier,
             regex_hit_0, regex_hit_1, ...]
    
    Note: LID (language) is not included in numeric vector (use embedding or one-hot separately)
    """
    base = [
        features["zwc_density"],
        features["base64_frac"],
        features["mixed_script_ratio"],
        features["punct_burst"],
        features["emb_ood_energy"],
        float(features["ttl_delta_days"]),
        features["trust_tier"],
    ]
    
    regex_vec = expand_regex_hits(features["regex_hits"], category_keys)
    
    return base + regex_vec

