"""
Common Text Processing Helpers for External Benign Corpus Collection

Minimal, deterministic helpers for classification and telemetry.
"""

import re
import unicodedata

# Patterns
FENCE_RE = re.compile(r"(^|\n)```[^\n]*\n[\s\S]*?\n```", re.MULTILINE)
CALL_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(", re.ASCII)
JS_ATTR_RE = re.compile(r"\bon[a-zA-Z]+\s*=", re.IGNORECASE)
URL_SCHEME_RE = re.compile(r"\b(?:https?|javascript):", re.IGNORECASE)
SQL_TOKEN_RE = re.compile(r"\b(select|insert|update|delete|drop|create|alter)\b", re.IGNORECASE)
B64_LIKE_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def normalize(text: str) -> str:
    """Early canonicalization: NFKC, strip zero-widths"""
    t = unicodedata.normalize("NFKC", text)
    t = t.replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")
    return t


def has_codefence(text: str) -> bool:
    """Check for markdown code fences"""
    return bool(FENCE_RE.search(text))


def count_calls(text: str) -> int:
    """Count function call patterns"""
    return len(CALL_RE.findall(text))


def has_js_attr(text: str) -> bool:
    """Check for JavaScript event attributes"""
    return bool(JS_ATTR_RE.search(text))


def has_urlscheme(text: str) -> bool:
    """Check for URL schemes (http/https/javascript)"""
    return bool(URL_SCHEME_RE.search(text))


def contains_sql_tokens(text: str) -> bool:
    """Check for SQL keywords"""
    return bool(SQL_TOKEN_RE.search(text))


def contains_base64_like(text: str) -> bool:
    """Check for base64-like patterns"""
    return bool(B64_LIKE_RE.search(text))


def min_distance_to_call(text: str, risky_kw: list) -> int:
    """
    Return minimal char distance between any risky keyword and nearest "(" call.
    Returns -1 if no calls or no keywords found.
    """
    idx_calls = [m.start() for m in CALL_RE.finditer(text)]
    if not idx_calls:
        return -1
    
    best = 10**9
    for kw in risky_kw:
        start = 0
        while True:
            k = text.find(kw, start)
            if k < 0:
                break
            nearest = min(abs(k - c) for c in idx_calls)
            if nearest < best:
                best = nearest
            start = k + len(kw)
    
    return -1 if best == 10**9 else best


def detect_lang(text: str) -> str:
    """
    Simple language detection (placeholder).
    In production: use langid or fastText.
    Returns: "en"|"de"|"other"
    """
    # German indicators
    de_words = ['der', 'die', 'das', 'und', 'ist', 'nicht', 'auch', 'wird', 'werden']
    # English indicators
    en_words = ['the', 'and', 'is', 'not', 'also', 'will', 'are', 'were', 'have']
    
    text_lower = text.lower()
    de_count = sum(1 for w in de_words if f' {w} ' in text_lower)
    en_count = sum(1 for w in en_words if f' {w} ' in text_lower)
    
    if de_count > en_count:
        return 'de'
    elif en_count > de_count:
        return 'en'
    else:
        return 'other'

