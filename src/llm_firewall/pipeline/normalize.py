"""
Early Canonicalization Pipeline
Runs BEFORE all detectors to normalize obfuscation patterns
"""

import unicodedata
import re
from typing import Dict

# Emoji pattern for bridging detection (ranges that work with re)
EMOJI_RE = re.compile(
    r"[\U0001F1E6-\U0001F1FF\U0001F200-\U0001FAFF]|[\ud83c][\udd70-\udd7f]|[\ud835][\udc00-\udfff]"
)

# Zero-Width chars and Variation Selectors
RE_ZWVS = re.compile(r"[\u200B\u200C\u200D\uFEFF\uFE0E\uFE0F]")

# Transport encoding patterns
HEX2 = re.compile(r"%(?i:[0-9A-F]{2})")
HEX2_RUN = re.compile(r"(?:%(?i:[0-9A-F]{2})){3,}")  # min 3 consecutive
QP_SOFT = re.compile(r"=\r?\n")  # soft line breaks
QP_HEX = re.compile(r"=(?i:[0-9A-F]{2})")
QUOTED = re.compile(r"(['\"])(.*?)(\1)", re.S)  # only decode in quotes
COMMENT_LINE = re.compile(r"^\s*#.*$", re.M)


def early_canon(text: str) -> str:
    """
    Early canonicalization to neutralize token fragmentation attacks.

    Steps:
    1. NFKC normalization (FULLWIDTH → ASCII, ligatures, etc)
    2. Strip zero-width and variation selectors
    3. Normalize ideographic spaces to ASCII space

    This prevents attacks like:
    - eVaL("c\uff4f\uff4fde") - fullwidth in quotes
    - ex\u3000\u3000cute('code') - ideographic spaces
    - trig\u200b\u200ager('event') - zero-width breaks
    """
    # 1) NFKC fold (maps FULLWIDTH ASCII → ASCII, FF08 ) → '(' etc.)
    t = unicodedata.normalize("NFKC", text)

    # 2) Strip zero-width / variation selectors (break token boundaries otherwise)
    t = RE_ZWVS.sub("", t)

    # 3) Collapse ideographic spaces to ASCII space
    t = t.replace("\u3000", " ")

    return t


def _pct_decode(s: str, max_bytes: int = 4096) -> str:
    """URL percent-decode with safety limits"""
    try:
        if len(s) > max_bytes:
            return s
        return bytes.fromhex(s.replace("%", "")).decode("utf-8", "ignore")
    except Exception:
        return s


def _qp_decode(s: str, max_bytes: int = 4096) -> str:
    """Quoted-Printable decode (soft breaks + =HH)"""
    if len(s) > max_bytes:
        return s
    # Remove soft line breaks
    s2 = QP_SOFT.sub("", s)
    # Decode =HH sequences
    try:
        return QP_HEX.sub(
            lambda m: bytes.fromhex(m.group(0)[1:]).decode("utf-8", "ignore"), s2
        )
    except Exception:
        return s2


def transport_light(text: str, contrib: Dict) -> str:
    """
    Light transport decoding (URL %XX, QP =HH) ONLY in quoted strings.
    FPR-safe: Only decodes inside quotes to avoid false positives.
    """

    def _maybe_decode(segment: str) -> str:
        dec = segment

        # URL: only if high density or >=3 hex pairs in sequence
        if HEX2_RUN.search(segment) or (
            segment.count("%") >= 3 and HEX2.search(segment)
        ):
            dec2 = _pct_decode(segment)
            if dec2 != segment:
                contrib["url_percent_decoded"] = True
                dec = dec2

        # QP: only if soft breaks or =HH present
        if "=\n" in segment or "=\r\n" in segment or QP_HEX.search(segment):
            dec3 = _qp_decode(dec)
            if dec3 != dec:
                contrib["qp_decoded"] = True
                dec = dec3

        return dec

    # Only decode content in quotes (FPR-safe)
    out, last = [], 0
    for m in QUOTED.finditer(text):
        out.append(text[last : m.start(2)])
        out.append(_maybe_decode(m.group(2)))
        last = m.end(2)
    out.append(text[last:])
    return "".join(out)


def comment_join_in_quotes(text: str) -> str:
    """
    Remove comment lines ONLY inside quoted strings.
    Prevents comment-split evasion while preserving normal comments.
    """

    def _join(seg: str) -> str:
        return COMMENT_LINE.sub("", seg)

    out, last = [], 0
    for m in QUOTED.finditer(text):
        out.append(text[last : m.start(2)])
        out.append(_join(m.group(2)))
        last = m.end(2)
    out.append(text[last:])
    return "".join(out)


def strip_emoji(s: str) -> str:
    """
    Remove emojis for call detection bridging.
    Used for detecting calls like: a🅰lert() -> alert()
    """
    return EMOJI_RE.sub("", s)
