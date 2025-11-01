# -*- coding: utf-8 -*-
"""
Unicode Placement Analysis
Distinguishes exotic Unicode in identifiers/hosts (risky) vs strings/comments (benign)
RC2 P3.0: Context-aware exotic Unicode scoring
"""
import re
from typing import Dict, Set


# Unicode ranges
RANGES = {
    "MATH": [(0x1D400, 0x1D7FF)],
    "ENCLOSED": [(0x2460, 0x24FF), (0x1F100, 0x1F1FF)],
    "LIGATURES": [(0xFB00, 0xFB06)],
    "COMBINING": [(0x0300, 0x036F)],
    "CYRILLIC": [(0x0400, 0x052F)],
    "GREEK": [(0x0370, 0x03FF)],
}


def _in_ranges(cp: int, ranges) -> bool:
    """Check if codepoint in ranges"""
    for a, b in ranges:
        if a <= cp <= b:
            return True
    return False


def _family(cp: int) -> str:
    """Get Unicode family"""
    if _in_ranges(cp, RANGES["COMBINING"]): return "COMBINING"
    if _in_ranges(cp, RANGES["LIGATURES"]): return "LIGATURES"
    if _in_ranges(cp, RANGES["MATH"]): return "MATH"
    if _in_ranges(cp, RANGES["ENCLOSED"]): return "ENCLOSED"
    return None


def _has_mixed_script(token: str) -> bool:
    """Check for Latin + Cyrillic/Greek mix (spoofing)"""
    has_lat = any(('A' <= ch <= 'Z' or 'a' <= ch <= 'z') for ch in token)
    has_cyr = any(_in_ranges(ord(ch), RANGES["CYRILLIC"]) for ch in token)
    has_grk = any(_in_ranges(ord(ch), RANGES["GREEK"]) for ch in token)
    return has_lat and (has_cyr or has_grk)


def analyze_unicode_placement(text: str) -> Dict[str, float]:
    """
    Analyze where exotic Unicode appears
    
    Returns:
        {
            'id_density.FAMILY': float (0-1),
            'sc_density.FAMILY': float (0-1),  
            'id_mixed_script': float (0/1)
        }
    """
    # Simple tokenization (identifiers vs strings/comments)
    # Identifier pattern: word-like
    IDENT_RE = re.compile(r'\b[A-Za-z_]\w*\b')
    STRING_RE = re.compile(r'["\']([^"\'\\]|\\.)*["\']')
    COMMENT_RE = re.compile(r'(#|//).*?$', re.MULTILINE)
    
    # Extract identifiers
    identifiers = ' '.join(IDENT_RE.findall(text))
    
    # Remove strings and comments for "code" portion
    no_strings = STRING_RE.sub('', text)
    no_comments = COMMENT_RE.sub('', no_strings)
    
    # Count exotic chars in identifiers vs strings/comments
    fam_id_counts = {}
    fam_sc_counts = {}
    id_mixed = 0
    
    # Analyze identifiers
    for match in IDENT_RE.finditer(no_comments):
        token = match.group(0)
        if _has_mixed_script(token):
            id_mixed = 1
        
        for ch in token:
            fam = _family(ord(ch))
            if fam:
                fam_id_counts[fam] = fam_id_counts.get(fam, 0) + 1
    
    # Analyze strings/comments (everything not in no_comments)
    for ch in text:
        fam = _family(ord(ch))
        if fam:
            # Total count
            if ch not in no_comments:
                fam_sc_counts[fam] = fam_sc_counts.get(fam, 0) + 1
    
    total_id_chars = len(identifiers) if identifiers else 1
    total_sc_chars = len(text) - len(no_comments) if len(text) > len(no_comments) else 1
    
    def dens(count: int, total: int) -> float:
        return (count / total) if total > 0 else 0.0
    
    result = {"id_mixed_script": float(id_mixed)}
    
    for fam in ("COMBINING", "LIGATURES", "MATH", "ENCLOSED"):
        result[f"id_density.{fam}"] = dens(fam_id_counts.get(fam, 0), total_id_chars)
        result[f"sc_density.{fam}"] = dens(fam_sc_counts.get(fam, 0), total_sc_chars)
    
    return result


def adjust_unicode_signals(signals: Set[str], text: str, ctx: str) -> Set[str]:
    """
    Adjust exotic Unicode signals based on placement
    
    Args:
        signals: Current signal set
        text: Original text
        ctx: Context (code/config/natural)
    
    Returns:
        Adjusted signal set
    """
    exotic_signals = {
        'unicode_combining_seen', 'unicode_ligature_seen',
        'unicode_math_alpha_seen', 'unicode_enclosed_seen'
    }
    
    if not any(s in signals for s in exotic_signals):
        return signals
    
    placement = analyze_unicode_placement(text)
    result = set(signals)
    
    # Promotion: Identifiers with mixed scripts OR high density in identifiers
    if placement.get("id_mixed_script", 0.0) >= 1.0:
        result.add("mixed_script_identifier_strong")
    
    id_density_total = sum(
        placement.get(f"id_density.{fam}", 0.0)
        for fam in ("MATH", "ENCLOSED", "LIGATURES", "COMBINING")
    )
    
    if ctx in {"code", "config"} and id_density_total >= 0.05:  # RC2 P3.1: stricter (0.06 → 0.05)
        result.add("unicode_exotic_identifier_risky")
    
    # Benign case: Low density in strings/comments (RC2 P3.1: stricter)
    LOW_THRESHOLD = 0.10  # 10% (reduced from 12%)
    sc_densities = [
        placement.get(f"sc_density.{fam}", 0.0)
        for fam in ("COMBINING", "LIGATURES", "MATH", "ENCLOSED")
    ]
    
    benign_sc = all(d <= LOW_THRESHOLD for d in sc_densities)
    
    if ctx in {"code", "config"} and benign_sc:
        # Neutralize exotic signals (low density in strings/comments)
        for sig in exotic_signals:
            result.discard(sig)
        result.add("unicode_exotic_sc_benign")
    
    return result

