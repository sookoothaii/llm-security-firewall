"""
Text Canonicalization (Production-Grade)
=========================================

Deterministic canonicalization pipeline to defeat evasion techniques.

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations

import re
import unicodedata

# Zero-width characters (ZW) - EXPANDED for comprehensive detection
# Includes all zero-width spaces, joiners, and invisible characters
_ZW = re.compile(
    r"[\u200B-\u200D"  # ZWSP, ZWNJ, ZWJ
    r"\uFEFF"  # ZWNBSP (BOM)
    r"\u2060-\u2064"  # WORD JOINER, FUNCTION APPLICATION, INVISIBLE TIMES, INVISIBLE SEPARATOR, INVISIBLE PLUS
    r"\u180E"  # MONGOLIAN VOWEL SEPARATOR
    r"\u00AD"  # SOFT HYPHEN (invisible)
    r"]"
)
_VS = re.compile(r"[\uFE0E\uFE0F]")  # Variation Selectors
_WS = re.compile(r"\s+")

# EXPANDED homoglyph map - covers more Cyrillic, Greek, and mathematical characters
_HOMO = {
    # Cyrillic → Latin (common attack vectors)
    ord("\u0435"): "e",  # Cyrillic ye (е)
    ord("\u0430"): "a",  # Cyrillic a (а)
    ord("\u043e"): "o",  # Cyrillic o (о)
    ord("\u0441"): "c",  # Cyrillic es (с)
    ord("\u0440"): "p",  # Cyrillic er (р)
    ord("\u0445"): "x",  # Cyrillic ha (х)
    ord("\u0443"): "y",  # Cyrillic u (у)
    ord("\u0438"): "n",  # Cyrillic i (и) - looks like n
    ord("\u043c"): "m",  # Cyrillic em (м)
    ord("\u0432"): "B",  # Cyrillic ve (в) - looks like B
    ord("\u043d"): "H",  # Cyrillic en (н) - looks like H
    ord("\u043a"): "k",  # Cyrillic ka (к)
    ord("\u0433"): "r",  # Cyrillic ghe (г) - looks like r
    ord("\u0456"): "i",  # Ukrainian i (і)
    ord("\u04cf"): "l",  # Cyrillic palochka (ӏ)
    ord("\u044a"): "b",  # Cyrillic hard sign (ъ)
    ord("\u044c"): "b",  # Cyrillic soft sign (ь)
    # Greek → Latin (common in attacks)
    ord("\u0399"): "I",  # Greek Iota (Ι)
    ord("\u0395"): "E",  # Greek Epsilon (Ε)
    ord("\u0391"): "A",  # Greek Alpha (Α)
    ord("\u039f"): "O",  # Greek Omicron (Ο)
    ord("\u03a4"): "T",  # Greek Tau (Τ)
    ord("\u03a0"): "P",  # Greek Pi (Π)
    ord("\u0392"): "B",  # Greek Beta (Β)
    ord("\u0397"): "H",  # Greek Eta (Η)
    ord("\u039a"): "K",  # Greek Kappa (Κ)
    ord("\u039c"): "M",  # Greek Mu (Μ)
    ord("\u03a1"): "P",  # Greek Rho (Ρ)
    ord("\u03a5"): "Y",  # Greek Upsilon (Υ)
    ord("\u03a7"): "X",  # Greek Chi (Χ)
    ord("\u03b1"): "a",  # Greek alpha (α)
    ord("\u03bf"): "o",  # Greek omicron (ο)
    ord("\u03c1"): "p",  # Greek rho (ρ)
    ord("\u03c4"): "t",  # Greek tau (τ)
    ord("\u03bd"): "v",  # Greek nu (ν)
    # Mathematical Alphanumeric Symbols → Latin
    ord("\u1d49C"): "A",  # Mathematical Script Capital A (𝒜)
    ord("\u1d49E"): "C",  # Mathematical Script Capital C (𝒞)
    ord("\u1d4a2"): "G",  # Mathematical Script Capital G (𝒢)
    ord("\u1d4a5"): "J",  # Mathematical Script Capital J (𝒥)
    ord("\u1d4a6"): "K",  # Mathematical Script Capital K (𝒦)
    ord("\u1d4a9"): "N",  # Mathematical Script Capital N (𝒩)
    ord("\u1d4aA"): "O",  # Mathematical Script Capital O (𝒪)
    ord("\u1d4aB"): "P",  # Mathematical Script Capital P (𝒫)
    ord("\u1d4aC"): "Q",  # Mathematical Script Capital Q (𝒬)
    ord("\u1d4aE"): "S",  # Mathematical Script Capital S (𝒮)
    ord("\u1d4aF"): "T",  # Mathematical Script Capital T (𝒯)
    ord("\u1d4b0"): "U",  # Mathematical Script Capital U (𝒰)
    ord("\u1d4b1"): "V",  # Mathematical Script Capital V (𝒱)
    ord("\u1d4b2"): "W",  # Mathematical Script Capital W (𝒲)
    ord("\u1d4b3"): "X",  # Mathematical Script Capital X (𝒳)
    ord("\u1d4b4"): "Y",  # Mathematical Script Capital Y (𝒴)
    ord("\u1d4b5"): "Z",  # Mathematical Script Capital Z (𝒵)
    ord("\u1d68A"): "c",  # Mathematical Monospace Small C (𝚌)
    ord("\u1d68B"): "d",  # Mathematical Monospace Small D (𝚍)
    ord("\u1d68C"): "e",  # Mathematical Monospace Small E (𝚎)
    ord("\u1d68D"): "f",  # Mathematical Monospace Small F (𝚏)
    ord("\u1d68E"): "g",  # Mathematical Monospace Small G (𝚐)
    ord("\u1d68F"): "h",  # Mathematical Monospace Small H (𝚑)
    ord("\u1d690"): "i",  # Mathematical Monospace Small I (𝚒)
    ord("\u1d691"): "j",  # Mathematical Monospace Small J (𝚓)
    ord("\u1d692"): "k",  # Mathematical Monospace Small K (𝚔)
    ord("\u1d693"): "l",  # Mathematical Monospace Small L (𝚕)
    ord("\u1d694"): "m",  # Mathematical Monospace Small M (𝚖)
    ord("\u1d695"): "n",  # Mathematical Monospace Small N (𝚗)
    ord("\u1d696"): "o",  # Mathematical Monospace Small O (𝚘)
    ord("\u1d697"): "p",  # Mathematical Monospace Small P (𝚙)
    ord("\u1d698"): "q",  # Mathematical Monospace Small Q (𝚚)
    ord("\u1d699"): "r",  # Mathematical Monospace Small R (𝚛)
    ord("\u1d69A"): "s",  # Mathematical Monospace Small S (𝚜)
    ord("\u1d69B"): "t",  # Mathematical Monospace Small T (𝚝)
    ord("\u1d69C"): "u",  # Mathematical Monospace Small U (𝚞)
    ord("\u1d69D"): "v",  # Mathematical Monospace Small V (𝚟)
    ord("\u1d69E"): "w",  # Mathematical Monospace Small W (𝚠)
    ord("\u1d69F"): "x",  # Mathematical Monospace Small X (𝚡)
    ord("\u1d6a0"): "y",  # Mathematical Monospace Small Y (𝚢)
    ord("\u1d6a1"): "z",  # Mathematical Monospace Small Z (𝚣)
    # Fullwidth characters → ASCII
    ord("\uff21"): "A",  # Fullwidth Latin Capital A
    ord("\uff22"): "B",  # Fullwidth Latin Capital B
    ord("\uff23"): "C",  # Fullwidth Latin Capital C
    ord("\uff24"): "D",  # Fullwidth Latin Capital D
    ord("\uff25"): "E",  # Fullwidth Latin Capital E
    ord("\uff26"): "F",  # Fullwidth Latin Capital F
    ord("\uff27"): "G",  # Fullwidth Latin Capital G
    ord("\uff28"): "H",  # Fullwidth Latin Capital H
    ord("\uff29"): "I",  # Fullwidth Latin Capital I
    ord("\uff2a"): "J",  # Fullwidth Latin Capital J
    ord("\uff2b"): "K",  # Fullwidth Latin Capital K
    ord("\uff2c"): "L",  # Fullwidth Latin Capital L
    ord("\uff2d"): "M",  # Fullwidth Latin Capital M
    ord("\uff2e"): "N",  # Fullwidth Latin Capital N
    ord("\uff2f"): "O",  # Fullwidth Latin Capital O
    ord("\uff30"): "P",  # Fullwidth Latin Capital P
    ord("\uff31"): "Q",  # Fullwidth Latin Capital Q
    ord("\uff32"): "R",  # Fullwidth Latin Capital R
    ord("\uff33"): "S",  # Fullwidth Latin Capital S
    ord("\uff34"): "T",  # Fullwidth Latin Capital T
    ord("\uff35"): "U",  # Fullwidth Latin Capital U
    ord("\uff36"): "V",  # Fullwidth Latin Capital V
    ord("\uff37"): "W",  # Fullwidth Latin Capital W
    ord("\uff38"): "X",  # Fullwidth Latin Capital X
    ord("\uff39"): "Y",  # Fullwidth Latin Capital Y
    ord("\uff3a"): "Z",  # Fullwidth Latin Capital Z
    ord("\uff41"): "a",  # Fullwidth Latin Small A
    ord("\uff42"): "b",  # Fullwidth Latin Small B
    ord("\uff43"): "c",  # Fullwidth Latin Small C
    ord("\uff44"): "d",  # Fullwidth Latin Small D
    ord("\uff45"): "e",  # Fullwidth Latin Small E
    ord("\uff46"): "f",  # Fullwidth Latin Small F
    ord("\uff47"): "g",  # Fullwidth Latin Small G
    ord("\uff48"): "h",  # Fullwidth Latin Small H
    ord("\uff49"): "i",  # Fullwidth Latin Small I
    ord("\uff4a"): "j",  # Fullwidth Latin Small J
    ord("\uff4b"): "k",  # Fullwidth Latin Small K
    ord("\uff4c"): "l",  # Fullwidth Latin Small L
    ord("\uff4d"): "m",  # Fullwidth Latin Small M
    ord("\uff4e"): "n",  # Fullwidth Latin Small N
    ord("\uff4f"): "o",  # Fullwidth Latin Small O
    ord("\uff50"): "p",  # Fullwidth Latin Small P
    ord("\uff51"): "q",  # Fullwidth Latin Small Q
    ord("\uff52"): "r",  # Fullwidth Latin Small R
    ord("\uff53"): "s",  # Fullwidth Latin Small S
    ord("\uff54"): "t",  # Fullwidth Latin Small T
    ord("\uff55"): "u",  # Fullwidth Latin Small U
    ord("\uff56"): "v",  # Fullwidth Latin Small V
    ord("\uff57"): "w",  # Fullwidth Latin Small W
    ord("\uff58"): "x",  # Fullwidth Latin Small X
    ord("\uff59"): "y",  # Fullwidth Latin Small Y
    ord("\uff5a"): "z",  # Fullwidth Latin Small Z
    # Punctuation and dashes
    ord("\u2014"): "-",  # EM dash
    ord("\u2013"): "-",  # EN dash
    ord("\u2012"): "-",  # Figure dash
    ord("\u2212"): "-",  # Minus sign
    ord("\u201c"): '"',  # Smart quote left
    ord("\u201d"): '"',  # Smart quote right
    ord("\u2018"): "'",  # Smart apostrophe left
    ord("\u2019"): "'",  # Smart apostrophe right
    ord("\u201a"): ",",  # Single low-9 quotation mark
    ord("\u201b"): "'",  # Single high-reversed-9 quotation mark
    ord("\u201e"): '"',  # Double low-9 quotation mark
    ord("\u201f"): '"',  # Double high-reversed-9 quotation mark
    ord("\uff07"): "'",  # Fullwidth apostrophe
    ord("\uff02"): '"',  # Fullwidth quote
    ord("\u0131"): "i",  # Dotless i
    ord("\u0237"): "j",  # Dotless j
}


def canonicalize(text: str) -> str:
    """
    Deterministic canonicalization pipeline (ENHANCED v2):
      1) Unicode NFKD normalization (decomposes combining diacritics)
      2) Strip Combining Diacritics (U+0300-U+036F, including U+0337)
      3) Strip Zero-Width + Variation Selectors (early removal)
      4) Homoglyph mapping (comprehensive)
      5) Casefold
      6) Whitespace normalize

    Changes from v1:
    - NFKD normalization (decomposes combining marks like U+0337)
    - Combining diacritics removal (prevents s̷y̷s̷t̷e̷m̷ attacks)
    - NFC instead of NFKC (stricter, prevents compatibility decomposition attacks)
    - Zero-width removal BEFORE homoglyph mapping (prevents ZW obfuscation)
    - Expanded homoglyph map (Cyrillic, Greek, Mathematical, Fullwidth)
    """
    if not text:
        return ""

    # Step 1: NFKD normalization (decomposes combining diacritics)
    # This separates base characters from combining marks (e.g., s + U+0337 → s)
    s = unicodedata.normalize("NFKD", text)

    # Step 2: Remove combining diacritics (U+0300-U+036F)
    # This includes U+0337 (Combining Short Stroke Overlay) used in s̷y̷s̷t̷e̷m̷ attacks
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")

    # Step 3: NFC normalization (recompose remaining characters)
    s = unicodedata.normalize("NFC", s)

    # Step 4: Remove zero-width characters EARLY (before homoglyph mapping)
    # This prevents zero-width characters from being used to obfuscate homoglyphs
    s = _ZW.sub("", s)
    s = _VS.sub("", s)

    # Step 5: Map homoglyphs to Latin equivalents
    s = s.translate(_HOMO)

    # Step 6: Casefold (lowercase normalization)
    s = s.casefold()

    # Step 7: Normalize whitespace
    s = _WS.sub(" ", s).strip()

    return s
