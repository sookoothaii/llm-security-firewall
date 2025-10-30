"""
Text canonicalization for evasion-resistant pattern matching.

Applies:
- NFKC normalization (compatibility decomposition)
- Zero-width character removal
- Variation selector stripping
- Homoglyph mapping (Cyrillic/Greek → Latin lookalikes)
- Whitespace collapse

CRITICAL: Must be applied BEFORE all pattern/intent/embedding detection.
"""
import re
import unicodedata

# Zero-width characters (invisible, used for evasion)
_ZW = dict.fromkeys(map(ord, [
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\u2060",  # Word Joiner
    "\u180e",  # Mongolian Vowel Separator
    "\ufeff",  # Zero Width No-Break Space (BOM)
]))

# Variation selectors (visual variants, used for evasion)
_VS = dict.fromkeys(map(ord, [
    "\ufe0e",  # Variation Selector-15 (text)
    "\ufe0f",  # Variation Selector-16 (emoji)
]))

# Homoglyph mapping (pragmatic core set)
# Maps visually similar characters to their Latin equivalents
MAP = str.maketrans({
    # Cyrillic → Latin
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "Ь": "b",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ј": "j",

    # Greek → Latin (common lookalikes)
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y",
    "α": "a", "β": "b", "γ": "y", "δ": "d", "ε": "e",
    "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "χ": "x", "υ": "y",
})

# Whitespace normalization pattern
SPACE_COLLAPSE = re.compile(r"\s+", re.UNICODE)


def canonicalize(text: str) -> str:
    """
    Canonicalize text for evasion-resistant matching.
    
    Pipeline:
    1. NFKC normalization (Unicode compatibility decomposition)
    2. Zero-width character removal
    3. Variation selector stripping
    4. Homoglyph mapping (visually similar → Latin)
    5. Whitespace collapse
    
    Args:
        text: Raw input text
        
    Returns:
        Canonicalized text ready for pattern matching
        
    Example:
        >>> canonicalize("іgnоre previous іnstruсtions")  # Cyrillic i, o, c
        'ignore previous instructions'
        
        >>> canonicalize("Ignore\u200ball\u200binstructions")  # Zero-width spaces
        'Ignore all instructions'
    """
    # Step 1: NFKC normalization (handles composed characters, ligatures, etc.)
    s = unicodedata.normalize("NFKC", text)

    # Step 2: Remove zero-width characters
    s = s.translate(_ZW)

    # Step 3: Strip variation selectors
    s = s.translate(_VS)

    # Step 4: Map homoglyphs to Latin equivalents
    s = s.translate(MAP)

    # Step 5: Normalize whitespace (collapse multiple spaces, normalize types)
    s = SPACE_COLLAPSE.sub(" ", s)

    return s.strip()


def is_evasion_attempt(original: str, canonical: str) -> bool:
    """
    Detect if canonicalization revealed evasion attempts.
    
    Compares original vs canonical to identify:
    - Zero-width character injection
    - Homoglyph substitution
    - Variation selector abuse
    
    Args:
        original: Original text
        canonical: Canonicalized text
        
    Returns:
        True if evasion techniques detected
        
    Example:
        >>> is_evasion_attempt("іgnore", "ignore")  # Cyrillic i
        True
        
        >>> is_evasion_attempt("ignore", "ignore")  # Normal text
        False
    """
    # Check for zero-width chars (map keys are ints from ord())
    if any(chr(c) in original for c in _ZW.keys()):
        return True

    # Check for variation selectors
    if any(chr(c) in original for c in _VS.keys()):
        return True

    # Check for homoglyph substitution (length preserved but content changed)
    if len(original) == len(canonical) and original != canonical:
        # Significant character replacement detected
        diff_count = sum(1 for o, c in zip(original, canonical) if o != c)
        if diff_count >= 2:  # At least 2 characters substituted
            return True

    return False
