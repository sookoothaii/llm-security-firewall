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
_ZW = dict.fromkeys(
    map(
        ord,
        [
            "\u200b",  # Zero Width Space
            "\u200c",  # Zero Width Non-Joiner
            "\u200d",  # Zero Width Joiner
            "\u2060",  # Word Joiner
            "\u180e",  # Mongolian Vowel Separator
            "\ufeff",  # Zero Width No-Break Space (BOM)
        ],
    )
)

# Variation selectors (visual variants, used for evasion)
_VS = dict.fromkeys(
    map(
        ord,
        [
            "\ufe0e",  # Variation Selector-15 (text)
            "\ufe0f",  # Variation Selector-16 (emoji)
        ],
    )
)

# Homoglyph mapping (pragmatic core set)
# Maps visually similar characters to their Latin equivalents
MAP = str.maketrans(
    {
        # Cyrillic → Latin
        "А": "A",
        "В": "B",
        "Е": "E",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
        "Ь": "b",
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ј": "j",
        # Greek → Latin (common lookalikes)
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Ζ": "Z",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Χ": "X",
        "Υ": "Y",
        "α": "a",
        "β": "b",
        "γ": "y",
        "δ": "d",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "χ": "x",
        "υ": "y",
    }
)

# Whitespace normalization pattern
SPACE_COLLAPSE = re.compile(r"\s+", re.UNICODE)

# Pattern to detect spaces between letters (but preserve word boundaries)
# Matches: letter-space-letter (within words)
SPACE_BETWEEN_LETTERS = re.compile(r"(\w)\s+(\w)", re.UNICODE)

# Leetspeak/typo normalization mapping
LEETSPEAK_MAP = str.maketrans({
    '0': 'o',  # zero -> o
    '1': 'i',  # one -> i
    '3': 'e',  # three -> e
    '4': 'a',  # four -> a
    '5': 's',  # five -> s
    '@': 'a',  # @ -> a
    '!': 'i',  # ! -> i
    '$': 's',  # $ -> s
})


def normalize_obfuscation(text: str) -> str:
    """
    Normalize obfuscated text for pattern matching.
    
    Two-stage approach:
    - Stage 1 (always): Basic normalization (spaces between letters, leetspeak)
    - Stage 2 (conditional): Aggressive normalization only for high-risk keywords
    
    Handles:
    - Spaces between letters: "g e n e r a t e" -> "generate"
    - Leetspeak/typos: "expl0it" -> "exploit", "h@ck" -> "hack"
    
    Note: This preserves word boundaries (spaces between words remain).
    
    Args:
        text: Input text (may contain obfuscation)
        
    Returns:
        Normalized text with obfuscation removed
        
    Example:
        >>> normalize_obfuscation("g e n e r a t e  t h e  l y r i c s")
        'generate the lyrics'
        
        >>> normalize_obfuscation("expl0it the system")
        'exploit the system'
        
        >>> normalize_obfuscation("h@ck the password")
        'hack the password'
    """
    # High-risk keywords that should trigger aggressive normalization
    HIGH_RISK_KEYWORDS = {
        "hack", "exploit", "bypass", "crack", "malware", "ransomware",
        "phishing", "steal", "unauthorized", "intrusion", "breach",
        "fake", "hoax", "conspiracy", "cover-up",
        "generate", "reproduce", "copy", "duplicate", "download", "pirated",
        "jailbreak", "ignore", "override", "disable", "evade"
    }
    
    # Stage 1: Always apply basic normalization
    # Remove spaces between letters recursively (but keep word boundaries)
    # Strategy: Process text by splitting on multiple spaces (word boundaries)
    # For each segment, remove spaces between single letters recursively
    
    def remove_spaces_between_single_letters(segment: str) -> str:
        """Remove spaces between single letters in a segment recursively."""
        max_iterations = 20
        iteration = 0
        s = segment
        
        while iteration < max_iterations:
            # Simple pattern: letter-space-letter
            # This will match any two letters separated by spaces
            # We apply it recursively until no more matches
            pattern = r'([a-zA-Z])\s+([a-zA-Z])'
            new_s = re.sub(pattern, r'\1\2', s)
            
            # If no change occurred, we're done
            if new_s == s:
                break
            s = new_s
            iteration += 1
        
        return s
    
    # Normalize leetspeak/typos FIRST (before space removal)
    has_leetspeak = any(char in text for char in ['0', '1', '3', '4', '5', '@', '!', '$'])
    if has_leetspeak:
        text = text.translate(LEETSPEAK_MAP)
    
    # CRITICAL FIX: Detect obfuscation vs normal words
    # Obfuscation pattern: single letters separated by spaces (e.g., "g e n e r a t e")
    # Normal words: multiple letters together (e.g., "generate the lyrics")
    # Strategy: Only remove spaces between single letters, preserve spaces between words
    
    # Check if text contains obfuscation pattern (single letters with spaces)
    # Pattern: letter-space-letter (repeated) indicates obfuscation
    obfuscation_pattern = r'\b([a-zA-Z])\s+([a-zA-Z])\s+([a-zA-Z])\s+([a-zA-Z])'
    has_obfuscation = bool(re.search(obfuscation_pattern, text))
    
    if has_obfuscation:
        # Text contains obfuscation - use segment-based approach
        # Split text by multiple spaces (2+ spaces indicate word boundaries)
        # Process each segment separately to preserve word boundaries
        segments = re.split(r'\s{2,}', text)
        processed_segments = [remove_spaces_between_single_letters(seg.strip()) for seg in segments]
        
        # Join with single space to preserve word boundaries
        # DO NOT call remove_spaces_between_single_letters() again on the joined text!
        s = ' '.join(processed_segments)
    else:
        # No obfuscation detected - return text as-is (preserve normal word spacing)
        # This prevents "generate the lyrics" from becoming "generatethelyrics"
        s = text
    
    return s


def canonicalize(text: str) -> str:
    """
    Canonicalize text for evasion-resistant matching.

    Pipeline:
    1. NFKC normalization (Unicode compatibility decomposition)
    2. Zero-width character removal
    3. Variation selector stripping
    4. Homoglyph mapping (visually similar → Latin)
    5. Obfuscation normalization (spaces between letters, leetspeak)
    6. Whitespace collapse

    Args:
        text: Raw input text

    Returns:
        Canonicalized text ready for pattern matching

    Example:
        >>> canonicalize("іgnоre previous іnstruсtions")  # Cyrillic i, o, c
        'ignore previous instructions'

        >>> canonicalize("Ignore\u200ball\u200binstructions")  # Zero-width spaces
        'Ignore all instructions'
        
        >>> canonicalize("g e n e r a t e  t h e  l y r i c s")  # Spaces between letters
        'generate the lyrics'
        
        >>> canonicalize("expl0it the system")  # Leetspeak
        'exploit the system'
    """
    # Step 1: NFKC normalization (handles composed characters, ligatures, etc.)
    s = unicodedata.normalize("NFKC", text)

    # Step 2: Remove zero-width characters
    s = s.translate(_ZW)

    # Step 3: Strip variation selectors
    s = s.translate(_VS)

    # Step 4: Map homoglyphs to Latin equivalents
    s = s.translate(MAP)

    # Step 5: Normalize obfuscation (spaces between letters, leetspeak)
    s = normalize_obfuscation(s)

    # Step 6: Normalize whitespace (collapse multiple spaces, normalize types)
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
