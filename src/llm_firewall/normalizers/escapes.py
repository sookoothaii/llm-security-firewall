# -*- coding: utf-8 -*-
"""
CSS/JS Escape Handling and Backslash-Continuation Folding
Closes: GR-06 (Properties fold)
"""
import re

def fold_backslash_newline(text: str) -> str:
    """
    Fold backslash-continuation lines (Java .properties, CSS multi-line strings)
    Replaces: \\\r?\n[ \t]* with empty string
    """
    # Properties-style continuation
    folded = re.sub(r'\\\r?\n[ \t]*', '', text)
    return folded

def css_unescape(text: str, max_unescapes: int = 100):
    r"""
    Decode CSS hex escapes: \HHHH (1-6 hex digits)
    Returns: (unescaped_text, metadata)
    """
    count = 0
    
    def replace_css_hex(match):
        nonlocal count
        if count >= max_unescapes:
            return match.group(0)
        count += 1
        hex_str = match.group(1)
        try:
            codepoint = int(hex_str, 16)
            if 0 <= codepoint <= 0x10ffff:
                return chr(codepoint)
        except (ValueError, OverflowError):
            pass
        return match.group(0)
    
    # CSS hex escape: \HHHH (1-6 digits, optional space after)
    pattern = r'\\([0-9a-fA-F]{1,6})[ \t]?'
    result = re.sub(pattern, replace_css_hex, text)
    
    return result, {"css_unescaped": count, "css_truncated": count >= max_unescapes}

def js_unescape(text: str, max_unescapes: int = 100):
    r"""
    Decode JavaScript hex escapes: \uHHHH, \xHH
    Returns: (unescaped_text, metadata)
    """
    count = 0
    
    def replace_js_hex(match):
        nonlocal count
        if count >= max_unescapes:
            return match.group(0)
        count += 1
        hex_str = match.group(1)
        try:
            codepoint = int(hex_str, 16)
            if 0 <= codepoint <= 0x10ffff:
                return chr(codepoint)
        except (ValueError, OverflowError):
            pass
        return match.group(0)
    
    # JS escapes: \uHHHH or \xHH
    result = re.sub(r'\\u([0-9a-fA-F]{4})', replace_js_hex, text)
    result = re.sub(r'\\x([0-9a-fA-F]{2})', replace_js_hex, result)
    
    return result, {"js_unescaped": count, "js_truncated": count >= max_unescapes}

