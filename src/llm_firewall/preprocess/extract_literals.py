# -*- coding: utf-8 -*-
"""
Extract String Literals and Comments from Code
RC2 P4.3: AST-Gating to avoid false positives on identifiers
"""

import io
import tokenize
from typing import List, Tuple


def extract_py_literals_and_comments(src: str) -> List[Tuple[str, int]]:
    """
    Extract string literals and comments from Python source

    Args:
        src: Python source code

    Returns:
        List of (content, line_number) tuples
    """
    if not src:
        return []

    out = []
    try:
        rdr = io.BytesIO(src.encode("utf-8", errors="ignore")).readline
        for tok in tokenize.tokenize(rdr):
            if tok.type in (tokenize.STRING, tokenize.COMMENT):
                out.append((tok.string, tok.start[0]))
    except Exception:
        # Tokenize can fail on malformed code
        # Fallback: scan full text
        return [(src, 1)]

    return out


def extract_scannable_parts(text: str, context: str = "natural") -> List[str]:
    """
    Extract scannable parts based on context

    Args:
        text: Input text
        context: Context type (code, config, natural)

    Returns:
        List of text parts to scan (literals/comments for code, full text otherwise)
    """
    if context == "code":
        # Try Python extraction
        literals = extract_py_literals_and_comments(text)
        if literals:
            # Return literal contents (strip quotes)
            parts = []
            for content, _ in literals:
                # Strip string quotes
                if content.startswith(('"""', "'''")):
                    parts.append(content[3:-3])
                elif content.startswith(('"', "'")):
                    parts.append(content[1:-1])
                elif content.startswith("#"):
                    parts.append(content[1:])
                else:
                    parts.append(content)
            return [p for p in parts if p]

    # Fallback or non-code: scan full text
    return [text]
