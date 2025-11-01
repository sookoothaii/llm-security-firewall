"""Lightweight YAML anchor/alias expansion for cross-line secret detection."""

from __future__ import annotations

import re

ANCHOR = re.compile(r"&([A-Za-z][\w\-]{0,31})\s+([^\n]+)")
ALIAS = re.compile(r"\*([A-Za-z][\w\-]{0,31})\b")


def expand_yaml_aliases(
    text: str, max_alias: int = 4, max_expand_bytes: int = 1024
) -> str:
    """
    Lightweight, bounded expansion of YAML &anchors/*aliases across lines.

    Args:
        text: Input text (may contain YAML)
        max_alias: Maximum alias expansions per line
        max_expand_bytes: Maximum bytes per anchor value

    Returns:
        Text with aliases expanded (bounded)
    """
    if not text or ("&" not in text and "*" not in text):
        return text

    anchors = {}
    lines = text.splitlines()

    # Pass 1: collect simple one-line anchors (&id value)
    for ln in lines:
        for m in ANCHOR.finditer(ln):
            name, val = m.group(1), m.group(2).strip()
            if name not in anchors and val:
                anchors[name] = val[:max_expand_bytes]

    if not anchors:
        return text

    # Pass 2: replace up to max_alias occurrences per line
    out = []
    for ln in lines:
        replaced = 0

        def _sub(m):
            nonlocal replaced
            if replaced >= max_alias:
                return m.group(0)
            name = m.group(1)
            if name in anchors:
                replaced += 1
                return anchors[name]
            return m.group(0)

        out.append(ALIAS.sub(_sub, ln))

    return "\n".join(out)
