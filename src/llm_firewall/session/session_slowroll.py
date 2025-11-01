"""Session slow-roll assembler for cross-turn fragment detection."""

from __future__ import annotations

from typing import Any

MAX_BUF = 256


def _statebag(st: Any) -> dict[str, str]:
    """Get or create session assembly buffer."""
    bag = getattr(st, "_asm", None)
    if bag is None:
        bag = {"buf": ""}
        setattr(st, "_asm", bag)
    return bag


def update_assembler(st: Any, text: str) -> dict[str, bool]:
    """
    Update session-wide text buffer and check for assembled secrets.

    Args:
        st: Session state object
        text: New turn text

    Returns:
        Dictionary with partial, complete, and assembled_strong flags
    """

    # Inline compact_alnum to avoid circular imports
    def compact_alnum(s: str) -> str:
        return "".join(ch for ch in s if ch.isalnum())

    # Inline anchor list to avoid circular imports
    anchors = [
        "sk-live",
        "sk-test",
        "ghp_",
        "gho_",
        "xoxb-",
        "xoxp-",
        "x-api-key",
        "api_key",
        "bearer",
    ]

    bag = _statebag(st)
    c = compact_alnum(text).lower()
    buf = (bag["buf"] + c)[-MAX_BUF:]
    bag["buf"] = buf

    # Prepare anchor compacts
    anchors_compact = [a.replace("-", "").replace("_", "").lower() for a in anchors]

    # Check for partial (ending with anchor prefix)
    partial = any(
        buf.endswith(a[: max(3, len(a) // 2)]) for a in anchors_compact
    ) or any(a in buf for a in anchors_compact[:-1])

    # Check for complete (full anchor present)
    complete = any(a in buf for a in anchors_compact)

    # Check for assembled_strong (anchor + >=32 alnum tail)
    assembled_strong = False
    for a in anchors_compact:
        i = buf.find(a)
        if i >= 0:
            tail = "".join(ch for ch in buf[i + len(a) :] if ch.isalnum())
            if len(tail) >= 32:
                assembled_strong = True
                break

    return {
        "partial": partial,
        "complete": complete,
        "assembled_strong": assembled_strong,
    }
