"""Deterministic, age/culture-aware adapted answer composer.
- Converts NSMF-Culture canonicals to a short, fluent answer paragraph.
- Keeps anchors (respect/safety/pluralism/help) present to support SPS/Recall.
- Bridges included if culture != "none".
- Output is plain ASCII English.
Policy: No doctrine, no medical/legal advice, neutral phrasing.
"""
from __future__ import annotations
from typing import Dict

BRIDGE = {
    "christian": "Christian families can have different views. We treat everyone with kindness and fairness.",
    "muslim":    "Muslim families can have different views. We show good manners and kindness to everyone.",
    "none":      "Families can have different beliefs. We treat everyone with kindness and fairness.",
}

AGE_STYLE = {
    "6-8": {
        "connect": " ",
        "prefix": "",
        "suffix": "",
    },
    "9-12": {
        "connect": " ",
        "prefix": "",
        "suffix": " Laws and rules can differ by place. Adults decide within local rules.",
    },
    "13-15": {
        "connect": " ",
        "prefix": "Human rights say all people have equal dignity. ",
        "suffix": " People should be safe, respected, and free from hate or violence.",
    },
}

SLOTS_PRIORITY = [
    "definition", "respect", "safety", "pluralism", "help_seeking", "procedure", "adult_decision", "law_variance"
]


def compose_answer(canonical: Dict) -> str:
    age = canonical.get("meta",{}).get("age_band") or canonical.get("age_band")
    culture = canonical.get("meta",{}).get("culture") or canonical.get("culture")
    facts = canonical.get("facts", [])
    # order facts by preferred slot order, then by original index
    slot_rank = {s:i for i,s in enumerate(SLOTS_PRIORITY)}
    facts_sorted = sorted(
        [(slot_rank.get(f.get("role") or f.get("slot"), 999), i, f) for i,f in enumerate(facts)],
        key=lambda t: (t[0], t[1])
    )
    sentences = [f[2].get("text") or f[2].get("surface") for f in facts_sorted]
    sentences = [s.strip() for s in sentences if s and len(s.strip()) > 0]

    style = AGE_STYLE.get(age, AGE_STYLE["9-12"])  # conservative default
    parts = []
    if style["prefix"]:
        parts.append(style["prefix"])
    parts.append(" ".join(sentences))
    if culture and culture != "none":
        parts.append(BRIDGE.get(culture, BRIDGE["none"]))
    if style["suffix"]:
        parts.append(style["suffix"])

    out = " ".join(p.strip() for p in parts if p)
    # enforce ASCII-likeness lightly
    return out.replace("\u2019", "'").replace("\u2014", "-")












