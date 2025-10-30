# -*- coding: utf-8 -*-
"""
Rule-based Neutralizer for persuasion-framed prompts.
- Strips social influence cues detected by existing lexicons.
- Produces a policy-neutral restatement that preserves *content intent* while
  removing titles, reciprocity, urgency, ingroup appeals, and role-play cues.
- Dependency-light; pairs with PersuasionDetector.

Notes:
- This module does **not** generate or encourage harmful instructions.
- The restatement aims for invariance of safety decisions: the policy should
  evaluate content without framing.

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Dict, List, Tuple

from llm_firewall.text.normalize_unicode import normalize

FLAGS = re.IGNORECASE | re.UNICODE

# Minimal replacements to de-personalize phrasing without LM calls
PRONOUN_MAP = [
    (re.compile(r"\b(I|I'm|I am|we|we're|we are|me|us|my|our)\b", FLAGS), "the user"),
    (
        re.compile(
            r"\b(you|you're|you are|your|yours|du|dein|dir|dich|ihr|euer)\b", FLAGS
        ),
        "the assistant",
    ),
]

# Remove excessive punctuation/urgency markers
PUNCT_RE = re.compile(r"[!]{2,}")

# Fallback phrase when content intent cannot be extracted confidently
FALLBACK = "The user asks for information."  # policy-neutral


class Neutralizer:
    def __init__(self, lexicon_dir: str | pathlib.Path):
        self.lexicon_dir = pathlib.Path(lexicon_dir)
        self._compiled: Dict[str, List[re.Pattern]] = {}
        self._load()

    def _load(self) -> None:
        for p in sorted(self.lexicon_dir.glob("*.json")):
            data = json.loads(p.read_text(encoding="utf-8"))
            regs = [re.compile(r, FLAGS) for r in data.get("regex", [])]
            self._compiled[p.stem] = regs

    def strip_persuasion(self, text: str) -> Tuple[str, Dict[str, int]]:
        """Remove segments matching persuasion-regexes; return cleaned text and stats."""
        t = normalize(text)
        removed = {cat: 0 for cat in self._compiled.keys()}
        for cat, regs in self._compiled.items():
            for rgx in regs:
                t, n = rgx.subn(" ", t)  # replace by space to keep token boundaries
                removed[cat] += n
        # Pronoun depersonalization
        for rgx, repl in PRONOUN_MAP:
            t = rgx.sub(repl, t)
        # Nuke multi !
        t = PUNCT_RE.sub("!", t)
        # normalize spaces again
        t = re.sub(r"\s+", " ", t, flags=FLAGS).strip()
        return t, removed

    # Very lightweight intent extraction (verb + object heuristics)
    _VERB_LEADS = re.compile(
        r"\b(tell|explain|list|summarize|describe|translate|classify|generate|write|call|insult|bypass|synthesize|make|build|show|teach)\b\s+(.*)",
        FLAGS,
    )

    def extract_intent(self, text: str) -> str:
        """
        Heuristic: capture leading request verb + remainder (object NP/VP).
        Falls back to original text when uncertain; never invents new objects.
        """
        t = normalize(text)
        m = self._VERB_LEADS.search(t)
        if not m:
            return t if t else FALLBACK
        verb, rest = m.group(1), m.group(2)
        # Trim subordinate clauses introduced by persuasion cues leftovers
        rest = re.split(
            r"\b(because|since|as|so that|damit|weil|da|denn)\b", rest, maxsplit=1
        )[0]
        rest = re.sub(r"\s+", " ", rest).strip(" .:")
        if not rest:
            return FALLBACK
        return f"{verb} {rest}"

    def restate_neutral(self, text: str, max_len: int = 500) -> Dict[str, object]:
        """
        Produces a structured restatement object:
            {
              'original': <original>,
              'cleaned': <persuasion-stripped text>,
              'intent': <heuristic intent>,
              'restated': <policy-neutral single-sentence restatement>,
              'removed_counts': {cat: n, ...}
            }
        """
        cleaned, stats = self.strip_persuasion(text)
        intent = self.extract_intent(cleaned)
        # De-2nd-person: replace 'the assistant' pronoun with neutral phrasing
        intent = re.sub(r"\bthe assistant\b", "the system", intent, flags=FLAGS)
        # Compose final restatement
        intent = intent[:max_len]
        restated = f"User request (neutral): {intent}."
        return {
            "original": text,
            "cleaned": cleaned,
            "intent": intent,
            "restated": restated,
            "removed_counts": stats,
        }

