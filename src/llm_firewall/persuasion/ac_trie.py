# -*- coding: utf-8 -*-
"""
Pure-Python Aho-Corasick automaton with graceful fallback.

Usage:
    matcher = build_from_lexicons("src/llm_firewall/lexicons/persuasion")
    hits = matcher.search_categories(text)  # {category: count}

Notes:
- Only matches *keywords* entries (fast path). Regex remain in L1.
- Case-insensitive by lowercasing both patterns and text after normalize().
- Safe for untrusted input; no eval/regex compile here.

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations

import json
import pathlib
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

try:
    pass  # if available, else fallback to re for normalize whitespace
except Exception:  # pragma: no cover
    pass  # type: ignore

from llm_firewall.text.normalize_unicode import normalize


@dataclass
class _Node:
    next: Dict[str, int]
    fail: int
    out: List[Tuple[str, str]]  # (pattern, category)


class AhoCorasick:
    def __init__(self):
        self.nodes: List[_Node] = [_Node(next={}, fail=0, out=[])]

    def _add_word(self, word: str, category: str):
        s = 0
        for ch in word:
            s = self.nodes[s].next.setdefault(ch, self._new())
        self.nodes[s].out.append((word, category))

    def _new(self) -> int:
        self.nodes.append(_Node(next={}, fail=0, out=[]))
        return len(self.nodes) - 1

    def build(self, patterns: Iterable[Tuple[str, str]]):
        # Insert patterns
        for pat, cat in patterns:
            if not pat:
                continue
            self._add_word(pat, cat)
        # Build failure links (BFS)
        q: deque[int] = deque()
        for ch, s in list(self.nodes[0].next.items()):
            self.nodes[s].fail = 0
            q.append(s)
        while q:
            r = q.popleft()
            for a, s in self.nodes[r].next.items():
                q.append(s)
                state = self.nodes[r].fail
                while a not in self.nodes[state].next and state != 0:
                    state = self.nodes[state].fail
                self.nodes[s].fail = self.nodes[state].next.get(a, 0)
                self.nodes[s].out += self.nodes[self.nodes[s].fail].out

    def find_iter(self, text: str):
        s = 0
        for i, ch in enumerate(text):
            while ch not in self.nodes[s].next and s != 0:
                s = self.nodes[s].fail
            s = self.nodes[s].next.get(ch, 0)
            if self.nodes[s].out:
                for pat, cat in self.nodes[s].out:
                    yield (i - len(pat) + 1, i + 1, pat, cat)

    def search_categories(self, text: str) -> Dict[str, int]:
        t = normalize(text).lower()
        counts: Dict[str, int] = defaultdict(int)
        for *_, cat in self.find_iter(t):
            counts[cat] += 1
        return dict(counts)


def build_from_lexicons(lexicon_dir: str | pathlib.Path) -> AhoCorasick:
    """Builds automaton from `keywords` fields across all JSON lexicons."""
    lex_dir = pathlib.Path(lexicon_dir)
    pats: List[Tuple[str, str]] = []
    for p in sorted(lex_dir.glob("*.json")):
        data = json.loads(p.read_text(encoding="utf-8"))
        kws = [k.strip().lower() for k in data.get("keywords", []) if k.strip()]
        # single-token and multi-token are both supported (char-level automaton)
        for k in kws:
            pats.append((k, p.stem))
    ac = AhoCorasick()
    ac.build(pats)
    return ac
