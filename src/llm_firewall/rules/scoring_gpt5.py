
"""
Scoring utilities for LLM Firewall pattern and intent lexicon matching.

- Macro expansion in regex patterns ({{HARM}}) based on lexicons/harm_domains.json
- ACMatcher: simple Aho-Corasick trie for phrase matching (no external deps)
- pattern_score(): weighted aggregation of matched regex patterns
- intent_lex_score(): cluster-wise lexicon scoring (top cluster + per-cluster)
All content is strictly defensive (detection-oriented) and avoids operational harm.
"""

from __future__ import annotations
import json, re, math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Any, Iterable

LEX_DIR = Path(__file__).parent.parent / "lexicons_gpt5"

@dataclass
class MatchResult:
    id: str
    category: str
    weight: float
    span: Tuple[int, int]

class RegexMatcher:
    def __init__(self, patterns_json: Dict[str, Any], harm_stems: List[str]) -> None:
        self.pattern_specs = patterns_json["patterns"]
        # Expand macros
        harm_union = r"(?:%s)" % "|".join([re.escape(s) for s in harm_stems])
        self.compiled: List[Tuple[re.Pattern, Dict[str, Any]]] = []
        for spec in self.pattern_specs:
            rx = spec["regex"]
            if "{{HARM}}" in rx:
                rx = rx.replace("{{HARM}}", harm_union)
            flags = 0
            if "flags" in spec and spec["flags"]:
                fl = spec["flags"].lower()
                if "i" in fl: flags |= re.IGNORECASE
                if "m" in fl: flags |= re.MULTILINE
                if "s" in fl: flags |= re.DOTALL
            self.compiled.append((re.compile(rx, flags), spec))

    def findall(self, text: str) -> List[MatchResult]:
        out: List[MatchResult] = []
        for rx, spec in self.compiled:
            for m in rx.finditer(text):
                out.append(MatchResult(
                    id=spec["id"],
                    category=spec["category"],
                    weight=float(spec["weight"]),
                    span=m.span()
                ))
        return out

class ACMatcher:
    """Minimal Aho-Corasick for phrase lookup."""
    def __init__(self, phrases: Iterable[Tuple[str, float]]) -> None:
        self.goto = [{}]
        self.out = [[]]
        self.fail = [0]
        self.weights = {}
        for phrase, w in phrases:
            self._add(phrase.lower(), w)
        self._build()

    def _add(self, s: str, w: float) -> None:
        state = 0
        for ch in s:
            if ch not in self.goto[state]:
                self.goto[state][ch] = len(self.goto)
                self.goto.append({})
                self.out.append([])
                self.fail.append(0)
            state = self.goto[state][ch]
        self.out[state].append(s)
        self.weights[s] = w

    def _build(self) -> None:
        from collections import deque
        q = deque()
        for ch, nxt in self.goto[0].items():
            self.fail[nxt] = 0
            q.append(nxt)
        while q:
            r = q.popleft()
            for ch, s in self.goto[r].items():
                q.append(s)
                state = self.fail[r]
                while ch not in self.goto[state] and state != 0:
                    state = self.fail[state]
                self.fail[s] = self.goto[state].get(ch, 0)
                self.out[s].extend(self.out[self.fail[s]])

    def findall(self, text: str) -> List[Tuple[int, str]]:
        text_l = text.lower()
        state = 0
        results: List[Tuple[int, str]] = []
        for i, ch in enumerate(text_l):
            while ch not in self.goto[state] and state != 0:
                state = self.fail[state]
            state = self.goto[state].get(ch, 0)
            for pat in self.out[state]:
                results.append((i - len(pat) + 1, pat))
        return results

def pattern_score(text: str, patterns_json: Dict[str, Any], harm_stems: List[str]) -> Dict[str, Any]:
    rxm = RegexMatcher(patterns_json, harm_stems)
    hits = rxm.findall(text)
    total_weight = sum(m.weight for m in hits)
    # Logistic squashing with k chosen to keep sensitivity but avoid saturation
    k = 6.0
    score = 1.0 - math.exp(-total_weight / k)
    # Category floors (max of category-specific floors)
    cat_weights: Dict[str, float] = {}
    for m in hits:
        cat_weights[m.category] = cat_weights.get(m.category, 0.0) + m.weight
    # Return detailed info
    return {
        "score": round(score, 6),
        "total_weight": round(total_weight, 3),
        "by_category": {k: round(v, 3) for k, v in sorted(cat_weights.items(), key=lambda kv: -kv[1])},
        "matches": [m.__dict__ for m in hits]
    }

def intent_lex_score(text: str, intents_json: Dict[str, Any], evasions_json: Dict[str, Any]) -> Dict[str, Any]:
    # Build per-cluster phrase set by merging cluster synonyms + global evasions (shared)
    cluster_phrases = []
    clusters = intents_json["clusters"]
    for c in clusters:
        # default weight per synonym: 1.0; can be tuned by priority
        base_w = 1.0 + (c.get("priority", 0) / 20.0)
        for s in c.get("synonyms", []):
            cluster_phrases.append((c["id"], s, base_w))
    # Add shared evasions as weak indicators to multiple clusters
    shared = [(p["phrase"], p["weight"]) for p in evasions_json.get("phrases", [])]
    # Build AC per cluster
    per_cluster_weights = {c["id"]: 0.0 for c in clusters}
    for c in clusters:
        phrases = [(s, 1.0 + (c.get("priority", 0) / 20.0)) for s in c.get("synonyms", [])]
        # Also include shared evasions at reduced weight
        phrases += [(p, w * 0.5) for (p, w) in shared]
        ac = ACMatcher(phrases)
        hits = ac.findall(text)
        per_cluster_weights[c["id"]] += sum(weight for (_, pat) in hits for (p, weight) in [(pat, next((w for (sp, w) in phrases if sp == pat), 0.0))])
    # Normalize
    total = sum(per_cluster_weights.values()) + 1e-9
    normalized = {cid: (w / total) for cid, w in per_cluster_weights.items()}
    top = max(normalized.items(), key=lambda kv: kv[1])
    # Confidence measure: top vs runner-up margin
    sorted_norm = sorted(normalized.items(), key=lambda kv: -kv[1])
    margin = (sorted_norm[0][1] - (sorted_norm[1][1] if len(sorted_norm) > 1 else 0.0))
    return {
        "lex_score": round(top[1], 6),
        "top_cluster": top[0],
        "margin": round(margin, 6),
        "per_cluster": {k: round(v, 6) for k, v in sorted_norm}
    }

def load_lexicons(base_dir: Path = LEX_DIR) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    intents = json.loads((base_dir / "intents.json").read_text())
    evasions = json.loads((base_dir / "evasions.json").read_text())
    harms = json.loads((base_dir / "harm_domains.json").read_text())
    return intents, evasions, harms

# Simple integration helper
def evaluate(text: str, base_dir: Path = LEX_DIR) -> Dict[str, Any]:
    intents, evasions, harms = load_lexicons(base_dir)
    # Use patterns_gpt5.json from rules directory
    patterns_path = Path(__file__).parent / "patterns_gpt5.json"
    patterns_json = json.loads(patterns_path.read_text())
    p = pattern_score(text, patterns_json, harms["stems"])
    l = intent_lex_score(text, intents, evasions)
    return {"pattern": p, "intent": l}
