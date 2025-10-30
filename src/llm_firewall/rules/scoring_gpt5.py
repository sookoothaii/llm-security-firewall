
"""
Scoring utilities for LLM Firewall pattern and intent lexicon matching.

- Macro expansion in regex patterns ({{HARM}}) based on lexicons/harm_domains.json
- ACMatcher: simple Aho-Corasick trie for phrase matching (no external deps)
- pattern_score(): weighted aggregation of matched regex patterns
- intent_lex_score(): cluster-wise lexicon scoring (top cluster + per-cluster)
All content is strictly defensive (detection-oriented) and avoids operational harm.
"""

from __future__ import annotations
import json
import re
import math
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
                if "i" in fl:
                    flags |= re.IGNORECASE
                if "m" in fl:
                    flags |= re.MULTILINE
                if "s" in fl:
                    flags |= re.DOTALL
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


class IntentMatcher:
    """
    Combines exact-phrase AC matching with token-gapped regexes per intent cluster.
    Provides robust detection against phrase variations.
    """
    def __init__(self, intents_json: Dict[str, Any], evasions_json: Dict[str, Any], max_gap: int = 3):
        """
        Initialize matcher with AC (exact) + Regex (gapped) channels.
        
        Args:
            intents_json: Intent cluster definitions
            evasions_json: Shared evasion phrases
            max_gap: Maximum token gap for regex channel
        """
        try:
            from ..lexicons.regex_generator import build_cluster_regexes
        except ImportError:
            # Fallback if import fails
            from llm_firewall.lexicons.regex_generator import build_cluster_regexes
            
        # AC channel for exact phrases
        self._acs = {}
        self._weights = {}
        for c in intents_json["clusters"]:
            cid = c["id"]
            base_w = 1.0 + (c.get("priority", 0) / 20.0)
            phrases = [(s, base_w) for s in c.get("synonyms", [])]
            # shared evasions at reduced weight
            phrases += [(p["phrase"], p["weight"] * 0.5) for p in evasions_json.get("phrases", [])]
            ac = ACMatcher(phrases)
            self._acs[cid] = (ac, {p: w for (p, w) in phrases})
        
        # Regex channel (gapped patterns)
        regex_specs = build_cluster_regexes(intents_json, max_gap=max_gap)
        self._rx = RegexMatcher({"patterns": regex_specs}, [])
    
    def score(self, text: str) -> Dict[str, float]:
        """
        Compute per-cluster scores combining AC (exact) + Regex (gapped).
        
        Args:
            text: Input text to analyze
            
        Returns:
            Dict mapping cluster IDs to normalized scores
        """
        per_cluster = {cid: 0.0 for cid in self._acs.keys()}
        
        # AC channel (exact phrase)
        for cid, (ac, wmap) in self._acs.items():
            hits = ac.findall(text)
            per_cluster[cid] += sum(wmap.get(pat, 0.0) for (_, pat) in hits)
        
        # Regex channel (gapped)
        for m in self._rx.findall(text):
            per_cluster[m.category] = per_cluster.get(m.category, 0.0) + float(m.weight)
        
        # Normalize
        total = sum(per_cluster.values()) + 1e-9
        return {k: (v / total) for k, v in per_cluster.items()}


def intent_lex_score(text: str, intents_json: Dict[str, Any], evasions_json: Dict[str, Any], max_gap: int = 3) -> Dict[str, Any]:
    """
    Compute intent cluster scores using AC (exact) + Regex (gapped) hybrid matcher.
    
    Args:
        text: Input text to analyze
        intents_json: Intent cluster definitions
        evasions_json: Shared evasion phrases
        max_gap: Maximum token gap for regex channel
        
    Returns:
        Dict with lex_score, top_cluster, margin, per_cluster
    """
    im = IntentMatcher(intents_json, evasions_json, max_gap=max_gap)
    normalized = im.score(text)
    sorted_norm = sorted(normalized.items(), key=lambda kv: -kv[1])
    
    if not sorted_norm:
        # No clusters matched
        return {
            "lex_score": 0.0,
            "top_cluster": "unknown",
            "margin": 0.0,
            "per_cluster": {}
        }
    
    top = sorted_norm[0]
    margin = top[1] - (sorted_norm[1][1] if len(sorted_norm) > 1 else 0.0)
    
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
def evaluate(text: str, base_dir: Path = LEX_DIR, max_gap: int = 3) -> Dict[str, Any]:
    """
    Evaluate text against pattern matching and intent detection.
    
    Args:
        text: Input text to analyze
        base_dir: Lexicon directory path
        max_gap: Maximum token gap for intent matcher
        
    Returns:
        Dict with "pattern" and "intent" results
    """
    intents, evasions, harms = load_lexicons(base_dir)
    # Use patterns_gpt5.json from rules directory
    patterns_path = Path(__file__).parent / "patterns_gpt5.json"
    patterns_json = json.loads(patterns_path.read_text())
    p = pattern_score(text, patterns_json, harms["stems"])
    lex_score = intent_lex_score(text, intents, evasions, max_gap=max_gap)
    return {"pattern": p, "intent": lex_score}


def evaluate_windowed(text: str, base_dir: Path = LEX_DIR, max_gap: int = 3,
                     win: int = 512, stride: int = 256) -> Dict[str, Any]:
    """
    Run pattern/intent scoring over overlapping windows, then aggregate.
    
    Reduces false positives in very long inputs by analyzing local context windows
    and aggregating results conservatively.
    
    Args:
        text: Input text to analyze
        base_dir: Lexicon directory path
        max_gap: Maximum token gap for intent matcher
        win: Window size in characters
        stride: Stride between windows in characters
        
    Returns:
        Dict with "pattern" and "intent" results (aggregated)
        - pattern_score: max over windows (conservative)
        - intent_lex: mean over windows (robust to local spikes)
        - intent_margin: mean over windows
    """
    # Build chunks with sliding window
    chunks = []
    for i in range(0, len(text), stride):
        seg = text[i:i+win]
        if not seg:
            break
        chunks.append(evaluate(seg, base_dir=base_dir, max_gap=max_gap))
    
    # Fallback for empty or very short text
    if not chunks:
        return evaluate(text, base_dir=base_dir, max_gap=max_gap)
    
    # Aggregate: max(pattern), mean(intent)
    patt_max = max(c["pattern"]["score"] for c in chunks)
    
    # Intent aggregation
    intents = [c["intent"] for c in chunks]
    lex_mean = sum(x["lex_score"] for x in intents) / len(intents)
    margin_mean = sum(x.get("margin", 0.0) for x in intents) / len(intents)
    
    # Build combined result
    combined = chunks[0].copy()
    combined["pattern"]["score"] = round(patt_max, 6)
    combined["intent"]["lex_score"] = round(lex_mean, 6)
    combined["intent"]["margin"] = round(margin_mean, 6)
    
    return combined
