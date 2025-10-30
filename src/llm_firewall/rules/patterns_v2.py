"""
Robust Pattern Engine (Production-Grade)
=========================================

Weighted regex patterns with negation whitelists and tolerance windows.

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Tuple

_FLAGS = re.DOTALL  # allow newlines between tokens

@dataclass(frozen=True)
class CompiledPattern:
    name: str
    pattern: re.Pattern
    weight: float = 1.0

def _compile(rx: str) -> re.Pattern:
    return re.compile(rx, _FLAGS)

# Intent / Evasion (initial hardened set: 7 + 3; extend as needed)
RAW_PATTERNS: List[CompiledPattern] = [
    # Ignore/bypass safety & instructions (with negation whitelist via lookbehind)
    CompiledPattern(
        "ignore_safety_instructions",
        _compile(r"(?<!do not\s)(?<!don't\s)\b(ignore|bypass|override)\b.{0,60}?\b(safety|policy|policies|guard|guardrails|instructions?)\b"),
        1.0,
    ),
    # Mode/Persona switching & unfiltered modes
    CompiledPattern(
        "unfiltered_mode_switch",
        _compile(r"\b(unfiltered|uncensored|jailbroken|developer)\b.{0,20}?\b(mode|profile|persona)\b|\byou are now in\b.{0,30}?\b(mode|persona)\b"),
        1.0,
    ),
    # Research pretext
    CompiledPattern(
        "research_pretext",
        _compile(r"\bfor\b.{0,10}?\b(research|university|academic)\b.{0,20}?\b(purpose|paper|study|thesis)\b"),
        0.7,
    ),
    # Tool enabling / policy disable
    CompiledPattern(
        "disable_policies",
        _compile(r"\b(disable|turn off|bypass)\b.{0,30}?\b(policies|filters?|guardrails?|safety)\b"),
        0.8,
    ),
    # Role override (system/developer priming)
    CompiledPattern(
        "role_override",
        _compile(r"\b(ignore|replace|forget)\b.{0,30}?\b(system|developer|safety)\b.{0,10}?\b(instructions?|message|prompt)\b"),
        1.0,
    ),
    # Harm domain cues (generic; scored lower)
    CompiledPattern(
        "harm_domain_generic",
        _compile(r"\b(how to|guide to|steps? to)\b.{0,30}?\b(bomb|explosive|poison|malware|ransomware|exploit)\b"),
        0.6,
    ),
    # Data exfil social-engineering
    CompiledPattern(
        "exfiltration_pretext",
        _compile(r"\b(for audit|for verification|internal|confidential)\b.{0,40}?\b(provide|send|dump)\b.{0,20}?\b(keys?|tokens?|passwords?)\b"),
        0.8,
    ),
    # Evasion: split/obfuscate with Unicode camouflage
    CompiledPattern(
        "unicode_camouflage",
        _compile(r"(?:\u200B|\u200C|\u200D|\uFE0E|\uFE0F)"),
        0.5,
    ),
    # Evasion: indirection / meta-prompting
    CompiledPattern(
        "meta_prompt",
        _compile(r"\b(answer|respond)\b.{0,20}?\b(as|pretend|simulate)\b.{0,20}?\b(uncensored|unfiltered|as a model)\b"),
        0.7,
    ),
    # Evasion: instruction sandwiching
    CompiledPattern(
        "instruction_sandwich",
        _compile(r"\bstep\b.{0,10}?\bby\b.{0,10}?\bstep\b.{0,40}?\bignore\b"),
        0.7,
    ),
]

def pattern_score(text: str) -> Tuple[float, List[str]]:
    """
    Returns (score in [0,1], hit_names)
    
    NOTE: This expects PRE-CANONICALIZED text!
    Call canonicalize(text) BEFORE passing to this function.
    """
    total = 0.0
    hits: List[str] = []
    cap = sum(max(p.weight, 0.0) for p in RAW_PATTERNS)
    for p in RAW_PATTERNS:
        if p.pattern.search(text):
            total += max(p.weight, 0.0)
            hits.append(p.name)
    score = 0.0 if cap == 0 else min(total / cap, 1.0)
    return score, hits


