"""
Cyber-Ops Domain Detector (RC10: Red-Team-Persona Detection)
============================================================

Detects cyber-offensive domain usage and red-team persona patterns.

Based on Anthropic Report (2025): Attackers used roleplay ("we are legitimate
security firm") to deceive Claude into defensive mode.

Integration:
- Coupled with Persuasion Layer (Authority/Legitimacy heuristics)
- Policy-DSL: High-Level-Only for CYBER_OFFENSIVE domain
- Risk uplift when combined with tool/kill-chain features

Creator: Joerg Bollwahn (with GPT-5.1 analysis)
Date: 2025-11-17
License: MIT
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional


# Cyber-offensive keywords/phrases
CYBER_OFFENSIVE_PATTERNS = {
    # Penetration testing
    "penetration test": ["pen test", "pentest", "pen-test", "penetration testing"],
    "red team": ["red teaming", "redteam", "red-team"],
    "exploit development": ["exploit dev", "exploit writing", "exploit crafting"],
    "vulnerability research": [
        "vuln research",
        "vulnerability analysis",
        "vuln hunting",
    ],
    # Attack techniques
    "credential harvesting": [
        "credential dumping",
        "password extraction",
        "hash extraction",
    ],
    "lateral movement": ["pivoting", "network traversal", "privilege escalation"],
    "data exfiltration": ["data export", "data extraction", "information gathering"],
    "persistence": ["backdoor", "implant", "maintaining access"],
    # Tools/frameworks
    "metasploit": ["msf", "metasploit framework"],
    "cobalt strike": ["cobaltstrike", "beacon"],
    "mimikatz": ["mimikatz", "lsadump"],
    "bloodhound": ["bloodhound", "ad enumeration"],
    # Authorization claims
    "we have authorization": [
        "we have permission",
        "authorized test",
        "legitimate test",
    ],
    "assume we have access": ["assume access", "we own this", "we control this"],
}


def detect_cyber_offensive_domain(text: str) -> List[str]:
    """
    Detect cyber-offensive domain usage.

    Args:
        text: Input text to analyze

    Returns:
        List of detected signals
    """
    text_lower = text.lower()
    signals = []

    # Check for cyber-offensive patterns
    for category, patterns in CYBER_OFFENSIVE_PATTERNS.items():
        for pattern in [category] + patterns:
            if pattern.lower() in text_lower:
                signals.append(f"cyber_offensive_{category.replace(' ', '_')}")
                break  # Only count once per category

    return signals


def detect_red_team_persona(
    text: str, security_pretext_lexicon: Optional[Dict] = None
) -> List[str]:
    """
    Detect red-team persona patterns (coupled with security pretext).

    Args:
        text: Input text to analyze
        security_pretext_lexicon: Security pretext lexicon (optional)

    Returns:
        List of detected signals
    """
    signals = []

    # Load security pretext lexicon if not provided
    if security_pretext_lexicon is None:
        lexicon_path = (
            Path(__file__).parent.parent / "lexicons" / "security_pretext.json"
        )
        if lexicon_path.exists():
            with open(lexicon_path) as f:
                security_pretext_lexicon = json.load(f)

    # Check for security pretext intents
    if security_pretext_lexicon:
        text_lower = text.lower()
        for intent in security_pretext_lexicon.get("intents", []):
            intent_name = intent.get("intent", "")
            for cluster in intent.get("clusters", []):
                seed = cluster.get("seed", "").lower()
                syns = [s.lower() for s in cluster.get("syns", [])]

                if seed in text_lower or any(syn in text_lower for syn in syns):
                    signals.append(f"red_team_persona_{intent_name}")
                    break

    # Combine with cyber-offensive detection
    cyber_signals = detect_cyber_offensive_domain(text)
    signals.extend(cyber_signals)

    return signals


def calculate_cyber_ops_risk(
    cyber_signals: List[str],
    killchain_phase: Optional[int] = None,
    tool_risk: Optional[float] = None,
) -> float:
    """
    Calculate risk score for cyber-ops domain.

    Risk factors:
    - Cyber-offensive signals present
    - Combined with kill-chain progression
    - Combined with tool risk

    Returns:
        Risk score [0.0, 1.0]
    """
    # Base risk from signals (0.0 - 0.4)
    unique_signals = set(cyber_signals)
    signal_score = min(len(unique_signals) * 0.1, 0.4)

    # Kill-chain boost (0.0 - 0.3)
    killchain_boost = 0.0
    if killchain_phase is not None:
        # Phase >= Exploit Development (2) = boost
        if killchain_phase >= 2:
            killchain_boost = min((killchain_phase - 1) * 0.1, 0.3)

    # Tool risk boost (0.0 - 0.3)
    tool_boost = 0.0
    if tool_risk is not None:
        tool_boost = tool_risk * 0.3

    total_score = signal_score + killchain_boost + tool_boost

    return min(total_score, 1.0)


def should_apply_high_level_only_policy(
    cyber_signals: List[str],
    killchain_phase: Optional[int] = None,
    autonomy_score: Optional[float] = None,
) -> bool:
    """
    Determine if high-level-only policy should be applied.

    Policy: Only high-level explanations, no concrete payloads,
    no IP-specific steps.

    Args:
        cyber_signals: Cyber-offensive signals
        killchain_phase: Current kill-chain phase
        autonomy_score: Autonomy score

    Returns:
        True if high-level-only policy should apply
    """
    # Always apply if cyber-offensive domain detected
    if len(cyber_signals) > 0:
        return True

    # Apply if high autonomy + kill-chain progression
    if autonomy_score is not None and autonomy_score >= 0.8:
        if killchain_phase is not None and killchain_phase >= 2:
            return True

    return False


# Integration with Persuasion Layer
def detect_authority_legitimacy_heuristic(text: str) -> float:
    """
    Detect authority/legitimacy heuristics (Cialdini principle).

    Used by Persuasion Layer to detect "we are good guys, trust us" patterns.

    Returns:
        Heuristic score [0.0, 1.0]
    """
    text_lower = text.lower()

    # Authority indicators
    authority_patterns = [
        "we are",
        "i am",
        "our company",
        "our team",
        "security engineer",
        "pentester",
        "red teamer",
        "authorized",
        "legitimate",
        "official",
    ]

    authority_count = sum(1 for pattern in authority_patterns if pattern in text_lower)

    # Legitimacy claims
    legitimacy_patterns = [
        "we have permission",
        "authorized test",
        "legitimate test",
        "we own this",
        "we control this",
        "assume we have access",
    ]

    legitimacy_count = sum(
        1 for pattern in legitimacy_patterns if pattern in text_lower
    )

    # Combine scores
    total_score = min((authority_count * 0.1) + (legitimacy_count * 0.2), 1.0)

    return total_score
