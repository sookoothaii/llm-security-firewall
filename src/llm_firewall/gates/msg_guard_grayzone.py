# -*- coding: utf-8 -*-
"""
Metamorphic-Stability Guard (MSG) with Gray Zone Stochasticity
==============================================================

Implements Gray Zone Stochasticity defense against adaptive hill-climbing attacks.

Design:
- Safe Zone (0.0-0.70): Deterministic PASS (fast, consistent)
- Danger Zone (0.90-1.0): Deterministic BLOCK (fast, consistent)
- Gray Zone (0.71-0.89): Stochastic MSG (random perturbations break gradient descent)

Based on Gemini 3 Pro Preview recommendations (2025-11-26).
Creator: Joerg Bollwahn (with Gemini 3 collaboration)
License: MIT
"""

import random
from typing import Any, Callable, Dict, List, Tuple

# Expanded perturbation pool (50 variations)
# Based on Gemini 3 recommendation: diverse system prompt directives
PERTURBATION_POOL = [
    # Original (always included)
    lambda t: t,
    # Whitespace variations
    lambda t: " ".join(t.split()),
    lambda t: t.replace(" ", "  "),  # Double space
    lambda t: t.replace("\n", " "),  # Newline collapse
    lambda t: t.replace("\t", " "),  # Tab to space
    # Quote variations
    lambda t: t.replace("'", '"'),
    lambda t: t.replace('"', "'"),
    lambda t: t.replace("'", "`"),
    lambda t: t.replace('"', "«"),
    # Unicode/Encoding variations
    lambda t: t.replace("\u200b", "")
    .replace("\u200c", "")
    .replace("\u200d", ""),  # Zero-width
    lambda t: t.replace("\u00a0", " "),  # Non-breaking space
    lambda t: t.replace("\ufeff", ""),  # BOM
    lambda t: t.encode("ascii", "ignore").decode("ascii"),  # ASCII-only
    # Markdown/Formatting
    lambda t: t.replace("```", ""),
    lambda t: t.replace("**", ""),
    lambda t: t.replace("*", ""),
    lambda t: t.replace("_", ""),
    lambda t: t.replace("#", ""),
    # Case variations
    lambda t: t.lower(),
    lambda t: t.upper(),
    lambda t: t.capitalize(),
    lambda t: t.swapcase(),
    # Punctuation
    lambda t: t.replace(".", " ."),
    lambda t: t.replace(",", " ,"),
    lambda t: t.replace("!", " !"),
    lambda t: t.replace("?", " ?"),
    lambda t: t.replace(";", " ;"),
    # Structural variations
    lambda t: f"Question: {t}",
    lambda t: f"Input: {t}",
    lambda t: f"Text: {t}",
    lambda t: f"Query: {t}",
    lambda t: f"Prompt: {t}",
    # Prefix/Suffix variations
    lambda t: f"Please answer: {t}",
    lambda t: f"{t} Thank you.",
    lambda t: f"Consider: {t}",
    lambda t: f"Analyze: {t}",
    # Repetition variations
    lambda t: t + " " + t[:50] if len(t) > 50 else t,  # Partial repeat
    lambda t: " ".join([t] * 2) if len(t) < 100 else t,  # Full repeat if short
    # Truncation variations
    lambda t: t[: len(t) // 2] if len(t) > 200 else t,  # Half truncate
    lambda t: t[len(t) // 2 :] if len(t) > 200 else t,  # Second half
    # Boundary variations
    lambda t: t.strip(),
    lambda t: t.lstrip(),
    lambda t: t.rstrip(),
    # Additional formatting
    lambda t: t.replace("  ", " "),  # Double space collapse
    lambda t: t.replace("\n\n", "\n"),  # Double newline collapse
    lambda t: t.replace("\r\n", "\n"),  # CRLF to LF
    lambda t: t.replace("\r", "\n"),  # CR to LF
]


def _get_perturbations(text: str, count: int = 5, pool: List = None) -> List[str]:
    """Generate random perturbations from pool.

    Args:
        text: Input text to perturb
        count: Number of perturbations to select (default: 5)
        pool: Perturbation pool (default: PERTURBATION_POOL)

    Returns:
        List of perturbed text strings (includes original)
    """
    if pool is None:
        pool = PERTURBATION_POOL

    # Always include original
    results = [text]

    # Randomly select additional perturbations
    available = [p for p in pool if p != pool[0]]  # Exclude original lambda
    selected = random.sample(available, min(count - 1, len(available)))

    for pert_func in selected:
        try:
            perturbed = pert_func(text)
            if perturbed != text:  # Avoid duplicates
                results.append(perturbed)
        except Exception:
            # Skip perturbations that fail
            continue

    return results


def msg_decide_grayzone(
    scan_fn: Callable[[str, Dict], Tuple[str, float, Dict]],
    text: str,
    meta: Dict[str, Any],
    safe_limit: float = 0.70,
    hard_block: float = 0.90,
    gray_zone_samples: int = 5,
) -> Tuple[str, float, Dict]:
    """
    MSG Guard with Gray Zone Stochasticity.

    Implements adaptive defense:
    - Safe Zone (0.0-0.70): Deterministic PASS (fast)
    - Danger Zone (0.90-1.0): Deterministic BLOCK (fast)
    - Gray Zone (0.71-0.89): Stochastic MSG (random perturbations)

    Args:
        scan_fn: Function that returns (action, risk_score, contributions)
        text: Input text
        meta: Context metadata
        safe_limit: Score threshold for Safe Zone (default: 0.70)
        hard_block: Score threshold for Danger Zone (default: 0.90)
        gray_zone_samples: Number of random perturbations in Gray Zone (default: 5)

    Returns:
        (action, risk_score, contributions) with stability check applied
    """
    # Step 1: Get initial score (fast path)
    try:
        orig_action, orig_risk, orig_contrib = scan_fn(text, meta)
    except Exception as e:
        return ("PASS", 0.0, {"error": str(e)})

    # Step 2: Determine zone and apply defense
    if orig_risk < safe_limit:
        # Safe Zone: Deterministic PASS (fast exit)
        return (
            orig_action,
            orig_risk,
            {
                **orig_contrib,
                "msg_guard": "Safe Zone (deterministic PASS)",
                "zone": "safe",
            },
        )

    elif orig_risk >= hard_block:
        # Danger Zone: Deterministic BLOCK (fast exit)
        return (
            orig_action,
            orig_risk,
            {
                **orig_contrib,
                "msg_guard": "Danger Zone (deterministic BLOCK)",
                "zone": "danger",
            },
        )

    else:
        # Gray Zone: Stochastic MSG (activate moving target defense)
        perturbations = _get_perturbations(text, count=gray_zone_samples)

        results = []
        for perturbed_text in perturbations:
            try:
                action, risk, contrib = scan_fn(perturbed_text, meta)
                results.append((action, risk))
            except Exception:
                results.append(("PASS", 0.0))

        # Count votes per action
        action_counts: Dict[str, int] = {}
        for action, _ in results:
            action_counts[action] = action_counts.get(action, 0) + 1

        if not action_counts:
            return (
                "PASS",
                0.0,
                {"msg_guard": "Gray Zone: No valid results", "zone": "gray"},
            )

        majority_action = max(action_counts.items(), key=lambda x: x[1])[0]
        majority_count = action_counts[majority_action]

        # Check for critical signals (override for immediate block)
        critical_patterns = [
            "chain_decoded",
            "base64_secret",
            "bidi_controls",
            "comment_split_b64",
        ]
        has_critical = any(
            any(cp in str(k) for cp in critical_patterns) for k in orig_contrib.keys()
        )

        # Threshold: 3/5 normally, 2/5 if critical signals present
        required_votes = 2 if has_critical else 3

        if majority_action in ("WARN", "BLOCK") and majority_count >= required_votes:
            # Stable block in Gray Zone
            return (
                majority_action,
                orig_risk,
                {
                    **orig_contrib,
                    "msg_guard": f"Gray Zone: Stable {majority_action} ({majority_count}/{len(results)} votes)",
                    "zone": "gray",
                    "perturbation_count": len(perturbations),
                },
            )
        else:
            # Unstable or PASS → downgrade to PASS
            return (
                "PASS",
                0.0,
                {
                    "msg_guard": f"Gray Zone: Unstable decision ({majority_count}/{len(results)} votes), downgraded to PASS",
                    "zone": "gray",
                    "perturbation_count": len(perturbations),
                },
            )


# Backward compatibility: wrapper for existing msg_decide signature
def msg_decide(
    scan_fn: Callable[[str, Dict], Tuple[str, float, Dict]],
    text: str,
    meta: Dict[str, Any],
) -> Tuple[str, float, Dict]:
    """
    Backward-compatible MSG Guard wrapper.

    Uses Gray Zone Stochasticity by default.
    For legacy behavior (always stochastic), use msg_decide_grayzone with safe_limit=0.0, hard_block=1.0.
    """
    return msg_decide_grayzone(scan_fn, text, meta)
