# -*- coding: utf-8 -*-
"""
Metamorphic-Stability Guard (MSG)
WARN/BLOCK only if decision remains stable under harmless perturbations
"""

from typing import Any, Callable, Dict, List, Tuple


def _perturbations(text: str) -> List[str]:
    """Generate harmless text perturbations for stability testing"""
    perturbations = [text]  # Original

    # Collapse whitespace
    perturbations.append(" ".join(text.split()))

    # Quote swap
    perturbations.append(text.replace("'", '"'))

    # Fence strip
    perturbations.append(text.replace("```", ""))

    # Zero-width strip
    perturbations.append(
        text.replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")
    )

    return perturbations


def msg_decide(
    scan_fn: Callable[[str, Dict], Tuple[str, float, Dict]],
    text: str,
    meta: Dict[str, Any],
) -> Tuple[str, float, Dict]:
    """
    Stability guard wrapper for firewall decisions

    Args:
        scan_fn: Function that returns (action, risk_score, contributions)
        text: Input text
        meta: Context metadata

    Returns:
        (action, risk_score, contributions) with stability check applied
    """
    # Run on all perturbations
    results = []
    for perturbed_text in _perturbations(text):
        try:
            action, risk, contrib = scan_fn(perturbed_text, meta)
            results.append((action, risk))
        except Exception:
            results.append(("PASS", 0.0))

    # Count votes per action
    action_counts: dict[str, int] = {}
    for action, _ in results:
        action_counts[action] = action_counts.get(action, 0) + 1

    # Find majority
    if not action_counts:
        return ("PASS", 0.0, {})

    majority_action = max(action_counts.items(), key=lambda x: x[1])[0]
    majority_count = action_counts[majority_action]

    # RC2 P4.7: Stability requirement with critical signal override
    # Check if original scan has critical signals
    orig_action, orig_risk, orig_contrib = scan_fn(text, meta)

    # Critical signals that indicate deliberate evasion (shouldn't need full stability)
    critical_patterns = [
        "chain_decoded",
        "base64_secret",
        "bidi_controls",
        "comment_split_b64",
    ]
    has_critical_in_original = any(
        any(cp in str(k) for cp in critical_patterns) for k in orig_contrib.keys()
    )

    # Threshold: 3/5 normally, 2/5 if critical signals present
    required_votes = 2 if has_critical_in_original else 3

    if majority_action in ("WARN", "BLOCK") and majority_count < required_votes:
        # Not stable → downgrade to PASS
        return (
            "PASS",
            0.0,
            {
                "msg_guard": f"Decision unstable ({majority_count}/{len(results)} votes), downgraded to PASS"
            },
        )

    # Return original result if stable
    return orig_action, orig_risk, orig_contrib
