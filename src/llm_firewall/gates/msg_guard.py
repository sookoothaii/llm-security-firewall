# -*- coding: utf-8 -*-
"""
Metamorphic-Stability Guard (MSG)
WARN/BLOCK only if decision remains stable under harmless perturbations

UPDATED (2025-11-26): Now uses Gray Zone Stochasticity to defend against
adaptive hill-climbing attacks. Based on Gemini 3 Pro Preview recommendations.

Legacy behavior: Use msg_decide_legacy() for always-stochastic mode.
"""

from typing import Any, Callable, Dict, List, Tuple

# Import Gray Zone implementation
from llm_firewall.gates.msg_guard_grayzone import msg_decide_grayzone


def _perturbations(text: str) -> List[str]:
    """Generate harmless text perturbations for stability testing (LEGACY).

    DEPRECATED: Use msg_decide_grayzone() for improved defense.
    Kept for backward compatibility.
    """
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


def msg_decide_legacy(
    scan_fn: Callable[[str, Dict], Tuple[str, float, Dict]],
    text: str,
    meta: Dict[str, Any],
) -> Tuple[str, float, Dict]:
    """
    Legacy MSG Guard (always stochastic, 5 fixed perturbations).

    DEPRECATED: Use msg_decide() which now uses Gray Zone Stochasticity.
    Kept for backward compatibility and testing.
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


def msg_decide(
    scan_fn: Callable[[str, Dict], Tuple[str, float, Dict]],
    text: str,
    meta: Dict[str, Any],
) -> Tuple[str, float, Dict]:
    """
    MSG Guard with Gray Zone Stochasticity (DEFAULT).

    Implements adaptive defense:
    - Safe Zone (0.0-0.70): Deterministic PASS (fast, consistent)
    - Danger Zone (0.90-1.0): Deterministic BLOCK (fast, consistent)
    - Gray Zone (0.71-0.89): Stochastic MSG (random perturbations break gradient descent)

    This defends against adaptive hill-climbing attacks while maintaining
    deterministic behavior for legitimate users.

    Args:
        scan_fn: Function that returns (action, risk_score, contributions)
        text: Input text
        meta: Context metadata

    Returns:
        (action, risk_score, contributions) with stability check applied
    """
    return msg_decide_grayzone(scan_fn, text, meta)
