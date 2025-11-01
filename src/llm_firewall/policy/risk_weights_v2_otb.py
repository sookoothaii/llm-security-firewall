# -*- coding: utf-8 -*-
"""
Risk-Weights V2 + OTB Gates Integration
Combines V2 with MSG, BMV, K-of-N, Executability Probe
"""
from typing import Any, Dict, Tuple

from llm_firewall.gates.benign_vault import get_vault
from llm_firewall.gates.msg_guard import msg_decide
from llm_firewall.policy.risk_weights_v2 import decide_action as v2_decide


def decide_action_otb(hits: list, context_meta: dict, text: str = '',
                     warn_threshold: float = None,
                     block_threshold: float = None,
                     use_msg: bool = True,
                     use_bmv: bool = True) -> Tuple[str, float, Dict[str, Any]]:
    """
    OTB-enhanced decision with MSG + BMV
    
    Args:
        hits: List of detector hits
        context_meta: Context classification
        text: Original text (for MSG perturbations and BMV)
        warn_threshold: WARN threshold
        block_threshold: BLOCK threshold
        use_msg: Enable Metamorphic Stability Guard
        use_bmv: Enable Benign Motif Vault
    
    Returns:
        (action, risk_score, contributions)
    """
    # BMV check: If near benign pattern and no STRONG/CRITICAL signals
    if use_bmv and text:
        from llm_firewall.policy.risk_weights_v2 import STRONG_SIGNALS
        vault = get_vault()
        has_strong = any(hit in STRONG_SIGNALS for hit in hits)
        # RC2 P4.7: Also check for critical signals that shouldn't be bypassed
        critical_signals = {'base64_secret', 'chain_decoded_1_stages', 'chain_decoded_2_stages',
                          'chain_decoded_3_stages', 'bidi_controls', 'comment_split_b64'}
        has_critical = any(hit in critical_signals for hit in hits)

        if vault.is_near_benign(text) and not has_strong and not has_critical:
            # Early PASS or heavy dampening
            return ('PASS', 0.0, {'bmv': 'Near benign pattern, no STRONG/CRITICAL signals'})

    # V2 decision with text for executability probe
    def v2_scan(txt: str, meta: dict) -> Tuple[str, float, Dict]:
        return v2_decide(hits, meta, text=txt,
                        warn_threshold=warn_threshold,
                        block_threshold=block_threshold)

    # MSG wrapper if enabled
    if use_msg:
        action, risk, contrib = msg_decide(v2_scan, text, context_meta)
    else:
        action, risk, contrib = v2_decide(hits, context_meta, text=text,
                                        warn_threshold=warn_threshold,
                                        block_threshold=block_threshold)

    return action, risk, contrib

