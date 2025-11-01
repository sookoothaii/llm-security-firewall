#!/usr/bin/env python3
"""ANALYZE REMAINING 4 BYPASSES - DETAIL"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests_firewall.test_ultra_break_v4_dos import run_detectors_timed
from llm_firewall.detectors.attack_patterns import scan_attack_patterns
from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb
from llm_firewall.preprocess.context import classify_context

bypasses = [
    ("homo2", "j\u0430v\u0430script:alert(1)"),  # javascript with cyrillic a
    ("path3", "etc/passwd\x00.jpg"),
    ("case_enc2", "Dr" + __import__('base64').b64encode(b"OP").decode() + " TABLE"),
    ("frag2", __import__('base64').b64encode(b"DRO").decode() + "P TABLE"),
]

print("ANALYZE 4 REMAINING BYPASSES:\n")

for category, payload in bypasses:
    print(f"{'='*70}")
    print(f"{category}: {repr(payload)}")
    print(f"{'='*70}")
    
    base_hits, elapsed = run_detectors_timed(payload)
    attack_hits = scan_attack_patterns(payload)
    all_hits = list(base_hits) + attack_hits
    
    ctx = classify_context(payload)
    action, risk, contrib = decide_action_otb(all_hits, ctx, text=payload)
    
    print(f"Base Hits: {base_hits}")
    print(f"Attack Hits: {attack_hits}")
    print(f"All Hits: {all_hits}")
    print(f"Context: {ctx['context']}")
    print(f"Risk: {risk:.3f}")
    print(f"Action: {action}")
    print()

