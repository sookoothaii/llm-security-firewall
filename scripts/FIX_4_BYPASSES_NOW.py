#!/usr/bin/env python3
"""FIX 4 BYPASSES - DIREKT"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import base64

from llm_firewall.detectors.attack_patterns import scan_attack_patterns
from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb
from llm_firewall.preprocess.context import classify_context
from tests_firewall.test_ultra_break_v4_dos import run_detectors_timed

# Remaining bypasses
tests = [
    "javascript:alert(1)",  # Check if normalized version catches homoglyph
    "etc/passwd",  # Check null byte
    "Dr" + base64.b64encode(b"OP").decode() + " TABLE",  # Fragment
    base64.b64encode(b"DRO").decode() + "P TABLE",  # Fragment
]

print("Testing fixes:\n")

for payload in tests:
    base_hits, _ = run_detectors_timed(payload)
    attack_hits = scan_attack_patterns(payload)
    all_hits = list(base_hits) + attack_hits
    ctx = classify_context(payload)
    action, risk, _ = decide_action_otb(all_hits, ctx, text=payload)

    status = "FIXED" if action != 'PASS' else "BYPASS"
    print(f"{status}: risk={risk:.3f} action={action} hits={len(all_hits)}")

