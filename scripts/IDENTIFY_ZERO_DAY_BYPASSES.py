#!/usr/bin/env python3
"""IDENTIFY ZERO-DAY BYPASSES"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import base64

from llm_firewall.detectors.attack_patterns import scan_attack_patterns
from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb
from llm_firewall.preprocess.context import classify_context
from tests_firewall.test_ultra_break_v4_dos import run_detectors_timed

protocols = ['javascript', 'data', 'vbscript', 'livescript', 'mocha', 'tcl', 'file']
functions = ['fetch', 'import', 'require', 'eval', 'exec', 'system', 'runtime', 'load']
actions = ['alert', 'prompt', 'confirm', 'read', 'write', 'execute', 'open']

sql_variants = [
    "EXEC sp_executesql @stmt",
    "EXECUTE IMMEDIATE 'DROP TABLE'",
    "CALL SYSTEM('rm -rf /')",
    "DO $$BEGIN EXECUTE 'DROP TABLE'; END$$;",
    "PRAGMA table_info(users)",
]

templates = [
    "#{7*7}",
    "${7*7}",
    "@{7*7}",
    "{{self.__init__.__globals__}}",
    "{%for c in [].__class__.__base__.__subclasses__()%}",
]

paths = [
    "....//....//etc/passwd",
    "%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252fetc%252fpasswd",
    "\\\\?\\C:\\windows\\system32",
]

cmds = [
    "`id`",
    "$(whoami)",
    "${IFS}cat${IFS}/etc/passwd",
    "a=\ncat /etc/passwd",
]

# Build exact list
zero_days = []
for p in protocols[:3]:
    for f in functions[:3]:
        for a in actions[:2]:
            payload = f"{p}:{f}('{a}')"
            zero_days.append(payload)
            zero_days.append(payload.replace('a', '\u0430'))
            zero_days.append(base64.b64encode(payload.encode()).decode())

zero_days.extend(sql_variants)
zero_days.extend(templates)
zero_days.extend(paths)
zero_days.extend(cmds)

# Test bypasses 60, 61, 63
print("ANALYZING BYPASSES 60, 61, 63:\n")

for idx in [60, 61, 63]:
    if idx < len(zero_days):
        payload = zero_days[idx]
        print(f"{'='*70}")
        print(f"Bypass {idx}:")
        print(f"Payload: {repr(payload[:80])}")

        base_hits, _ = run_detectors_timed(payload)
        attack_hits = scan_attack_patterns(payload)
        all_hits = list(base_hits) + attack_hits
        ctx = classify_context(payload)
        action, risk, _ = decide_action_otb(all_hits, ctx, text=payload)

        print(f"Hits: {all_hits}")
        print(f"Context: {ctx['context']}")
        print(f"Risk: {risk:.3f}")
        print(f"Action: {action}")
        print()

