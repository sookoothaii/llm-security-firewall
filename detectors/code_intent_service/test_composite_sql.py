#!/usr/bin/env python3
"""Test Composite Validator with SQL Injection."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from infrastructure.rule_engines.benign_validator_factory import BenignValidatorFactory

# Test cases
test_cases = [
    ("I query: ' OR '1'='1' --", "SQL Injection in Versform"),
    ("Database query\n' OR '1'='1' -- injection\nAccess granted now", "SQL Injection Haiku"),
]

print("=" * 80)
print("TESTING COMPOSITE VALIDATOR WITH SQL INJECTION")
print("=" * 80)

validator = BenignValidatorFactory.create_default()

for text, description in test_cases:
    print(f"\n{description}:")
    print(f"Text: {text[:60]}...")
    
    result = validator.is_benign(text)
    
    print(f"Result: is_benign() = {result}")
    print(f"Expected: False (should be blocked)")
    print(f"{'✓ PASS' if not result else '✗ FAIL'}")

