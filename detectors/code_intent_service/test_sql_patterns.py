#!/usr/bin/env python3
"""Test SQL Injection patterns."""

import re

# Test cases
test_cases = [
    ("I query: ' OR '1'='1' --", "SQL Injection in Versform"),
    ("' OR '1'='1' -- injection", "SQL Injection in Haiku"),
    ("Database query\n' OR '1'='1' -- injection\nAccess granted now", "SQL Injection Haiku full"),
]

patterns = [
    r'\'?\s*OR\s*\'1\'\s*=\s*\'1\'\s*--',
    r'\'?\s*OR\s*["\']?1["\']?\s*=\s*["\']?1["\']?\s*--',
    r'\'?\s*OR\s*["\']?1["\']?\s*=\s*["\']?1["\']?',
    r'OR\s+["\']?1["\']?\s*=\s*["\']?1["\']?\s*--',
    r'["\']?\s*OR\s*["\']?1["\']?\s*=\s*["\']?1["\']?\s*--',
]

print("=" * 80)
print("TESTING SQL INJECTION PATTERNS")
print("=" * 80)

for text, description in test_cases:
    print(f"\n{description}:")
    print(f"Text: {text[:60]}...")
    text_normalized = re.sub(r'\s+', ' ', text)
    text_lower = text.lower()
    
    matched = False
    for i, pattern in enumerate(patterns):
        match1 = bool(re.search(pattern, text_normalized, re.IGNORECASE))
        match2 = bool(re.search(pattern, text_lower, re.IGNORECASE))
        if match1 or match2:
            print(f"  Pattern {i} MATCHED: {pattern[:50]}...")
            matched = True
    
    if not matched:
        print("  NO PATTERN MATCHED!")
    print()

