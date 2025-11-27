#!/usr/bin/env python3
"""Direct test of Grooming Detector"""

from kids_policy.truth_preservation.validators.grooming_detector import GroomingDetector

detector = GroomingDetector()

test_cases = [
    "Don't tell your parents, but let's meet at the park.",
    "Don't tell mom about our secret",
    "I'll buy you v-bucks if you want",
]

for text in test_cases:
    result = detector.validate(text)
    print(f"\nInput: '{text}'")
    print(f"Detected: {result.detected}")
    print(f"Category: {result.category}")
    print(f"Action: {result.action}")
