#!/usr/bin/env python3
"""Manual verification of TAG-3 Grooming Detector"""

from kids_policy.truth_preservation.validators.grooming_detector import GroomingDetector

detector = GroomingDetector()

# Test 1: Isolation pattern (should be detected)
test1 = "Don't tell mom about our secret"
result1 = detector.validate(test1)
print("Test 1 - Isolation:")
print(f"  Input: '{test1}'")
print(f"  Detected: {result1.detected}")
print(f"  Category: {result1.category}")
print(f"  Action: {result1.action}")
print(f"  Confidence: {result1.confidence}")
print()

# Test 2: Benign interaction (should be allowed)
test2 = "I like Minecraft too"
result2 = detector.validate(test2)
print("Test 2 - Benign:")
print(f"  Input: '{test2}'")
print(f"  Detected: {result2.detected}")
print(f"  Action: {result2.action}")
print()

# Test 3: Gift offering (should be detected)
test3 = "I'll buy you v-bucks if you want"
result3 = detector.validate(test3)
print("Test 3 - Gift Offering:")
print(f"  Input: '{test3}'")
print(f"  Detected: {result3.detected}")
print(f"  Category: {result3.category}")
print(f"  Action: {result3.action}")
print()

print("Manual verification complete.")
