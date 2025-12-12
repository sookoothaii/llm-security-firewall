#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyze which firewall layers are blocking prompts.
"""

import json
import sys
from collections import Counter

if len(sys.argv) < 2:
    print("Usage: python analyze_blocking_layers.py <results_json>")
    sys.exit(1)

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

blocked = [r for r in data["results"] if r.get("blocked", False)]

print(f"Total Blocked: {len(blocked)}")
print()

# Analyze block reasons
reasons = [r.get("reason", "N/A") for r in blocked]
reason_counter = Counter(reasons)

print("Block Reasons (Top 10):")
for reason, count in reason_counter.most_common(10):
    print(f"  {count:4d} ({count / len(blocked) * 100:5.1f}%): {reason[:80]}")

print()

# Analyze detected threats
all_threats = []
for r in blocked:
    threats = r.get("detected_threats", [])
    all_threats.extend(threats)

threat_counter = Counter(all_threats)
print("Detected Threats (Top 15):")
for threat, count in threat_counter.most_common(15):
    print(f"  {count:4d} ({count / len(blocked) * 100:5.1f}%): {threat}")

print()

# Check metadata for layer information
metadata_keys = set()
for r in blocked:
    metadata = r.get("metadata", {})
    metadata_keys.update(metadata.keys())

print(f"Metadata Keys Found: {sorted(metadata_keys)}")
print()

# Check for specific layer indicators
kids_policy_blocks = sum(1 for r in blocked if "Kids Policy" in r.get("reason", ""))
regex_blocks = sum(1 for r in blocked if "RegexGate" in r.get("reason", ""))
toxicity_blocks = sum(
    1
    for r in blocked
    if "toxicity" in str(r.get("metadata", {})).lower()
    or "toxicity" in str(r.get("detected_threats", [])).lower()
)
unicode_blocks = sum(
    1
    for r in blocked
    if "unicode" in r.get("reason", "").lower()
    or "unicode" in str(r.get("metadata", {})).lower()
)

print("Layer Breakdown:")
print(
    f"  Kids Policy: {kids_policy_blocks} ({kids_policy_blocks / len(blocked) * 100:.1f}%)"
)
print(f"  RegexGate: {regex_blocks} ({regex_blocks / len(blocked) * 100:.1f}%)")
print(
    f"  Toxicity Detector: {toxicity_blocks} ({toxicity_blocks / len(blocked) * 100:.1f}%)"
)
print(
    f"  Unicode/Encoding: {unicode_blocks} ({unicode_blocks / len(blocked) * 100:.1f}%)"
)
