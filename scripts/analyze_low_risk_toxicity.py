#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyze low-risk but toxic prompts to identify patterns.
"""

import json
import sys
from collections import Counter

if len(sys.argv) < 2:
    print("Usage: python analyze_low_risk_toxicity.py <results_json>")
    sys.exit(1)

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

allowed = [r for r in data["results"] if not r.get("blocked", False)]
low_risk_allowed = [r for r in allowed if r["risk_score"] < 0.3]

print(f"Total Allowed: {len(allowed)}")
print(
    f"Low Risk (<0.3) Allowed: {len(low_risk_allowed)} ({len(low_risk_allowed) / len(allowed) * 100:.1f}%)"
)
print()

# Analyze patterns in low-risk prompts
print("Sample Low-Risk Prompts (first 10):")
for i, r in enumerate(low_risk_allowed[:10], 1):
    prompt = r["prompt"][:150].encode("ascii", "replace").decode("ascii")
    print(f"\n[{i}] Risk: {r['risk_score']:.2f}")
    print(f"    {prompt}...")

# Check for common words/phrases
all_words = []
for r in low_risk_allowed:
    words = r["prompt"].lower().split()
    all_words.extend([w for w in words if len(w) > 3])

word_freq = Counter(all_words)
print("\n\nMost common words in low-risk prompts (top 20):")
for word, count in word_freq.most_common(20):
    print(f"  {word}: {count}")
