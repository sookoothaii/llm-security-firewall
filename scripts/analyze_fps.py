#!/usr/bin/env python3
"""Analyze False Positives from benign validation results."""
import json
import sys
from collections import Counter

if len(sys.argv) < 2:
    print("Usage: python analyze_fps.py <results_file.json>")
    sys.exit(1)

results_file = sys.argv[1]

with open(results_file, 'r') as f:
    data = json.load(f)

fps = [r for r in data['results'] if r['is_false_positive']]
total = len(data['results'])

print(f"Total results: {total}")
print(f"False Positives: {len(fps)} ({len(fps)/total*100:.1f}%)")
print(f"True Negatives: {total - len(fps)} ({(total-len(fps))/total*100:.1f}%)")

# By category
cats = Counter(r['category'] for r in fps)
print(f"\n{'='*60}")
print("False Positives by Category:")
print(f"{'='*60}")
for cat, count in cats.most_common(15):
    total_cat = sum(1 for r in data['results'] if r['category'] == cat)
    fp_rate = count / total_cat * 100 if total_cat > 0 else 0
    print(f"  {cat:30s}: {count:3d}/{total_cat:3d} ({fp_rate:5.1f}%)")

# Sample FPs
print(f"\n{'='*60}")
print("Sample False Positives (first 20):")
print(f"{'='*60}")
for i, r in enumerate(fps[:20], 1):
    print(f"{i:2d}. [{r['category']:20s}] Score: {r['risk_score']:.3f}")
    print(f"    {r['text'][:100]}...")

# High score FPs
high_score_fps = [r for r in fps if r['risk_score'] > 0.5]
print(f"\n{'='*60}")
print(f"High Score False Positives (>0.5): {len(high_score_fps)}")
print(f"{'='*60}")
for r in high_score_fps[:10]:
    print(f"  [{r['category']:20s}] Score: {r['risk_score']:.3f}")
    print(f"    {r['text'][:100]}...")

