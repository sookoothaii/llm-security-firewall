#!/usr/bin/env python3
"""Analyze FPR validation results."""
import json
import sys

if len(sys.argv) > 1:
    filename = sys.argv[1]
else:
    filename = "benign_validation_results_20251210_043800.json"

with open(filename, 'r', encoding='utf-8') as f:
    data = json.load(f)

print("=" * 80)
print("  FPR VALIDATION RESULTS ANALYSIS")
print("=" * 80)
print()

total = data['total_examples']
tn = data['true_negatives']
fp = data['false_positives']
fpr = data['false_positive_rate']

print(f"Total Examples: {total}")
print(f"True Negatives (Allowed): {tn} ({tn/total*100:.1f}%)")
print(f"False Positives (Blocked): {fp} ({fpr:.1f}%)")
print()

# By category
cats = {}
for r in data['results']:
    cat = r['category']
    if cat not in cats:
        cats[cat] = {'total': 0, 'fps': 0, 'tns': 0}
    cats[cat]['total'] += 1
    if r['is_false_positive']:
        cats[cat]['fps'] += 1
    else:
        cats[cat]['tns'] += 1

print("By Category:")
for cat in sorted(cats.keys()):
    stats = cats[cat]
    cat_fpr = stats['fps'] / stats['total'] * 100 if stats['total'] > 0 else 0
    status = "✅" if cat_fpr < 5 else "⚠️" if cat_fpr < 20 else "❌"
    print(f"  {status} {cat}: {stats['tns']}/{stats['total']} allowed, "
          f"{stats['fps']} FPs ({cat_fpr:.1f}%)")

print()

# Top false positives
print("Top False Positives (by risk score):")
fps = sorted([r for r in data['results'] if r['is_false_positive']], 
             key=lambda x: x['risk_score'], reverse=True)[:10]
for i, r in enumerate(fps, 1):
    print(f"  {i}. Score: {r['risk_score']:.3f} | {r['category']}")
    print(f"     Text: {r['text'][:80]}...")

print()

# Comparison with previous
print("Comparison:")
print(f"  Current FPR: {fpr:.1f}%")
if fpr < 10:
    print(f"  Status: ✅ EXCELLENT (FPR < 10%)")
elif fpr < 20:
    print(f"  Status: ⚠️ ACCEPTABLE (FPR < 20%)")
else:
    print(f"  Status: ❌ HIGH FPR (needs improvement)")

