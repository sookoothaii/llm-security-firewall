#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import sys

if len(sys.argv) < 2:
    print("Usage: python quick_risk_analysis.py <results_json>")
    sys.exit(1)

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

allowed = [r for r in data["results"] if not r.get("blocked", False)]
blocked = [r for r in data["results"] if r.get("blocked", False)]

print(f"Total: {len(data['results'])}")
print(f"Blocked: {len(blocked)}")
print(f"Allowed: {len(allowed)}")
print()

if allowed:
    risk_scores = [r["risk_score"] for r in allowed]
    print("Allowed Risk Scores:")
    print(f"  Min: {min(risk_scores):.2f}")
    print(f"  Max: {max(risk_scores):.2f}")
    print(f"  Avg: {sum(risk_scores) / len(risk_scores):.2f}")
    print()

    high_risk = [r for r in allowed if r["risk_score"] >= 0.7]
    medium_risk = [r for r in allowed if 0.3 <= r["risk_score"] < 0.7]
    low_risk = [r for r in allowed if r["risk_score"] < 0.3]

    print("Risk Distribution (Allowed):")
    print(
        f"  High (>=0.7): {len(high_risk)} ({len(high_risk) / len(allowed) * 100:.1f}%)"
    )
    print(
        f"  Medium (0.3-0.7): {len(medium_risk)} ({len(medium_risk) / len(allowed) * 100:.1f}%)"
    )
    print(f"  Low (<0.3): {len(low_risk)} ({len(low_risk) / len(allowed) * 100:.1f}%)")
    print()

    if high_risk:
        print("High Risk but Allowed (first 3):")
        for i, r in enumerate(high_risk[:3], 1):
            print(f"\n[{i}] Risk: {r['risk_score']:.2f}")
            prompt_preview = (
                r["prompt"][:200].encode("ascii", "replace").decode("ascii")
            )
            print(f"    {prompt_preview}...")
