#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyze blocked prompts to check for potential false positives.
"""

import json
import sys

if len(sys.argv) < 2:
    print("Usage: python analyze_blocked_prompts.py <results_json>")
    sys.exit(1)

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

blocked = [r for r in data["results"] if r.get("blocked", False)]
total = len(data["results"])

print(f"Total: {total}")
print(f"Blocked: {len(blocked)} ({len(blocked) / total * 100:.1f}%)")
print()

if blocked:
    risk_scores = [r["risk_score"] for r in blocked]
    print("Blocked Risk Scores:")
    print(f"  Min: {min(risk_scores):.2f}")
    print(f"  Max: {max(risk_scores):.2f}")
    print(f"  Avg: {sum(risk_scores) / len(risk_scores):.2f}")
    print()

    # Categorize by risk level
    very_high = [r for r in blocked if r["risk_score"] >= 0.9]
    high = [r for r in blocked if 0.7 <= r["risk_score"] < 0.9]
    medium = [r for r in blocked if 0.5 <= r["risk_score"] < 0.7]
    low = [r for r in blocked if r["risk_score"] < 0.5]

    print("Risk Distribution (Blocked):")
    print(
        f"  Very High (>=0.9): {len(very_high)} ({len(very_high) / len(blocked) * 100:.1f}%)"
    )
    print(f"  High (0.7-0.9): {len(high)} ({len(high) / len(blocked) * 100:.1f}%)")
    print(
        f"  Medium (0.5-0.7): {len(medium)} ({len(medium) / len(blocked) * 100:.1f}%)"
    )
    print(f"  Low (<0.5): {len(low)} ({len(low) / len(blocked) * 100:.1f}%)")
    print()

    # Check for low-risk blocks (potential false positives)
    if low:
        print(f"⚠️  Low Risk but Blocked (potential false positives): {len(low)}")
        print("Sample low-risk blocked prompts (first 5):")
        for i, r in enumerate(low[:5], 1):
            prompt_preview = (
                r["prompt"][:150].encode("ascii", "replace").decode("ascii")
            )
            print(f"\n[{i}] Risk: {r['risk_score']:.2f}")
            print(f"    Reason: {r.get('reason', 'N/A')[:100]}")
            print(f"    {prompt_preview}...")

    # Check metadata for toxicity signals
    toxicity_signals = []
    ml_signals = []
    keyword_signals = []

    for r in blocked:
        metadata = r.get("metadata", {})
        # Check for toxicity-related signals
        if "toxicity" in str(metadata).lower():
            toxicity_signals.append(r)
        # Check for ML toxicity
        if any("ml" in str(s).lower() for s in metadata.get("detected_threats", [])):
            ml_signals.append(r)
        # Check for keyword toxicity
        if any(
            "toxicity" in str(s).lower() for s in metadata.get("detected_threats", [])
        ):
            keyword_signals.append(r)

    print("\nToxicity Detection Breakdown:")
    print(f"  Total blocked: {len(blocked)}")
    print(
        f"  With toxicity signals: {len(toxicity_signals)} ({len(toxicity_signals) / len(blocked) * 100:.1f}%)"
    )
    print(
        f"  With ML signals: {len(ml_signals)} ({len(ml_signals) / len(blocked) * 100:.1f}%)"
    )
    print(
        f"  With keyword signals: {len(keyword_signals)} ({len(keyword_signals) / len(blocked) * 100:.1f}%)"
    )

    # Show sample of high-confidence blocks
    if very_high:
        print("\n[OK] High Confidence Blocks (first 3):")
        for i, r in enumerate(very_high[:3], 1):
            prompt_preview = (
                r["prompt"][:150].encode("ascii", "replace").decode("ascii")
            )
            threats = r.get("detected_threats", [])[:3]
            print(f"\n[{i}] Risk: {r['risk_score']:.2f}")
            print(f"    Threats: {', '.join(threats) if threats else 'N/A'}")
            print(f"    {prompt_preview}...")
