#!/usr/bin/env python3
"""Analyze HarmBench bypasses from evaluation results."""

import json


def analyze_bypasses(json_path: str):
    """Analyze bypasses from HarmBench results."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    bypasses = [r for r in data["results"] if not r["blocked"]]

    print("=" * 80)
    print("HARMBENCH BYPASS ANALYSIS")
    print("=" * 80)
    print(f"\nTotal Bypasses: {len(bypasses)} / {len(data['results'])}")
    print(f"ASR: {len(bypasses) / len(data['results']) * 100:.2f}%")
    print()

    # Group by category
    by_category = {}
    for b in bypasses:
        cat = b["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(b)

    print("BY CATEGORY:")
    print("-" * 80)
    for cat, items in sorted(by_category.items()):
        print(f"{cat}: {len(items)} bypasses")
    print()

    print("=" * 80)
    print("DETAILED BYPASS ANALYSIS")
    print("=" * 80)

    for i, bypass in enumerate(bypasses, 1):
        print(f"\n{i}. BYPASS #{i}")
        print("-" * 80)
        print(f"ID: {bypass['behavior_id']}")
        print(f"Category: {bypass['category']}")
        print(f"Risk Score: {bypass['risk_score']:.4f}")
        print(f"Reason: {bypass['reason']}")
        print(f"Latency: {bypass.get('latency_ms', 0):.2f}ms")
        print("\nPrompt:")
        print(f"  {bypass['prompt']}")
        print()

    # Analysis
    print("=" * 80)
    print("ANALYSIS")
    print("=" * 80)

    risk_scores = [b["risk_score"] for b in bypasses]
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0

    print(f"Average Risk Score: {avg_risk:.4f}")
    print(f"Min Risk Score: {min(risk_scores) if risk_scores else 0:.4f}")
    print(f"Max Risk Score: {max(risk_scores) if risk_scores else 0:.4f}")
    print()

    # Check if any have low risk scores (potential false negatives)
    low_risk = [b for b in bypasses if b["risk_score"] < 0.5]
    if low_risk:
        print(f"WARNING: {len(low_risk)} bypasses have risk scores < 0.5:")
        for b in low_risk:
            print(f"  - {b['behavior_id']}: {b['risk_score']:.4f}")
    else:
        print("All bypasses have risk scores >= 0.5 (high risk detected but allowed)")


if __name__ == "__main__":
    import sys

    json_path = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "results/harmbench_full_asr_2025_12_05.json"
    )
    analyze_bypasses(json_path)
