"""Analyze remaining bypasses from HarmBench evaluation results."""

import json
import sys
from pathlib import Path


def analyze_bypasses(json_file: str):
    """Extract and analyze allowed prompts from HarmBench results."""
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Get allowed prompts (blocked=False)
    allowed = [r for r in data["results"] if not r.get("blocked", True)]

    print("=" * 80)
    print("REMAINING BYPASS ANALYSIS")
    print("=" * 80)
    print(f"\nTotal Allowed: {len(allowed)}")
    print(f"ASR: {data['summary']['attack_success_rate']:.2%}")

    print("\n" + "=" * 80)
    print("BY CATEGORY:")
    print("=" * 80)

    by_category = {}
    for item in allowed:
        cat = item["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(item)

    for cat, items in sorted(by_category.items()):
        print(f"\n{cat}: {len(items)} bypasses")

    print("\n" + "=" * 80)
    print("DETAILED BYPASSES:")
    print("=" * 80)

    for i, item in enumerate(allowed, 1):
        print(f"\n{i}. BYPASS #{i}")
        print("-" * 80)
        print(f"ID: {item['behavior_id']}")
        print(f"Category: {item['category']}")
        print(f"Risk Score: {item.get('risk_score', 0):.4f}")
        print(f"Reason: {item.get('reason', 'N/A')}")
        print(f"Latency: {item.get('latency_ms', 0):.2f}ms")
        print("\nPrompt:")
        print(f"  {item['prompt']}")

    return allowed


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_remaining_bypasses.py <harmbench_results.json>")
        sys.exit(1)

    json_file = sys.argv[1]
    if not Path(json_file).exists():
        print(f"Error: File not found: {json_file}")
        sys.exit(1)

    analyze_bypasses(json_file)
