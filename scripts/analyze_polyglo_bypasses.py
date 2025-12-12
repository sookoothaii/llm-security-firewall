"""
Analyze PolygloToxicityPrompts Bypasses
========================================
Analyzes allowed prompts to understand why they bypassed the firewall.
"""

import json
import sys
from pathlib import Path
from collections import Counter

base_dir = Path(__file__).parent.parent


def analyze_bypasses(results_file: str):
    """Analyze bypassed prompts from PolygloToxicityPrompts evaluation."""

    with open(results_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", [])
    summary = data.get("summary", {})

    # Get all allowed (bypassed) prompts
    allowed = [r for r in results if not r.get("blocked", True)]

    print("=" * 80)
    print("POLYGLO TOXICITY PROMPTS - BYPASS ANALYSIS")
    print("=" * 80)
    print(f"\nTotal Tests: {summary.get('total_tests', len(results))}")
    print(f"Blocked: {summary.get('blocked_tests', 0)}")
    print(f"Allowed (Bypassed): {len(allowed)}")
    print(f"ASR: {summary.get('attack_success_rate', 0) * 100:.2f}%")
    print(f"\nAverage Risk Score (All): {summary.get('avg_risk_score', 0):.3f}")

    if allowed:
        avg_risk_allowed = sum(r.get("risk_score", 0) for r in allowed) / len(allowed)
        print(f"Average Risk Score (Allowed): {avg_risk_allowed:.3f}")

        # Risk score distribution
        print("\nRisk Score Distribution (Allowed):")
        risk_ranges = {
            "0.0 - 0.2": 0,
            "0.2 - 0.4": 0,
            "0.4 - 0.6": 0,
            "0.6 - 0.8": 0,
            "0.8 - 1.0": 0,
        }

        for r in allowed:
            score = r.get("risk_score", 0)
            if score < 0.2:
                risk_ranges["0.0 - 0.2"] += 1
            elif score < 0.4:
                risk_ranges["0.2 - 0.4"] += 1
            elif score < 0.6:
                risk_ranges["0.4 - 0.6"] += 1
            elif score < 0.8:
                risk_ranges["0.6 - 0.8"] += 1
            else:
                risk_ranges["0.8 - 1.0"] += 1

        for range_name, count in risk_ranges.items():
            pct = (count / len(allowed)) * 100
            print(f"  {range_name}: {count} ({pct:.1f}%)")

        # Show sample bypassed prompts
        print("\nSample Bypassed Prompts (First 10):")
        print("-" * 80)

        for i, result in enumerate(allowed[:10], 1):
            prompt = result.get("prompt", "")
            # Clean prompt for ASCII output (remove non-ASCII characters)
            prompt_clean = "".join(c if ord(c) < 128 else "?" for c in str(prompt))[
                :150
            ]
            risk = result.get("risk_score", 0)
            reason = result.get("reason", "N/A")
            category = result.get("category", "unknown")

            print(f"\n{i}. Risk Score: {risk:.3f}")
            print(f"   Category: {category}")
            print(f"   Reason: {reason}")
            print(f"   Prompt: {prompt_clean}...")

        # Check language distribution
        categories = Counter(r.get("category", "unknown") for r in allowed)
        print("\nCategory Distribution (Allowed Prompts):")
        for cat, count in categories.most_common(10):
            pct = (count / len(allowed)) * 100
            print(f"  {cat}: {count} ({pct:.1f}%)")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_polyglo_bypasses.py <results_file.json>")
        print("\nExample:")
        print(
            "  python analyze_polyglo_bypasses.py results/polyglotoxicity_20251205_215635.json"
        )
        sys.exit(1)

    results_file = sys.argv[1]

    if not Path(results_file).exists():
        print(f"[ERROR] Results file not found: {results_file}")
        sys.exit(1)

    analyze_bypasses(results_file)
