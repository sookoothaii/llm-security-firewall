"""
Analyze which layers are failing to block attacks.

Identifies which bypassed prompts are NOT being caught by which layers.
"""

import sys
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from llm_firewall.core.firewall_engine_v3 import FirewallEngineV3, FirewallConfig


def main():
    """Analyze bypass patterns."""
    print("\n")
    print("+" + "=" * 78 + "+")
    print("|" + " " * 23 + "Bypass Layer Analysis" + " " * 34 + "|")
    print("+" + "=" * 78 + "+")
    print()

    # Load dataset
    dataset_path = project_root / "datasets" / "core_suite.jsonl"
    test_cases = []
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                test_cases.append(json.loads(line))

    print(f"[OK] Loaded {len(test_cases)} test cases")
    print()

    # Initialize engine
    config = FirewallConfig(
        enable_sanitization=True,
        enable_normalization=True,
        enable_regex_gate=True,
        enable_exploit_detection=True,
        enable_toxicity_detection=True,
        enable_semantic_guard=True,
        enable_kids_policy=False,
        semantic_threshold=0.50,
        blocking_threshold=0.5,
    )
    engine = FirewallEngineV3(config)

    # Track bypasses
    bypassed_prompts = []
    layer_failures = {}

    print("Analyzing bypasses...")
    for case in test_cases:
        prompt = case.get("prompt", "")
        test_type = case.get("type", "benign")
        category = case.get("category", "unknown")

        if test_type != "redteam":
            continue  # Only analyze harmful prompts

        try:
            decision = engine.process_input(user_id="analyze", text=prompt)

            if decision.allowed:
                # This is a bypass!
                bypassed_prompts.append(
                    {
                        "prompt": prompt[:100],
                        "category": category,
                        "risk_score": decision.risk_score,
                        "threats": decision.detected_threats,
                        "layer_results": decision.metadata.get("layer_results", {}),
                    }
                )

                # Track layer failures
                for layer_name in [
                    "regex_gate",
                    "exploit_detection",
                    "toxicity_detection",
                    "semantic_guard",
                ]:
                    if layer_name not in layer_failures:
                        layer_failures[layer_name] = 0
                    layer_failures[layer_name] += 1

        except Exception as e:
            print(f"[ERROR] {e}")

    # Print results
    print()
    print("=" * 80)
    print(f"BYPASS ANALYSIS ({len(bypassed_prompts)} bypasses found)")
    print("=" * 80)
    print()

    if not bypassed_prompts:
        print("[OK] No bypasses detected!")
        return

    # Group by category
    by_category = {}
    for b in bypassed_prompts:
        cat = b["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(b)

    print("BYPASSES BY CATEGORY:")
    for cat, bypasses in sorted(
        by_category.items(), key=lambda x: len(x[1]), reverse=True
    ):
        print(f"  {cat}: {len(bypasses)} bypasses")
    print()

    # Show sample bypasses
    print("SAMPLE BYPASSES (first 10):")
    print("-" * 80)
    for i, b in enumerate(bypassed_prompts[:10], 1):
        print(f"{i}. [{b['category']}] Risk={b['risk_score']:.2f}")
        print(f"   {b['prompt'][:80]}...")
        print(f"   Threats: {b['threats'] if b['threats'] else 'None'}")
        print()

    # Layer failure analysis
    print("LAYER FAILURE COUNTS:")
    print("-" * 80)
    for layer, count in sorted(
        layer_failures.items(), key=lambda x: x[1], reverse=True
    ):
        print(f"  {layer}: {count} failures")
    print()

    # Risk score distribution
    risk_scores = [b["risk_score"] for b in bypassed_prompts]
    avg_risk = sum(risk_scores) / len(risk_scores)
    max_risk = max(risk_scores)
    min_risk = min(risk_scores)

    print("RISK SCORE DISTRIBUTION (for bypasses):")
    print(f"  Average: {avg_risk:.3f}")
    print(f"  Min: {min_risk:.3f}")
    print(f"  Max: {max_risk:.3f}")
    print()

    # Check how many have risk > 0.5
    high_risk_bypasses = [b for b in bypassed_prompts if b["risk_score"] >= 0.5]
    print(
        f"Bypasses with risk >= 0.5: {len(high_risk_bypasses)} ({len(high_risk_bypasses) / len(bypassed_prompts) * 100:.1f}%)"
    )
    print()

    # Recommendations
    print("=" * 80)
    print("RECOMMENDATIONS")
    print("=" * 80)
    print()

    if avg_risk >= 0.4:
        print(
            "1. LOWER BLOCKING_THRESHOLD: Average bypass risk is {:.3f}".format(
                avg_risk
            )
        )
        print("   Try: blocking_threshold = 0.3 or 0.35")
        print()

    if len(high_risk_bypasses) > len(bypassed_prompts) * 0.5:
        print(
            "2. THRESHOLD TOO HIGH: {}% of bypasses have risk >= 0.5".format(
                len(high_risk_bypasses) / len(bypassed_prompts) * 100
            )
        )
        print("   Try: blocking_threshold = 0.4")
        print()

    print("3. IMPROVE LAYER DETECTION:")
    print("   - Add more regex patterns to RegexGate")
    print("   - Improve exploit detection heuristics")
    print("   - Fine-tune toxicity thresholds")
    print()

    # Save report
    report_path = project_root / "results" / "bypass_analysis.json"
    report = {
        "total_bypasses": len(bypassed_prompts),
        "by_category": {k: len(v) for k, v in by_category.items()},
        "layer_failures": layer_failures,
        "risk_stats": {
            "avg": avg_risk,
            "min": min_risk,
            "max": max_risk,
        },
        "sample_bypasses": bypassed_prompts[:20],
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Full report saved to: {report_path}")
    print()


if __name__ == "__main__":
    main()
