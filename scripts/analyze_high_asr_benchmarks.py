#!/usr/bin/env python3
"""
Analyze High ASR Benchmarks (>20%)
==================================
Comprehensive analysis of AdvBench, PolygloToxicityPrompts, and HH-RLHF
to identify common bypass patterns and optimization opportunities.
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Any


def load_results(json_path: str) -> Dict[str, Any]:
    """Load benchmark results from JSON file."""
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def analyze_benchmark(name: str, results_file: str) -> Dict[str, Any]:
    """Analyze a single benchmark's bypass patterns."""
    print(f"\n{'=' * 80}")
    print(f"ANALYZING: {name}")
    print(f"{'=' * 80}")

    data = load_results(results_file)
    results = data.get("results", [])
    summary = data.get("summary", {})

    # Separate blocked and allowed
    blocked = [r for r in results if r.get("blocked", False)]
    allowed = [r for r in results if not r.get("blocked", False)]

    total = len(results)
    asr = len(allowed) / total if total > 0 else 0.0

    print(f"\nTotal Tests: {total}")
    print(f"Blocked: {len(blocked)} ({len(blocked) / total * 100:.1f}%)")
    print(f"Allowed (Bypassed): {len(allowed)} ({len(allowed) / total * 100:.1f}%)")
    print(f"ASR: {asr * 100:.2f}%")

    if not allowed:
        print("\n[PERFECT] No bypasses detected!")
        return {
            "name": name,
            "asr": asr,
            "total": total,
            "allowed": len(allowed),
            "blocked": len(blocked),
        }

    # Risk score analysis
    risk_scores_allowed = [r.get("risk_score", 0.0) for r in allowed]
    risk_scores_blocked = [r.get("risk_score", 0.0) for r in blocked]

    avg_risk_allowed = (
        sum(risk_scores_allowed) / len(risk_scores_allowed)
        if risk_scores_allowed
        else 0.0
    )
    avg_risk_blocked = (
        sum(risk_scores_blocked) / len(risk_scores_blocked)
        if risk_scores_blocked
        else 0.0
    )
    min_risk_allowed = min(risk_scores_allowed) if risk_scores_allowed else 0.0
    max_risk_allowed = max(risk_scores_allowed) if risk_scores_allowed else 0.0

    print("\nRisk Score Analysis:")
    print(f"  Average (Allowed): {avg_risk_allowed:.3f}")
    print(f"  Average (Blocked): {avg_risk_blocked:.3f}")
    print(f"  Min (Allowed): {min_risk_allowed:.3f}")
    print(f"  Max (Allowed): {max_risk_allowed:.3f}")

    # Risk score distribution for allowed
    risk_dist = {
        "0.0": 0,
        "0.0-0.2": 0,
        "0.2-0.4": 0,
        "0.4-0.6": 0,
        "0.6-0.8": 0,
        "0.8-1.0": 0,
    }

    for score in risk_scores_allowed:
        if score == 0.0:
            risk_dist["0.0"] += 1
        elif score < 0.2:
            risk_dist["0.0-0.2"] += 1
        elif score < 0.4:
            risk_dist["0.2-0.4"] += 1
        elif score < 0.6:
            risk_dist["0.4-0.6"] += 1
        elif score < 0.8:
            risk_dist["0.6-0.8"] += 1
        else:
            risk_dist["0.8-1.0"] += 1

    print("\nRisk Score Distribution (Allowed):")
    for range_name, count in risk_dist.items():
        pct = (count / len(allowed)) * 100 if allowed else 0
        print(f"  {range_name}: {count} ({pct:.1f}%)")

    # Reason analysis
    reasons = Counter(r.get("reason", "N/A") for r in allowed)
    print("\nTop Reasons for Bypass:")
    for reason, count in reasons.most_common(10):
        pct = (count / len(allowed)) * 100 if allowed else 0
        print(f"  {reason}: {count} ({pct:.1f}%)")

    # Component analysis
    components = Counter(r.get("component") for r in allowed)
    components = {k: v for k, v in components.items() if k is not None}
    if components:
        print("\nComponents (Allowed):")
        for comp, count in components.most_common(5):
            pct = (count / len(allowed)) * 100 if allowed else 0
            print(f"  {comp}: {count} ({pct:.1f}%)")

    # Category analysis
    categories = Counter(r.get("category", "unknown") for r in allowed)
    if len(categories) > 1:
        print("\nCategory Distribution (Allowed):")
        for cat, count in categories.most_common(10):
            pct = (count / len(allowed)) * 100 if allowed else 0
            print(f"  {cat}: {count} ({pct:.1f}%)")

    # Sample bypasses by risk score ranges
    print("\nSample Bypasses by Risk Score Range:")
    print("-" * 80)

    # Zero risk (critical)
    zero_risk = [r for r in allowed if r.get("risk_score", 0.0) == 0.0]
    if zero_risk:
        print(
            f"\n[CRITICAL] Zero Risk Score Bypasses: {len(zero_risk)} ({len(zero_risk) / len(allowed) * 100:.1f}%)"
        )
        for i, r in enumerate(zero_risk[:5], 1):
            prompt = str(r.get("prompt", ""))[:200]
            prompt_clean = "".join(c if ord(c) < 128 else "?" for c in prompt)
            print(f"  {i}. Reason: {r.get('reason', 'N/A')}")
            print(f"     Prompt: {prompt_clean}...")

    # Low risk (0.0-0.4)
    low_risk = [r for r in allowed if 0.0 < r.get("risk_score", 0.0) < 0.4]
    if low_risk:
        print(
            f"\n[WARNING] Low Risk Score (0.0-0.4): {len(low_risk)} ({len(low_risk) / len(allowed) * 100:.1f}%)"
        )
        for i, r in enumerate(low_risk[:3], 1):
            prompt = str(r.get("prompt", ""))[:200]
            prompt_clean = "".join(c if ord(c) < 128 else "?" for c in prompt)
            print(
                f"  {i}. Risk: {r.get('risk_score', 0.0):.3f}, Reason: {r.get('reason', 'N/A')}"
            )
            print(f"     Prompt: {prompt_clean}...")

    # Medium risk (0.4-0.6) - borderline cases
    medium_risk = [r for r in allowed if 0.4 <= r.get("risk_score", 0.0) < 0.6]
    if medium_risk:
        print(
            f"\n[INFO] Medium Risk Score (0.4-0.6): {len(medium_risk)} ({len(medium_risk) / len(allowed) * 100:.1f}%)"
        )
        print("  These are borderline cases - may need threshold adjustment")

    # High risk but still allowed (0.6-1.0) - potential threshold issue
    high_risk_allowed = [r for r in allowed if r.get("risk_score", 0.0) >= 0.6]
    if high_risk_allowed:
        print(
            f"\n[ALERT] High Risk Score but Allowed (>=0.6): {len(high_risk_allowed)} ({len(high_risk_allowed) / len(allowed) * 100:.1f}%)"
        )
        print("  These should have been blocked - potential threshold or logic issue")
        for i, r in enumerate(high_risk_allowed[:3], 1):
            prompt = str(r.get("prompt", ""))[:200]
            prompt_clean = "".join(c if ord(c) < 128 else "?" for c in prompt)
            print(
                f"  {i}. Risk: {r.get('risk_score', 0.0):.3f}, Reason: {r.get('reason', 'N/A')}"
            )
            print(f"     Prompt: {prompt_clean}...")

    return {
        "name": name,
        "asr": asr,
        "total": total,
        "allowed": len(allowed),
        "blocked": len(blocked),
        "avg_risk_allowed": avg_risk_allowed,
        "avg_risk_blocked": avg_risk_blocked,
        "zero_risk_count": len(zero_risk),
        "low_risk_count": len(low_risk),
        "medium_risk_count": len(medium_risk),
        "high_risk_allowed_count": len(high_risk_allowed),
        "top_reasons": dict(reasons.most_common(5)),
        "risk_distribution": risk_dist,
    }


def cross_benchmark_analysis(analyses: List[Dict[str, Any]]):
    """Identify common patterns across all benchmarks."""
    print(f"\n{'=' * 80}")
    print("CROSS-BENCHMARK ANALYSIS")
    print(f"{'=' * 80}")

    # Common reasons
    all_reasons = defaultdict(int)
    for analysis in analyses:
        for reason, count in analysis.get("top_reasons", {}).items():
            all_reasons[reason] += count

    print("\nMost Common Bypass Reasons (Across All Benchmarks):")
    for reason, count in sorted(all_reasons.items(), key=lambda x: x[1], reverse=True)[
        :10
    ]:
        print(f"  {reason}: {count} occurrences")

    # Risk score patterns
    print("\nRisk Score Pattern Summary:")
    total_allowed = sum(a["allowed"] for a in analyses)
    total_zero_risk = sum(a.get("zero_risk_count", 0) for a in analyses)
    total_low_risk = sum(a.get("low_risk_count", 0) for a in analyses)
    total_high_risk_allowed = sum(a.get("high_risk_allowed_count", 0) for a in analyses)

    print(f"  Total Bypasses: {total_allowed}")
    print(
        f"  Zero Risk Bypasses: {total_zero_risk} ({total_zero_risk / total_allowed * 100:.1f}%)"
    )
    print(
        f"  Low Risk Bypasses (0.0-0.4): {total_low_risk} ({total_low_risk / total_allowed * 100:.1f}%)"
    )
    print(
        f"  High Risk but Allowed (>=0.6): {total_high_risk_allowed} ({total_high_risk_allowed / total_allowed * 100:.1f}%)"
    )

    # Average risk scores
    print("\nAverage Risk Scores (Allowed):")
    for analysis in analyses:
        print(f"  {analysis['name']}: {analysis.get('avg_risk_allowed', 0.0):.3f}")


def generate_recommendations(analyses: List[Dict[str, Any]]):
    """Generate concrete optimization recommendations."""
    print(f"\n{'=' * 80}")
    print("OPTIMIZATION RECOMMENDATIONS")
    print(f"{'=' * 80}")

    total_allowed = sum(a["allowed"] for a in analyses)
    total_zero_risk = sum(a.get("zero_risk_count", 0) for a in analyses)
    total_low_risk = sum(a.get("low_risk_count", 0) for a in analyses)
    total_high_risk_allowed = sum(a.get("high_risk_allowed_count", 0) for a in analyses)

    recommendations = []

    # Zero risk bypasses
    if total_zero_risk > 0:
        zero_pct = total_zero_risk / total_allowed * 100
        recommendations.append(
            {
                "priority": "CRITICAL",
                "issue": f"Zero Risk Score Bypasses: {total_zero_risk} ({zero_pct:.1f}%)",
                "description": "Prompts with risk_score=0.0 are being allowed. This indicates detection failure.",
                "actions": [
                    "Review why these prompts get risk_score=0.0",
                    "Check if semantic similarity detection is working",
                    "Verify keyword/phrase detection coverage",
                    "Consider adding explicit pattern matching for common bypass patterns",
                ],
            }
        )

    # Low risk bypasses
    if total_low_risk > 0:
        low_pct = total_low_risk / total_allowed * 100
        recommendations.append(
            {
                "priority": "HIGH",
                "issue": f"Low Risk Score Bypasses (0.0-0.4): {total_low_risk} ({low_pct:.1f}%)",
                "description": "Many bypasses have risk scores below 0.4, suggesting detection sensitivity issues.",
                "actions": [
                    "Review semantic similarity thresholds",
                    "Check if embedding model is detecting subtle threats",
                    "Consider ensemble scoring (multiple models)",
                    "Add context-aware detection for ambiguous prompts",
                ],
            }
        )

    # High risk but allowed
    if total_high_risk_allowed > 0:
        high_pct = total_high_risk_allowed / total_allowed * 100
        recommendations.append(
            {
                "priority": "HIGH",
                "issue": f"High Risk but Allowed (>=0.6): {total_high_risk_allowed} ({high_pct:.1f}%)",
                "description": "Prompts with high risk scores are still being allowed. This suggests threshold or logic issues.",
                "actions": [
                    "Review blocking threshold (currently may be too high)",
                    "Check Kids Policy cumulative risk logic",
                    "Verify fail-closed behavior",
                    "Review decision logic in firewall_engine_v2.py",
                ],
            }
        )

    # ASR targets
    for analysis in analyses:
        if analysis["asr"] > 0.20:
            recommendations.append(
                {
                    "priority": "MEDIUM",
                    "issue": f"{analysis['name']}: ASR {analysis['asr'] * 100:.1f}% (Target: <20%)",
                    "description": "Benchmark has ASR above 20%, needs optimization.",
                    "actions": [
                        f"Focus on {analysis['name']} specific bypass patterns",
                        f"Review {analysis['name']} dataset characteristics",
                        "Consider benchmark-specific tuning",
                    ],
                }
            )

    # Print recommendations
    for i, rec in enumerate(recommendations, 1):
        print(f"\n{i}. [{rec['priority']}] {rec['issue']}")
        print(f"   Description: {rec['description']}")
        print("   Recommended Actions:")
        for action in rec["actions"]:
            print(f"     - {action}")

    return recommendations


def main():
    """Main analysis function."""
    if len(sys.argv) < 4:
        print(
            "Usage: python analyze_high_asr_benchmarks.py <advbench.json> <polyglotoxicity.json> <hh_rlhf.json>"
        )
        print("\nExample:")
        print("  python analyze_high_asr_benchmarks.py \\")
        print("    results/advbench_20251206_003006.json \\")
        print("    results/polyglotoxicity_20251206_003113.json \\")
        print("    results/hh_rlhf_helpful_base_20251206_003449.json")
        sys.exit(1)

    advbench_file = sys.argv[1]
    polyglot_file = sys.argv[2]
    hh_rlhf_file = sys.argv[3]

    # Verify files exist
    for f in [advbench_file, polyglot_file, hh_rlhf_file]:
        if not Path(f).exists():
            print(f"[ERROR] File not found: {f}")
            sys.exit(1)

    print("=" * 80)
    print("HIGH ASR BENCHMARK ANALYSIS (>20%)")
    print("=" * 80)
    print("\nAnalyzing three benchmarks with ASR >20%:")
    print("  1. AdvBench (Jailbreak)")
    print("  2. PolygloToxicityPrompts (Multilingual)")
    print("  3. HH-RLHF (Human Preference)")

    # Analyze each benchmark
    analyses = []
    analyses.append(analyze_benchmark("AdvBench", advbench_file))
    analyses.append(analyze_benchmark("PolygloToxicityPrompts", polyglot_file))
    analyses.append(analyze_benchmark("HH-RLHF", hh_rlhf_file))

    # Cross-benchmark analysis
    cross_benchmark_analysis(analyses)

    # Generate recommendations
    recommendations = generate_recommendations(analyses)

    # Summary
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print(f"{'=' * 80}")
    print(f"\nTotal Benchmarks Analyzed: {len(analyses)}")
    print(f"Total Tests: {sum(a['total'] for a in analyses)}")
    print(f"Total Bypasses: {sum(a['allowed'] for a in analyses)}")
    print(f"Average ASR: {sum(a['asr'] for a in analyses) / len(analyses) * 100:.1f}%")
    print(f"\nRecommendations Generated: {len(recommendations)}")
    print(
        f"  Critical: {sum(1 for r in recommendations if r['priority'] == 'CRITICAL')}"
    )
    print(f"  High: {sum(1 for r in recommendations if r['priority'] == 'HIGH')}")
    print(f"  Medium: {sum(1 for r in recommendations if r['priority'] == 'MEDIUM')}")


if __name__ == "__main__":
    main()
