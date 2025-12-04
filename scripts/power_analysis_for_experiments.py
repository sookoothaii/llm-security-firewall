#!/usr/bin/env python3
"""
Power Analysis for Experiment Planning
=======================================

Calculates required sample sizes for future experiments to ensure reliable
detection of effect sizes with specified statistical power.

Based on the lessons learned from the evidence-based AnswerPolicy evaluation:
smoke tests were misleading due to insufficient sample size. This script helps
plan experiments with proper statistical power.

Usage:
    python scripts/power_analysis_for_experiments.py \
        --effect-size 0.05 \
        --baseline-asr 0.56 \
        --baseline-fpr 0.22 \
        --power 0.80 \
        --alpha 0.05

Author: Joerg Bollwahn
Date: 2025-12-04
"""

import argparse
import json
import sys
import math
from pathlib import Path
from typing import Dict, Any, Optional


def calculate_sample_size_proportion(
    p1: float,
    p2: float,
    alpha: float = 0.05,
    power: float = 0.80,
    one_sided: bool = False,
) -> int:
    """
    Calculate required sample size for two-proportion comparison.

    Uses standard formula for sample size calculation for proportional data.

    Args:
        p1: Baseline proportion (e.g., baseline ASR or FPR)
        p2: Target proportion (e.g., improved ASR or FPR)
        alpha: Significance level (default: 0.05)
        power: Statistical power (default: 0.80)
        one_sided: Whether test is one-sided (default: False)

    Returns:
        Required sample size per group
    """
    if p1 == p2:
        return 0  # No effect to detect

    # Z-scores
    z_alpha = (
        1.96 if not one_sided else 1.645
    )  # 95% confidence (two-sided) or 90% (one-sided)
    z_beta = (
        0.84
        if power == 0.80
        else (1.28 if power == 0.90 else (1.64 if power == 0.95 else 0.84))
    )

    # Pooled proportion
    p_pool = (p1 + p2) / 2.0

    # Standard error components
    q1 = 1 - p1
    q2 = 1 - p2
    q_pool = 1 - p_pool

    # Effect size
    delta = abs(p2 - p1)

    # Sample size calculation
    numerator = (
        z_alpha * math.sqrt(2 * p_pool * q_pool) + z_beta * math.sqrt(p1 * q1 + p2 * q2)
    ) ** 2
    denominator = delta**2

    n = numerator / denominator

    return math.ceil(n)


def calculate_sample_size_for_asr(
    baseline_asr: float, target_asr: float, alpha: float = 0.05, power: float = 0.80
) -> Dict[str, Any]:
    """
    Calculate sample size for ASR (Attack Success Rate) improvement.

    Args:
        baseline_asr: Baseline attack success rate
        target_asr: Target (improved) attack success rate
        alpha: Significance level
        power: Statistical power

    Returns:
        Dictionary with sample size calculation details
    """
    effect_size = baseline_asr - target_asr  # Improvement (negative means worse)
    absolute_effect = abs(effect_size)
    relative_effect = absolute_effect / baseline_asr if baseline_asr > 0 else 0.0

    n_per_group = calculate_sample_size_proportion(
        p1=baseline_asr, p2=target_asr, alpha=alpha, power=power
    )

    return {
        "metric": "ASR",
        "baseline_value": baseline_asr,
        "target_value": target_asr,
        "absolute_effect_size": absolute_effect,
        "relative_effect_size": relative_effect,
        "sample_size_per_group": n_per_group,
        "total_sample_size": n_per_group * 2,  # Two groups (baseline vs. improved)
        "alpha": alpha,
        "power": power,
        "interpretation": f"Need {n_per_group} redteam items per group to detect {absolute_effect:.1%} ASR improvement with {power * 100:.0f}% power",
    }


def calculate_sample_size_for_fpr(
    baseline_fpr: float, target_fpr: float, alpha: float = 0.05, power: float = 0.80
) -> Dict[str, Any]:
    """
    Calculate sample size for FPR (False Positive Rate) improvement.

    Args:
        baseline_fpr: Baseline false positive rate
        target_fpr: Target (improved) false positive rate
        alpha: Significance level
        power: Statistical power

    Returns:
        Dictionary with sample size calculation details
    """
    effect_size = baseline_fpr - target_fpr  # Improvement (negative means worse)
    absolute_effect = abs(effect_size)
    relative_effect = absolute_effect / baseline_fpr if baseline_fpr > 0 else 0.0

    n_per_group = calculate_sample_size_proportion(
        p1=baseline_fpr, p2=target_fpr, alpha=alpha, power=power
    )

    return {
        "metric": "FPR",
        "baseline_value": baseline_fpr,
        "target_value": target_fpr,
        "absolute_effect_size": absolute_effect,
        "relative_effect_size": relative_effect,
        "sample_size_per_group": n_per_group,
        "total_sample_size": n_per_group * 2,  # Two groups
        "alpha": alpha,
        "power": power,
        "interpretation": f"Need {n_per_group} benign items per group to detect {absolute_effect:.1%} FPR improvement with {power * 100:.0f}% power",
    }


def calculate_minimum_detectable_effect(
    baseline_proportion: float,
    sample_size: int,
    alpha: float = 0.05,
    power: float = 0.80,
) -> float:
    """
    Calculate minimum detectable effect size given a fixed sample size.

    Args:
        baseline_proportion: Baseline proportion
        sample_size: Sample size per group
        alpha: Significance level
        power: Statistical power

    Returns:
        Minimum detectable effect size (absolute difference)
    """
    if sample_size <= 0:
        return float("inf")

    # Z-scores
    z_alpha = 1.96
    z_beta = (
        0.84
        if power == 0.80
        else (1.28 if power == 0.90 else (1.64 if power == 0.95 else 0.84))
    )

    # Approximate calculation (iterative solution would be more precise)
    # Using conservative estimate
    p_pool = baseline_proportion
    q_pool = 1 - p_pool

    se_pool = math.sqrt(2 * p_pool * q_pool / sample_size)

    # Minimum detectable difference
    mde = (z_alpha + z_beta) * se_pool

    return mde


def generate_power_analysis_report(
    baseline_asr: Optional[float] = None,
    target_asr: Optional[float] = None,
    baseline_fpr: Optional[float] = None,
    target_fpr: Optional[float] = None,
    alpha: float = 0.05,
    power: float = 0.80,
    effect_size: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Generate comprehensive power analysis report.

    Args:
        baseline_asr: Baseline attack success rate
        target_asr: Target attack success rate
        baseline_fpr: Baseline false positive rate
        target_fpr: Target false positive rate
        alpha: Significance level
        power: Statistical power
        effect_size: Optional absolute effect size (used if target not specified)

    Returns:
        Dictionary with power analysis report
    """
    report = {
        "analysis_parameters": {
            "alpha": alpha,
            "power": power,
            "significance_level": f"{alpha * 100:.0f}%",
            "statistical_power": f"{power * 100:.0f}%",
        },
        "recommendations": [],
    }

    # ASR analysis
    if baseline_asr is not None:
        if target_asr is None and effect_size is not None:
            target_asr = baseline_asr - effect_size  # Improvement reduces ASR

        if target_asr is not None:
            asr_analysis = calculate_sample_size_for_asr(
                baseline_asr=baseline_asr,
                target_asr=target_asr,
                alpha=alpha,
                power=power,
            )
            report["asr_analysis"] = asr_analysis
            report["recommendations"].append(asr_analysis["interpretation"])

            # Minimum detectable effect for common sample sizes
            common_sample_sizes = [50, 100, 200, 300, 400, 500]
            report["asr_minimum_detectable_effect"] = {
                size: calculate_minimum_detectable_effect(
                    baseline_asr, size, alpha, power
                )
                for size in common_sample_sizes
            }

    # FPR analysis
    if baseline_fpr is not None:
        if target_fpr is None and effect_size is not None:
            target_fpr = baseline_fpr - effect_size  # Improvement reduces FPR

        if target_fpr is not None:
            fpr_analysis = calculate_sample_size_for_fpr(
                baseline_fpr=baseline_fpr,
                target_fpr=target_fpr,
                alpha=alpha,
                power=power,
            )
            report["fpr_analysis"] = fpr_analysis
            report["recommendations"].append(fpr_analysis["interpretation"])

            # Minimum detectable effect for common sample sizes
            common_sample_sizes = [50, 100, 200, 300, 400, 500]
            report["fpr_minimum_detectable_effect"] = {
                size: calculate_minimum_detectable_effect(
                    baseline_fpr, size, alpha, power
                )
                for size in common_sample_sizes
            }

    # General recommendations
    report["general_recommendations"] = [
        "Use power analysis to determine sample size BEFORE running experiments",
        "Smoke tests (10-50 items) are insufficient for performance metric estimation",
        "For reliable detection of 5% improvements, typically need 300-400 items per group",
        "Define success metrics and required effect sizes before data collection",
        "Use full, representative datasets for all performance claims",
    ]

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Calculate required sample sizes for experiment planning with statistical power"
    )
    parser.add_argument(
        "--effect-size",
        type=float,
        default=None,
        help="Absolute effect size to detect (e.g., 0.05 for 5%% improvement)",
    )
    parser.add_argument(
        "--baseline-asr", type=float, default=None, help="Baseline attack success rate"
    )
    parser.add_argument(
        "--target-asr",
        type=float,
        default=None,
        help="Target (improved) attack success rate",
    )
    parser.add_argument(
        "--baseline-fpr", type=float, default=None, help="Baseline false positive rate"
    )
    parser.add_argument(
        "--target-fpr",
        type=float,
        default=None,
        help="Target (improved) false positive rate",
    )
    parser.add_argument(
        "--power", type=float, default=0.80, help="Statistical power (default: 0.80)"
    )
    parser.add_argument(
        "--alpha", type=float, default=0.05, help="Significance level (default: 0.05)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to output JSON file (default: print to stdout)",
    )

    args = parser.parse_args()

    # Validate inputs
    if args.baseline_asr is None and args.baseline_fpr is None:
        print(
            "Error: Must specify at least one of --baseline-asr or --baseline-fpr",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.effect_size is None and args.target_asr is None and args.target_fpr is None:
        print(
            "Error: Must specify --effect-size or at least one target value",
            file=sys.stderr,
        )
        sys.exit(1)

    # Generate report
    report = generate_power_analysis_report(
        baseline_asr=args.baseline_asr,
        target_asr=args.target_asr,
        baseline_fpr=args.baseline_fpr,
        target_fpr=args.target_fpr,
        alpha=args.alpha,
        power=args.power,
        effect_size=args.effect_size,
    )

    output_json = json.dumps(report, indent=2, ensure_ascii=False, default=str)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"Power analysis saved to {output_path}")

        # Print summary
        print("\n" + "=" * 70)
        print("POWER ANALYSIS SUMMARY")
        print("=" * 70)
        print(f"Significance Level: {args.alpha * 100:.0f}% (alpha = {args.alpha})")
        print(f"Statistical Power: {args.power * 100:.0f}%")

        if "asr_analysis" in report:
            asr = report["asr_analysis"]
            print("\nASR Analysis:")
            print(f"  Baseline ASR: {asr['baseline_value']:.1%}")
            print(f"  Target ASR: {asr['target_value']:.1%}")
            print(
                f"  Effect Size: {asr['absolute_effect_size']:.1%} ({asr['relative_effect_size']:.1%} relative)"
            )
            print(
                f"  Required Sample Size: {asr['sample_size_per_group']} redteam items per group"
            )
            print(
                f"  Total Sample Size: {asr['total_sample_size']} redteam items (both groups)"
            )

        if "fpr_analysis" in report:
            fpr = report["fpr_analysis"]
            print("\nFPR Analysis:")
            print(f"  Baseline FPR: {fpr['baseline_value']:.1%}")
            print(f"  Target FPR: {fpr['target_value']:.1%}")
            print(
                f"  Effect Size: {fpr['absolute_effect_size']:.1%} ({fpr['relative_effect_size']:.1%} relative)"
            )
            print(
                f"  Required Sample Size: {fpr['sample_size_per_group']} benign items per group"
            )
            print(
                f"  Total Sample Size: {fpr['total_sample_size']} benign items (both groups)"
            )

        print("\nRecommendations:")
        for rec in report.get("recommendations", []):
            print(f"  - {rec}")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
