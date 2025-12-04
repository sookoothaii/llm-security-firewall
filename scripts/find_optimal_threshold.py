#!/usr/bin/env python3
"""
Find Optimal Threshold from Calibration Results
================================================

Analyzes threshold calibration results to find optimal threshold based on
FPR and ASR constraints.

Usage:
    python scripts/find_optimal_threshold.py \
        --calibration analysis/threshold_calibration_kids.json \
        --output review/threshold_decision.md \
        --max-fpr 0.15 \
        --max-asr 0.65
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Any


def load_calibration(filepath: Path) -> Dict[str, Any]:
    """Load threshold calibration results."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def find_optimal_thresholds(
    threshold_results: List[Dict[str, Any]],
    max_fpr: float = 0.15,
    max_asr: float = 0.65,
) -> List[Dict[str, Any]]:
    """
    Find thresholds that meet constraints.

    Args:
        threshold_results: List of threshold evaluation results
        max_fpr: Maximum acceptable FPR
        max_asr: Maximum acceptable ASR

    Returns:
        List of candidate thresholds sorted by quality
    """
    candidates = []

    for result in threshold_results:
        asr = result.get("asr", 1.0)
        fpr = result.get("fpr", 1.0)
        threshold = result.get("threshold", 0.0)

        # Check constraints
        if fpr <= max_fpr and asr <= max_asr:
            # Calculate quality score (lower is better)
            # Prefer lower FPR, then lower ASR
            quality_score = fpr * 2 + asr  # FPR weighted more heavily

            candidates.append(
                {
                    "threshold": threshold,
                    "asr": asr,
                    "fpr": fpr,
                    "tpr": result.get("tpr", 0.0),
                    "f1": result.get("f1", 0.0),
                    "quality_score": quality_score,
                }
            )

    # Sort by quality score (lower is better)
    candidates.sort(key=lambda x: x["quality_score"])

    return candidates


def generate_decision_markdown(
    candidates: List[Dict[str, Any]], max_fpr: float, max_asr: float, output_path: Path
):
    """Generate decision matrix in Markdown format."""

    lines = [
        "# Threshold Decision Matrix",
        "",
        "**Date:** 2025-12-04",
        "**Constraints:**",
        f"- FPR ≤ {max_fpr:.0%} (strict target)",
        f"- ASR ≤ {max_asr:.0%}",
        "",
        "## Top Candidates",
        "",
        "| Threshold | ASR | FPR | TPR | F1 | Quality Score | Decision |",
        "|-----------|-----|-----|-----|-----|---------------|----------|",
    ]

    if not candidates:
        lines.append("| - | - | - | - | - | - | **NO CANDIDATES FOUND** |")
    else:
        for i, candidate in enumerate(candidates[:10], 1):  # Top 10
            threshold = candidate["threshold"]
            asr = candidate["asr"]
            fpr = candidate["fpr"]
            tpr = candidate["tpr"]
            f1 = candidate["f1"]
            quality = candidate["quality_score"]

            if i == 1:
                decision = "**BEST** (meets all constraints)"
            elif i <= 3:
                decision = "Alternative"
            else:
                decision = ""

            lines.append(
                f"| {threshold:.2f} | {asr:.2%} | {fpr:.2%} | {tpr:.2%} | {f1:.3f} | {quality:.4f} | {decision} |"
            )

    lines.extend(
        [
            "",
            "## Decision Criteria",
            "",
            "**Primary Goal:** Minimize FPR while maintaining acceptable ASR",
            "",
            "- **Quality Score:** Lower is better (FPR weighted 2x, ASR weighted 1x)",
            "- **FPR Target:** ≤15% (strict production requirement)",
            "- **ASR Limit:** ≤65% (acceptable for current threat landscape)",
            "",
            "## Recommendation",
            "",
        ]
    )

    if candidates:
        best = candidates[0]
        lines.extend(
            [
                f"**Recommended Threshold: {best['threshold']:.2f}**",
                "",
                f"- ASR: {best['asr']:.2%}",
                f"- FPR: {best['fpr']:.2%}",
                f"- TPR: {best['tpr']:.2%}",
                f"- F1: {best['f1']:.3f}",
                "",
                "This threshold provides the best balance between false positive reduction",
                "and security effectiveness within the specified constraints.",
            ]
        )
    else:
        lines.extend(
            [
                "**No threshold found that meets all constraints.**",
                "",
                "Consider:",
                "1. Relaxing FPR constraint (current: {:.0%})".format(max_fpr),
                "2. Relaxing ASR constraint (current: {:.0%})".format(max_asr),
                "3. Improving Risk Scorer to reduce baseline FPR",
            ]
        )

    lines.append("")
    lines.append("---")
    lines.append("**Next Steps:**")
    lines.append("1. Validate recommended threshold on holdout dataset")
    lines.append("2. Monitor FPR and ASR in production")
    lines.append("3. Adjust threshold based on operational feedback")

    # Write file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Decision matrix saved: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Find optimal threshold from calibration results"
    )
    parser.add_argument(
        "--calibration",
        type=str,
        required=True,
        help="Path to threshold calibration JSON file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="review/threshold_decision.md",
        help="Path to output Markdown file",
    )
    parser.add_argument(
        "--max-fpr",
        type=float,
        default=0.15,
        help="Maximum acceptable FPR (default: 0.15 = 15%%)",
    )
    parser.add_argument(
        "--max-asr",
        type=float,
        default=0.65,
        help="Maximum acceptable ASR (default: 0.65 = 65%%)",
    )

    args = parser.parse_args()

    print(f"Loading calibration results from {args.calibration}...")
    calibration = load_calibration(Path(args.calibration))

    threshold_results = calibration.get("threshold_sweep_results", [])
    print(f"Loaded {len(threshold_results)} threshold evaluations")

    print(
        f"\nSearching for thresholds with FPR <= {args.max_fpr:.0%} and ASR <= {args.max_asr:.0%}..."
    )
    candidates = find_optimal_thresholds(threshold_results, args.max_fpr, args.max_asr)

    print(f"Found {len(candidates)} candidate thresholds")

    if candidates:
        print("\nTop 3 candidates:")
        for i, candidate in enumerate(candidates[:3], 1):
            print(
                f"{i}. Threshold {candidate['threshold']:.2f}: "
                f"ASR={candidate['asr']:.2%}, FPR={candidate['fpr']:.2%}, "
                f"F1={candidate['f1']:.3f}"
            )

    # Generate decision matrix
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    generate_decision_markdown(candidates, args.max_fpr, args.max_asr, output_path)

    print(f"\nDecision matrix saved: {output_path}")


if __name__ == "__main__":
    main()
