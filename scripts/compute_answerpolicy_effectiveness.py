#!/usr/bin/env python3
"""
Computes AnswerPolicy effectiveness metrics with bootstrap confidence intervals.

Provides statistical validation of ASR/FPR improvements.
"""

import json
import sys
import argparse
import statistics
import random
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional


def load_decisions(log_path: Path) -> List[Dict[str, Any]]:
    """Load decisions from JSONL file."""
    decisions = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                decisions.append(json.loads(line))
    return decisions


def compute_metrics(decisions: List[Dict[str, Any]]) -> Dict[str, float]:
    """Compute ASR and FPR metrics."""
    redteam = [d for d in decisions if d.get("item_type") == "redteam"]
    benign = [d for d in decisions if d.get("item_type") == "benign"]

    redteam_allowed = [d for d in redteam if d.get("allowed")]
    benign_blocked = [d for d in benign if not d.get("allowed")]

    asr = len(redteam_allowed) / len(redteam) if redteam else 0.0
    fpr = len(benign_blocked) / len(benign) if benign else 0.0

    return {
        "asr": asr,
        "fpr": fpr,
        "redteam_total": len(redteam),
        "redteam_allowed": len(redteam_allowed),
        "benign_total": len(benign),
        "benign_blocked": len(benign_blocked),
    }


def bootstrap_confidence_interval(
    decisions: List[Dict[str, Any]],
    metric_func,
    n_bootstrap: int = 1000,
    confidence: float = 0.95,
    seed: int = 42,
) -> Tuple[float, float, float]:
    """
    Compute bootstrap confidence interval for a metric.

    Returns:
        (mean, lower_bound, upper_bound)
    """
    random.seed(seed)
    n = len(decisions)
    bootstrap_values = []

    for _ in range(n_bootstrap):
        # Resample with replacement
        sample = random.choices(decisions, k=n)
        value = metric_func(sample)
        bootstrap_values.append(value)

    bootstrap_values.sort()

    # Compute confidence interval
    alpha = 1.0 - confidence
    lower_idx = int(n_bootstrap * alpha / 2)
    upper_idx = int(n_bootstrap * (1 - alpha / 2))

    mean = statistics.mean(bootstrap_values)
    lower = bootstrap_values[lower_idx]
    upper = bootstrap_values[upper_idx]

    return mean, lower, upper


def compute_effectiveness(
    decisions: List[Dict[str, Any]],
    dataset_map: Optional[Dict[str, Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Compute effectiveness metrics from decisions.

    Args:
        decisions: List of decision dictionaries
        dataset_map: Optional mapping of item_id -> item dict (for type inference)

    Returns:
        Effectiveness metrics dictionary with redteam/benign breakdown
    """
    # Group by type
    redteam = []
    benign = []

    for decision in decisions:
        item_type = decision.get("item_type")
        if not item_type and dataset_map:
            # Try to infer from dataset_map
            item_id = decision.get("item_id")
            if item_id and item_id in dataset_map:
                item_type = dataset_map[item_id].get("type")

        if item_type == "redteam":
            redteam.append(decision)
        elif item_type == "benign":
            benign.append(decision)

    # Compute metrics
    redteam_blocked = [d for d in redteam if not d.get("allowed")]
    redteam_allowed = [d for d in redteam if d.get("allowed")]
    benign_blocked = [d for d in benign if not d.get("allowed")]
    benign_allowed = [d for d in benign if d.get("allowed")]

    # Count AnswerPolicy blocks
    redteam_ap_blocks = sum(
        1
        for d in redteam
        if d.get("metadata", {})
        .get("answer_policy", {})
        .get("blocked_by_answer_policy", False)
    )
    benign_ap_blocks = sum(
        1
        for d in benign
        if d.get("metadata", {})
        .get("answer_policy", {})
        .get("blocked_by_answer_policy", False)
    )

    return {
        "redteam": {
            "total": len(redteam),
            "blocked": len(redteam_blocked),
            "allowed": len(redteam_allowed),
            "asr": len(redteam_allowed) / len(redteam) if redteam else 0.0,
            "blocked_by_answer_policy": redteam_ap_blocks,
        },
        "benign": {
            "total": len(benign),
            "blocked": len(benign_blocked),
            "allowed": len(benign_allowed),
            "fpr": len(benign_blocked) / len(benign) if benign else 0.0,
            "blocked_by_answer_policy": benign_ap_blocks,
        },
    }


def format_summary(metrics: Dict[str, Any]) -> str:
    """
    Format effectiveness metrics as a summary string.

    Args:
        metrics: Effectiveness metrics dictionary

    Returns:
        Formatted summary string
    """
    policy_name = metrics.get("policy_name", "unknown")
    redteam = metrics.get("redteam", {})
    benign = metrics.get("benign", {})

    lines = []
    lines.append("=" * 80)
    lines.append("AnswerPolicy Effectiveness Summary")
    lines.append("=" * 80)
    lines.append(f"Policy: {policy_name}")
    lines.append("")
    lines.append("Redteam (ASR):")
    lines.append(f"  Total: {redteam.get('total', 0)}")
    lines.append(f"  Blocked: {redteam.get('blocked', 0)}")
    lines.append(f"  Allowed: {redteam.get('allowed', 0)}")
    lines.append(f"  ASR ~ {redteam.get('asr', 0.0):.3f}")
    lines.append("")
    lines.append("Benign (FPR):")
    lines.append(f"  Total: {benign.get('total', 0)}")
    lines.append(f"  Blocked: {benign.get('blocked', 0)}")
    lines.append(f"  Allowed: {benign.get('allowed', 0)}")
    lines.append(f"  FPR ~ {benign.get('fpr', 0.0):.3f}")
    lines.append("=" * 80)

    return "\n".join(lines)


# Re-export load_dataset from eval_utils for convenience
def load_dataset(dataset_path: Path) -> Dict[str, Dict[str, str]]:
    """
    Load dataset and create ID -> item mapping.

    Args:
        dataset_path: Path to dataset JSONL file

    Returns:
        Dictionary mapping item_id -> item dict
    """
    from scripts.eval_utils import load_dataset as _load_dataset

    return _load_dataset(dataset_path)


def analyze_effectiveness(
    evidence_log: Path, heuristic_log: Path, n_bootstrap: int = 1000, seed: int = 42
) -> Dict[str, Any]:
    """Analyze effectiveness with bootstrap confidence intervals."""

    evidence_decisions = load_decisions(evidence_log)
    heuristic_decisions = load_decisions(heuristic_log)

    # Compute point estimates
    evidence_metrics = compute_metrics(evidence_decisions)
    heuristic_metrics = compute_metrics(heuristic_decisions)

    # Bootstrap confidence intervals
    def asr_func(ds):
        return compute_metrics(ds)["asr"]

    def fpr_func(ds):
        return compute_metrics(ds)["fpr"]

    evidence_asr_mean, evidence_asr_lower, evidence_asr_upper = (
        bootstrap_confidence_interval(
            evidence_decisions, asr_func, n_bootstrap, seed=seed
        )
    )
    evidence_fpr_mean, evidence_fpr_lower, evidence_fpr_upper = (
        bootstrap_confidence_interval(
            evidence_decisions, fpr_func, n_bootstrap, seed=seed
        )
    )

    heuristic_asr_mean, heuristic_asr_lower, heuristic_asr_upper = (
        bootstrap_confidence_interval(
            heuristic_decisions, asr_func, n_bootstrap, seed=seed
        )
    )
    heuristic_fpr_mean, heuristic_fpr_lower, heuristic_fpr_upper = (
        bootstrap_confidence_interval(
            heuristic_decisions, fpr_func, n_bootstrap, seed=seed
        )
    )

    # Compute improvements
    asr_improvement = evidence_metrics["asr"] - heuristic_metrics["asr"]
    fpr_improvement = evidence_metrics["fpr"] - heuristic_metrics["fpr"]

    # Statistical significance: CIs don't overlap
    asr_significant = (evidence_asr_upper < heuristic_asr_lower) or (
        evidence_asr_lower > heuristic_asr_upper
    )
    fpr_significant = (evidence_fpr_upper < heuristic_fpr_lower) or (
        evidence_fpr_lower > heuristic_fpr_upper
    )

    return {
        "evidence": {
            "asr": evidence_metrics["asr"],
            "fpr": evidence_metrics["fpr"],
            "asr_ci": (evidence_asr_lower, evidence_asr_upper),
            "fpr_ci": (evidence_fpr_lower, evidence_fpr_upper),
        },
        "heuristic": {
            "asr": heuristic_metrics["asr"],
            "fpr": heuristic_metrics["fpr"],
            "asr_ci": (heuristic_asr_lower, heuristic_asr_upper),
            "fpr_ci": (heuristic_fpr_lower, heuristic_fpr_upper),
        },
        "improvement": {
            "asr_absolute": asr_improvement,
            "asr_relative": asr_improvement / heuristic_metrics["asr"]
            if heuristic_metrics["asr"] > 0
            else 0.0,
            "fpr_absolute": fpr_improvement,
            "fpr_relative": fpr_improvement / heuristic_metrics["fpr"]
            if heuristic_metrics["fpr"] > 0
            else 0.0,
        },
        "significance": {
            "asr_significant": asr_significant,
            "fpr_significant": fpr_significant,
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="Compute AnswerPolicy effectiveness with bootstrap confidence intervals"
    )
    parser.add_argument(
        "--decisions",
        type=str,
        required=True,
        help="Path to evidence-based decisions JSONL file",
    )
    parser.add_argument(
        "--heuristic",
        type=str,
        required=True,
        help="Path to heuristic baseline decisions JSONL file",
    )
    parser.add_argument(
        "--bootstrap",
        type=int,
        default=1000,
        help="Number of bootstrap samples (default: 1000)",
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for bootstrap (default: 42)"
    )
    parser.add_argument(
        "--output-md",
        type=str,
        default=None,
        help="Output markdown report path (optional)",
    )

    args = parser.parse_args()

    evidence_log = Path(args.decisions)
    heuristic_log = Path(args.heuristic)

    if not evidence_log.exists():
        print(f"Error: Evidence log not found: {evidence_log}", file=sys.stderr)
        return 1

    if not heuristic_log.exists():
        print(f"Error: Heuristic log not found: {heuristic_log}", file=sys.stderr)
        return 1

    results = analyze_effectiveness(
        evidence_log, heuristic_log, n_bootstrap=args.bootstrap, seed=args.seed
    )

    # Print results
    print("=" * 80)
    print("ANSWER POLICY EFFECTIVENESS ANALYSIS")
    print("=" * 80)
    print()
    print(f"Bootstrap samples: {args.bootstrap}")
    print("Confidence level: 95%")
    print()

    print("=" * 80)
    print("ATTACK SUCCESS RATE (ASR)")
    print("=" * 80)
    print(f"Evidence-based: {results['evidence']['asr']:.4f}")
    print(
        f"  95% CI: [{results['evidence']['asr_ci'][0]:.4f}, {results['evidence']['asr_ci'][1]:.4f}]"
    )
    print(f"Heuristic:      {results['heuristic']['asr']:.4f}")
    print(
        f"  95% CI: [{results['heuristic']['asr_ci'][0]:.4f}, {results['heuristic']['asr_ci'][1]:.4f}]"
    )
    print()
    print(
        f"Improvement: {results['improvement']['asr_absolute']:+.4f} ({results['improvement']['asr_relative'] * 100:+.1f}%)"
    )
    print(
        f"Statistically significant: {'YES' if results['significance']['asr_significant'] else 'NO'}"
    )
    print()

    print("=" * 80)
    print("FALSE POSITIVE RATE (FPR)")
    print("=" * 80)
    print(f"Evidence-based: {results['evidence']['fpr']:.4f}")
    print(
        f"  95% CI: [{results['evidence']['fpr_ci'][0]:.4f}, {results['evidence']['fpr_ci'][1]:.4f}]"
    )
    print(f"Heuristic:      {results['heuristic']['fpr']:.4f}")
    print(
        f"  95% CI: [{results['heuristic']['fpr_ci'][0]:.4f}, {results['heuristic']['fpr_ci'][1]:.4f}]"
    )
    print()
    print(
        f"Improvement: {results['improvement']['fpr_absolute']:+.4f} ({results['improvement']['fpr_relative'] * 100:+.1f}%)"
    )
    print(
        f"Statistically significant: {'YES' if results['significance']['fpr_significant'] else 'NO'}"
    )
    print()

    # Write markdown report if requested
    if args.output_md:
        output_path = Path(args.output_md)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("# Answer Policy Effectiveness Analysis\n\n")
            f.write(f"**Bootstrap samples:** {args.bootstrap}\n")
            f.write("**Confidence level:** 95%\n\n")

            f.write("## Attack Success Rate (ASR)\n\n")
            f.write("| Method | ASR | 95% CI |\n")
            f.write("|--------|-----|--------|\n")
            f.write(
                f"| Evidence-based | {results['evidence']['asr']:.4f} | [{results['evidence']['asr_ci'][0]:.4f}, {results['evidence']['asr_ci'][1]:.4f}] |\n"
            )
            f.write(
                f"| Heuristic | {results['heuristic']['asr']:.4f} | [{results['heuristic']['asr_ci'][0]:.4f}, {results['heuristic']['asr_ci'][1]:.4f}] |\n\n"
            )
            f.write(
                f"**Improvement:** {results['improvement']['asr_absolute']:+.4f} ({results['improvement']['asr_relative'] * 100:+.1f}%)\n"
            )
            f.write(
                f"**Statistically significant:** {'YES' if results['significance']['asr_significant'] else 'NO'}\n\n"
            )

            f.write("## False Positive Rate (FPR)\n\n")
            f.write("| Method | FPR | 95% CI |\n")
            f.write("|--------|-----|--------|\n")
            f.write(
                f"| Evidence-based | {results['evidence']['fpr']:.4f} | [{results['evidence']['fpr_ci'][0]:.4f}, {results['evidence']['fpr_ci'][1]:.4f}] |\n"
            )
            f.write(
                f"| Heuristic | {results['heuristic']['fpr']:.4f} | [{results['heuristic']['fpr_ci'][0]:.4f}, {results['heuristic']['fpr_ci'][1]:.4f}] |\n\n"
            )
            f.write(
                f"**Improvement:** {results['improvement']['fpr_absolute']:+.4f} ({results['improvement']['fpr_relative'] * 100:+.1f}%)\n"
            )
            f.write(
                f"**Statistically significant:** {'YES' if results['significance']['fpr_significant'] else 'NO'}\n\n"
            )

        print(f"Markdown report written: {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
