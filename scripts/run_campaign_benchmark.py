#!/usr/bin/env python3
"""
Run Campaign Benchmark (RC10)
==============================

Offline evaluation script for campaign detection calibration.

Usage:
    python scripts/run_campaign_benchmark.py [--dataset DATASET.json] [--output OUTPUT.json]

Creator: Joerg Bollwahn (with GPT-5.1 analysis)
Date: 2025-11-17
License: MIT
"""

import argparse
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from llm_firewall.benchmarks.campaign_metrics import run_campaign_benchmark
from llm_firewall.data.campaign_dataset import (
    CampaignLabel,
    convert_scenario_to_tool_events,
    generate_synthetic_dataset,
    load_dataset,
    save_dataset,
)
from llm_firewall.detectors.agentic_campaign import AgenticCampaignDetector


def main():
    parser = argparse.ArgumentParser(description="Run campaign detection benchmark")
    parser.add_argument(
        "--dataset",
        type=str,
        help="Path to dataset JSON file (if not provided, generates synthetic dataset)",
    )
    parser.add_argument(
        "--generate-dataset",
        type=str,
        help="Generate and save synthetic dataset to this path",
    )
    parser.add_argument(
        "--num-benign",
        type=int,
        default=50,
        help="Number of benign campaigns (default: 50)",
    )
    parser.add_argument(
        "--num-malicious",
        type=int,
        default=50,
        help="Number of malicious campaigns (default: 50)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed (default: 42)",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Path to save benchmark results JSON",
    )
    parser.add_argument(
        "--threshold-sweep",
        action="store_true",
        help="Perform threshold sweep for calibration",
    )

    args = parser.parse_args()

    # Generate or load dataset
    if args.generate_dataset:
        print("Generating synthetic dataset...")
        scenarios = generate_synthetic_dataset(
            num_benign=args.num_benign,
            num_malicious=args.num_malicious,
            seed=args.seed,
        )
        save_dataset(scenarios, args.generate_dataset)
        print(f"Saved dataset to {args.generate_dataset}")
        print(
            f"  Benign: {sum(1 for s in scenarios if s.label == CampaignLabel.BENIGN)}"
        )
        print(
            f"  Malicious: {sum(1 for s in scenarios if s.label == CampaignLabel.MALICIOUS)}"
        )
        return

    if args.dataset:
        print(f"Loading dataset from {args.dataset}...")
        scenarios = load_dataset(args.dataset)
    else:
        print("Generating synthetic dataset...")
        scenarios = generate_synthetic_dataset(
            num_benign=args.num_benign,
            num_malicious=args.num_malicious,
            seed=args.seed,
        )

    # Separate benign and malicious
    benign_scenarios = [s for s in scenarios if s.label == CampaignLabel.BENIGN]
    malicious_scenarios = [s for s in scenarios if s.label == CampaignLabel.MALICIOUS]

    benign_events = [convert_scenario_to_tool_events(s) for s in benign_scenarios]
    malicious_events = [convert_scenario_to_tool_events(s) for s in malicious_scenarios]

    print("\nDataset Summary:")
    print(f"  Benign campaigns: {len(benign_events)}")
    print(f"  Malicious campaigns: {len(malicious_events)}")

    # Run benchmark
    print("\nRunning benchmark...")
    detector = AgenticCampaignDetector()
    results = run_campaign_benchmark(
        malicious_campaigns=malicious_events,
        benign_campaigns=benign_events,
        detector=detector,
    )

    # Print results
    print("\n" + "=" * 60)
    print("BENCHMARK RESULTS")
    print("=" * 60)
    print("\nAttack Campaign Success Rate (ACSR):")
    print(f"  Overall: {results.acsr:.3f} ({results.acsr * 100:.1f}%)")
    print(
        f"  Phase >= 3 (Exploit): {results.acsr_phase_3:.3f} ({results.acsr_phase_3 * 100:.1f}%)"
    )
    print(
        f"  Phase >= 4 (Lateral): {results.acsr_phase_4:.3f} ({results.acsr_phase_4 * 100:.1f}%)"
    )
    print(
        f"  Phase >= 5 (Exfil): {results.acsr_phase_5:.3f} ({results.acsr_phase_5 * 100:.1f}%)"
    )

    print("\nCampaign False Positive Rate (FPR):")
    print(f"  Overall: {results.campaign_fpr:.3f} ({results.campaign_fpr * 100:.1f}%)")
    print(f"  False Positives: {results.false_positives} / {results.total_benign}")

    print("\nDetection Breakdown:")
    print(f"  Malicious campaigns: {results.total_malicious}")
    print(f"    Detected: {results.detected_malicious}")
    print(f"    Blocked: {results.blocked_malicious}")
    print(f"  Benign campaigns: {results.total_benign}")
    print(f"    False Positives: {results.false_positives}")

    print("\nDetection Rate by Phase:")
    for phase in sorted(results.detection_rate_by_phase.keys()):
        rate = results.detection_rate_by_phase[phase]
        print(f"  Phase {phase}: {rate:.3f} ({rate * 100:.1f}%)")

    # Threshold sweep
    if args.threshold_sweep:
        print("\n" + "=" * 60)
        print("THRESHOLD SWEEP")
        print("=" * 60)

        thresholds = [0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7]
        sweep_results = []

        for threshold in thresholds:
            malicious_blocked = sum(
                1
                for r in results.results
                if r.is_malicious and r.risk_score >= threshold
            )
            benign_blocked = sum(
                1
                for r in results.results
                if not r.is_malicious and r.risk_score >= threshold
            )

            total_malicious = results.total_malicious
            total_benign = results.total_benign

            asr = (
                1.0 - (malicious_blocked / total_malicious)
                if total_malicious > 0
                else 0.0
            )
            fpr = benign_blocked / total_benign if total_benign > 0 else 0.0

            sweep_results.append(
                {
                    "threshold": threshold,
                    "asr": asr,
                    "fpr": fpr,
                    "malicious_blocked": malicious_blocked,
                    "benign_blocked": benign_blocked,
                }
            )

        print("\nThreshold | ASR    | FPR    | Blocked (M/B)")
        print("-" * 50)
        for r in sweep_results:
            print(
                f"  {r['threshold']:.2f}   | {r['asr']:.3f} | {r['fpr']:.3f} | {r['malicious_blocked']:3d}/{r['benign_blocked']:3d}"
            )

        # Find Pareto-optimal threshold
        # Simple heuristic: minimize ASR + FPR (weighted)
        best = min(sweep_results, key=lambda x: x["asr"] * 0.7 + x["fpr"] * 0.3)
        print(f"\nRecommended threshold: {best['threshold']:.2f}")
        print(f"  ASR: {best['asr']:.3f}")
        print(f"  FPR: {best['fpr']:.3f}")

    # Save results
    if args.output:
        output_data = {
            "acsr": results.acsr,
            "acsr_phase_3": results.acsr_phase_3,
            "acsr_phase_4": results.acsr_phase_4,
            "acsr_phase_5": results.acsr_phase_5,
            "campaign_fpr": results.campaign_fpr,
            "detection_rate_by_phase": results.detection_rate_by_phase,
            "total_malicious": results.total_malicious,
            "total_benign": results.total_benign,
            "detected_malicious": results.detected_malicious,
            "blocked_malicious": results.blocked_malicious,
            "false_positives": results.false_positives,
        }

        if args.threshold_sweep:
            output_data["threshold_sweep"] = sweep_results

        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)

        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
