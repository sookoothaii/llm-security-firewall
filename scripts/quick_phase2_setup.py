#!/usr/bin/env python3
"""
Quick Setup Script for Phase 2 Validation
==========================================

This script generates the Phase 2 dataset and runs validation.
Make sure campaign_dataset.py is saved before running!
"""

import sys
from pathlib import Path

# Setup paths
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "src"))


def generate_dataset():
    """Generate Phase 2 dataset."""
    try:
        from data.campaign_dataset import (
            generate_synthetic_dataset_phase2,
            save_dataset,
        )

        print("=" * 80)
        print("GENERATING PHASE 2 DATASET")
        print("=" * 80)

        scenarios = generate_synthetic_dataset_phase2(
            num_baseline_benign=50,
            num_baseline_malicious=50,
            num_hc1=20,
            num_hc2=20,
            num_hc3=20,
            num_hc4=20,
            seed=42,
        )

        output_path = project_root / "data" / "phase2_dataset.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        save_dataset(scenarios, str(output_path))

        print(f"✓ Generated {len(scenarios)} scenarios")
        print(f"✓ Saved to {output_path}")

        # Count breakdown
        from collections import Counter

        by_difficulty = Counter(s.difficulty.value for s in scenarios)
        by_label = Counter(s.label.value for s in scenarios)

        print("\nBreakdown:")
        print(f"  By difficulty: {dict(by_difficulty)}")
        print(f"  By label: {dict(by_label)}")

        return True

    except ImportError as e:
        print(f"ERROR: Cannot import from campaign_dataset: {e}")
        print("\nMake sure campaign_dataset.py is saved with all Phase 2 functions!")
        return False
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback

        traceback.print_exc()
        return False


def run_validation():
    """Run Phase 2 validation."""
    try:
        from benchmarks.phase2_validation import (
            run_phase2_validation,
            print_validation_report,
        )

        dataset_path = project_root / "data" / "phase2_dataset.json"

        if not dataset_path.exists():
            print(f"ERROR: Dataset not found at {dataset_path}")
            print("Run generate_dataset() first!")
            return False

        print("\n" + "=" * 80)
        print("RUNNING PHASE 2 VALIDATION")
        print("=" * 80)

        results = run_phase2_validation(str(dataset_path), threshold=0.45)

        print_validation_report(results)

        # Save results
        output_path = project_root / "results" / "phase2_validation.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        import json

        output_data = {
            "threshold": results.threshold,
            "sanity_checks": [
                {
                    "scenario_type": c.scenario_type,
                    "passed": c.passed,
                    "checks": c.checks,
                    "errors": c.errors,
                }
                for c in results.sanity_checks
            ],
            "difficulty_metrics": {
                d.value: {
                    "asr": m.asr,
                    "fpr": m.fpr,
                    "total_malicious": m.total_malicious,
                    "total_benign": m.total_benign,
                    "detected_malicious": m.detected_malicious,
                    "blocked_malicious": m.blocked_malicious,
                    "false_positives": m.false_positives,
                    "avg_risk_score_malicious": m.avg_risk_score_malicious,
                    "avg_risk_score_benign": m.avg_risk_score_benign,
                }
                for d, m in results.difficulty_metrics.items()
            },
        }

        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2)

        print(f"\n✓ Results saved to {output_path}")

        return True

    except Exception as e:
        print(f"ERROR: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Phase 2 setup and validation")
    parser.add_argument(
        "--generate-only", action="store_true", help="Only generate dataset"
    )
    parser.add_argument(
        "--validate-only", action="store_true", help="Only run validation"
    )

    args = parser.parse_args()

    success = True

    if not args.validate_only:
        success = generate_dataset()

    if success and not args.generate_only:
        success = run_validation()

    if success:
        print("\n" + "=" * 80)
        print("PHASE 2 SETUP COMPLETE")
        print("=" * 80)
        sys.exit(0)
    else:
        print("\n" + "=" * 80)
        print("PHASE 2 SETUP FAILED")
        print("=" * 80)
        sys.exit(1)
