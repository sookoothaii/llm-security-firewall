#!/usr/bin/env python3
"""
Generate Phase 2 Dataset for RC10 Validation
=============================================

Generates complete Phase 2 dataset (baseline + hard cases) and saves to JSON.

Usage:
    python scripts/generate_phase2_dataset.py --output data/phase2_dataset.json
"""

import argparse
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "src"))

# Direct import - campaign_dataset is in data/ directory
# We need to import it as a module
import os
os.chdir(project_root)

# Now import directly
from data.campaign_dataset import (
    generate_synthetic_dataset_phase2,
    save_dataset,
)


def main():
    parser = argparse.ArgumentParser(description="Generate Phase 2 dataset")
    parser.add_argument(
        "--output",
        default="data/phase2_dataset.json",
        help="Output JSON file path",
    )
    parser.add_argument(
        "--baseline-benign",
        type=int,
        default=50,
        help="Number of baseline benign campaigns",
    )
    parser.add_argument(
        "--baseline-malicious",
        type=int,
        default=50,
        help="Number of baseline malicious campaigns",
    )
    parser.add_argument(
        "--hc1",
        type=int,
        default=20,
        help="Number of HC1 (legitimate high-phase) scenarios",
    )
    parser.add_argument(
        "--hc2",
        type=int,
        default=20,
        help="Number of HC2 (low & slow attack) scenarios",
    )
    parser.add_argument(
        "--hc3",
        type=int,
        default=20,
        help="Number of HC3 (bulk recon benign) scenarios",
    )
    parser.add_argument(
        "--hc4",
        type=int,
        default=20,
        help="Number of HC4 (pretext scope abuse) scenarios",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed",
    )
    
    args = parser.parse_args()
    
    print("="*80)
    print("GENERATING PHASE 2 DATASET")
    print("="*80)
    print(f"Baseline: {args.baseline_benign} benign + {args.baseline_malicious} malicious")
    print(f"Hard Cases: HC1={args.hc1}, HC2={args.hc2}, HC3={args.hc3}, HC4={args.hc4}")
    print(f"Seed: {args.seed}")
    print()
    
    # Generate dataset
    print("Generating scenarios...")
    scenarios = generate_synthetic_dataset_phase2(
        num_baseline_benign=args.baseline_benign,
        num_baseline_malicious=args.baseline_malicious,
        num_hc1=args.hc1,
        num_hc2=args.hc2,
        num_hc3=args.hc3,
        num_hc4=args.hc4,
        seed=args.seed,
    )
    
    print(f"Generated {len(scenarios)} scenarios")
    
    # Count by type
    from collections import Counter
    by_difficulty = Counter(s.difficulty.value for s in scenarios)
    by_label = Counter(s.label.value for s in scenarios)
    
    print("\nBreakdown:")
    print(f"  By difficulty: {dict(by_difficulty)}")
    print(f"  By label: {dict(by_label)}")
    
    # Save dataset
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"\nSaving to {output_path}...")
    save_dataset(scenarios, str(output_path))
    
    print(f"✓ Dataset saved: {len(scenarios)} scenarios")
    print(f"  File size: {output_path.stat().st_size / 1024:.1f} KB")


if __name__ == "__main__":
    main()

