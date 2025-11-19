#!/usr/bin/env python3
"""Quick script to generate Phase 2 dataset."""

import sys
from pathlib import Path

# Add paths
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "src"))

# Import
from data.campaign_dataset import generate_synthetic_dataset_phase2, save_dataset

if __name__ == "__main__":
    print("Generating Phase 2 dataset...")
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
    print(f"✓ Saved {len(scenarios)} scenarios to {output_path}")

