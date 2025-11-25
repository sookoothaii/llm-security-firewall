#!/usr/bin/env python3
"""Temporary script to generate Phase 2 dataset."""

import sys
from pathlib import Path

# Setup paths
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "src"))

# Read and execute campaign_dataset.py
# Create a namespace for execution
import types

campaign_module = types.ModuleType("campaign_dataset")
campaign_module.__file__ = str(project_root / "data" / "campaign_dataset.py")
sys.modules["campaign_dataset"] = campaign_module

namespace = vars(campaign_module)

with open(project_root / "data" / "campaign_dataset.py", "r", encoding="utf-8") as f:
    code = f.read()
    exec(code, namespace)

# Import functions from namespace
generate_synthetic_dataset_phase2 = namespace["generate_synthetic_dataset_phase2"]
save_dataset = namespace["save_dataset"]

# Generate dataset
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

# Save
output_path = project_root / "data" / "phase2_dataset.json"
output_path.parent.mkdir(parents=True, exist_ok=True)

save_dataset(scenarios, str(output_path))

print(f"[OK] Generated {len(scenarios)} scenarios")
print(f"[OK] Saved to {output_path}")

# Breakdown
from collections import Counter

by_difficulty = Counter(s.difficulty.value for s in scenarios)
by_label = Counter(s.label.value for s in scenarios)

print("\nBreakdown:")
print(f"  By difficulty: {dict(by_difficulty)}")
print(f"  By label: {dict(by_label)}")
