#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Direkter Test von get_feedback_summary()
"""

import os
import sys
from pathlib import Path

# Setze Environment Variables
os.environ["FEEDBACK_REPOSITORY_TYPE"] = "postgres"
os.environ["POSTGRES_CONNECTION_STRING"] = "postgresql://hakgal:admin@127.0.0.1:5172/hakgal"
os.environ["ENABLE_ADAPTIVE_LEARNING"] = "true"

# Add paths
project_root = Path(__file__).parent.parent
orchestrator_dir = project_root / "detectors" / "orchestrator"
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "detectors"))
sys.path.insert(0, str(orchestrator_dir))

print("="*80)
print("DIRECT FEEDBACK SUMMARY TEST")
print("="*80)

# Import
from infrastructure.app.composition_root import OrchestratorCompositionRoot

# Create Composition Root
print("\n1. Erstelle Composition Root...")
settings = {
    "FEEDBACK_REPOSITORY_TYPE": "postgres",
    "POSTGRES_CONNECTION_STRING": "postgresql://hakgal:admin@127.0.0.1:5172/hakgal",
    "ENABLE_ADAPTIVE_LEARNING": "true"
}
root = OrchestratorCompositionRoot(
    settings=settings,
    enable_adaptive_learning=True
)
print("   ✅ Composition Root erstellt")

# Create Feedback Collector
print("\n2. Erstelle Feedback Collector...")
collector = root.create_feedback_collector()
print(f"   ✅ Feedback Collector erstellt: {type(collector).__name__}")

# Get Repository
print("\n3. Prüfe Repository...")
repo = root.create_feedback_repository()
print(f"   ✅ Repository: {type(repo).__name__}")

# Test get_samples
print("\n4. Teste Repository.get_samples()...")
samples = repo.get_samples(limit=100)
print(f"   ✅ Samples: {len(samples)}")
fn_samples = [s for s in samples if s.get('is_false_negative', False)]
print(f"   ✅ False Negatives: {len(fn_samples)}")

if len(fn_samples) > 0:
    print(f"\n   Erste False Negative:")
    fn = fn_samples[0]
    print(f"     ID: {fn.get('id')}")
    print(f"     Text: {fn.get('text', '')[:60]}...")
    print(f"     is_false_negative: {fn.get('is_false_negative')}")
    print(f"     timestamp: {fn.get('timestamp')}")
    print(f"     created_at: {fn.get('created_at')}")

# Test get_feedback_summary
print("\n5. Teste get_feedback_summary(24)...")
summary = collector.get_feedback_summary(hours=24)
print(f"   ✅ Summary: {summary}")
print(f"   ✅ False Negatives: {summary.get('false_negative', 0)}")
print(f"   ✅ False Positives: {summary.get('false_positive', 0)}")

if summary.get('false_negative', 0) > 0:
    print(f"\n   ✅✅✅ FUNKTIONIERT! {summary.get('false_negative')} False Negatives erkannt!")
else:
    print(f"\n   ⚠️  PROBLEM: Keine False Negatives in Summary, obwohl {len(fn_samples)} in Repository!")

print("\n" + "="*80)

