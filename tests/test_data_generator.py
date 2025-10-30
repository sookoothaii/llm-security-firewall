# -*- coding: utf-8 -*-
"""Test data generator"""
import json
import pathlib
import subprocess
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_l3_data.py"
OUT = ROOT / "data" / "test_generated.jsonl"

def test_generator_runs():
    """Test that generator script runs without errors"""
    result = subprocess.run(
        ["python", str(SCRIPT), "--per-class", "10", "--lang", "both", "--out", str(OUT), "--seed", "42"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Generator failed: {result.stderr}"
    assert OUT.exists(), "Output file not created"


def test_class_balance():
    """Test that generated data is balanced"""
    if not OUT.exists():
        test_generator_runs()

    samples = []
    with open(OUT, "r", encoding="utf-8") as f:
        for line in f:
            samples.append(json.loads(line))

    counts = Counter(s["label"] for s in samples)

    # Should have ~10 samples per class (both EN + DE)
    assert len(counts) == 8, f"Not all classes present: {counts.keys()}"

    # Balance check (allow some variance for random generation)
    min_count = min(counts.values())
    max_count = max(counts.values())
    assert max_count - min_count <= 5, f"Imbalanced: {counts}"


def test_no_harmful_content():
    """Test that generated data contains no blocklist terms"""
    if not OUT.exists():
        test_generator_runs()

    blocklist = {"bomb", "weapon", "exploit", "malware", "drug", "synthesize", "hack"}

    with open(OUT, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            sample = json.loads(line)
            text_lower = sample["text"].lower()
            for term in blocklist:
                assert term not in text_lower, f"Line {i}: Blocklist term '{term}' found in: {sample['text']}"


