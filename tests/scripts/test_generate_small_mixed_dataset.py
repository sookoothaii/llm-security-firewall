"""
Tests for generate_small_mixed_dataset.py
=========================================

Tests dataset generation and validation.
"""

import json
import sys
import tempfile
from pathlib import Path

# Add project root to path
base_dir = Path(__file__).parent.parent.parent
if base_dir.exists():
    sys.path.insert(0, str(base_dir))

from scripts.generate_small_mixed_dataset import generate_dataset


def test_generate_dataset():
    """Test dataset generation."""
    items = generate_dataset(num_redteam=5, num_benign=5, seed=42)

    assert len(items) == 10

    redteam_count = sum(1 for item in items if item["type"] == "redteam")
    benign_count = sum(1 for item in items if item["type"] == "benign")

    assert redteam_count == 5
    assert benign_count == 5

    # Verify structure
    for item in items:
        assert "id" in item
        assert "type" in item
        assert "prompt" in item
        assert item["type"] in ["redteam", "benign"]
        assert isinstance(item["prompt"], str)
        assert len(item["prompt"]) > 0


def test_dataset_structure():
    """Test that generated dataset conforms to expected structure."""
    items = generate_dataset(num_redteam=2, num_benign=2, seed=123)

    with tempfile.TemporaryDirectory() as tmpdir:
        dataset_path = Path(tmpdir) / "test_dataset.jsonl"

        with open(dataset_path, "w", encoding="utf-8") as f:
            for item in items:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")

        # Validate JSONL structure
        loaded_items = []
        with open(dataset_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    item = json.loads(line)
                    loaded_items.append(item)

        assert len(loaded_items) == 4

        for item in loaded_items:
            assert "id" in item
            assert "type" in item
            assert "prompt" in item
            assert item["type"] in ["redteam", "benign"]


def main():
    """Run all tests."""
    print("Running tests for generate_small_mixed_dataset.py...")

    tests = [
        test_generate_dataset,
        test_dataset_structure,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            print(f"  [OK] {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  [ERROR] {test.__name__}: {e}")
            failed += 1

    print(f"\nResults: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
