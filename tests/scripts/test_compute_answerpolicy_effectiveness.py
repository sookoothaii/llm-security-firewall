"""
Tests for compute_answerpolicy_effectiveness.py
===============================================

Tests ASR/FPR computation with minimal test data.
"""

import json
import sys
import tempfile
from pathlib import Path

# Add project root to path
base_dir = Path(__file__).parent.parent.parent
if base_dir.exists():
    sys.path.insert(0, str(base_dir))

from scripts.compute_answerpolicy_effectiveness import (
    compute_effectiveness,
    format_summary,
    load_dataset,
)


def test_compute_effectiveness_simple():
    """Test ASR/FPR computation with simple test data."""
    decisions = [
        {
            "item_id": "rt_001",
            "item_type": "redteam",
            "allowed": False,
            "metadata": {
                "answer_policy": {
                    "enabled": True,
                    "blocked_by_answer_policy": True,
                },
            },
        },
        {
            "item_id": "rt_002",
            "item_type": "redteam",
            "allowed": True,
            "metadata": {
                "answer_policy": {
                    "enabled": True,
                    "blocked_by_answer_policy": False,
                },
            },
        },
        {
            "item_id": "b_001",
            "item_type": "benign",
            "allowed": True,
            "metadata": {
                "answer_policy": {
                    "enabled": True,
                    "blocked_by_answer_policy": False,
                },
            },
        },
        {
            "item_id": "b_002",
            "item_type": "benign",
            "allowed": False,
            "metadata": {
                "answer_policy": {
                    "enabled": True,
                    "blocked_by_answer_policy": True,
                },
            },
        },
    ]

    metrics = compute_effectiveness(decisions)

    assert metrics["redteam"]["total"] == 2
    assert metrics["redteam"]["blocked"] == 1
    assert metrics["redteam"]["allowed"] == 1
    assert metrics["redteam"]["asr"] == 0.5  # 1 allowed / 2 total

    assert metrics["benign"]["total"] == 2
    assert metrics["benign"]["blocked"] == 1
    assert metrics["benign"]["allowed"] == 1
    assert metrics["benign"]["fpr"] == 0.5  # 1 blocked / 2 total

    assert metrics["redteam"]["blocked_by_answer_policy"] == 1
    assert metrics["benign"]["blocked_by_answer_policy"] == 1


def test_compute_effectiveness_with_dataset():
    """Test ASR/FPR computation with dataset mapping."""
    decisions = [
        {
            "item_id": "rt_001",
            "allowed": False,
            "metadata": {"answer_policy": {"enabled": True}},
        },
        {
            "item_id": "b_001",
            "allowed": True,
            "metadata": {"answer_policy": {"enabled": True}},
        },
    ]

    dataset_map = {
        "rt_001": {"id": "rt_001", "type": "redteam", "prompt": "test"},
        "b_001": {"id": "b_001", "type": "benign", "prompt": "test"},
    }

    metrics = compute_effectiveness(decisions, dataset_map)

    assert metrics["redteam"]["total"] == 1
    assert metrics["benign"]["total"] == 1


def test_format_summary():
    """Test summary formatting."""
    metrics = {
        "policy_name": "kids",
        "total_items": 4,
        "redteam": {
            "total": 2,
            "blocked": 1,
            "allowed": 1,
            "blocked_by_answer_policy": 1,
            "asr": 0.5,
        },
        "benign": {
            "total": 2,
            "blocked": 1,
            "allowed": 1,
            "blocked_by_answer_policy": 1,
            "fpr": 0.5,
        },
    }

    summary = format_summary(metrics)

    assert "AnswerPolicy Effectiveness Summary" in summary
    assert "Policy: kids" in summary
    assert "ASR ~ 0.500" in summary
    assert "FPR ~ 0.500" in summary


def test_load_dataset():
    """Test dataset loading."""
    test_items = [
        {"id": "rt_001", "type": "redteam", "prompt": "test1"},
        {"id": "b_001", "type": "benign", "prompt": "test2"},
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        dataset_path = Path(tmpdir) / "test_dataset.jsonl"

        with open(dataset_path, "w", encoding="utf-8") as f:
            for item in test_items:
                f.write(json.dumps(item) + "\n")

        dataset_map = load_dataset(dataset_path)

        assert len(dataset_map) == 2
        assert "rt_001" in dataset_map
        assert "b_001" in dataset_map
        assert dataset_map["rt_001"]["type"] == "redteam"
        assert dataset_map["b_001"]["type"] == "benign"


def main():
    """Run all tests."""
    print("Running tests for compute_answerpolicy_effectiveness.py...")

    tests = [
        test_compute_effectiveness_simple,
        test_compute_effectiveness_with_dataset,
        test_format_summary,
        test_load_dataset,
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
