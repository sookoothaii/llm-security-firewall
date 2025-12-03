"""
Tests for eval_utils.py
=======================
"""

import sys
import tempfile
from pathlib import Path

# Add project root to path
base_dir = Path(__file__).parent.parent.parent
if base_dir.exists():
    sys.path.insert(0, str(base_dir))

from scripts.eval_utils import parse_jsonl, load_dataset, ensure_directory


def test_parse_jsonl():
    """Test parsing JSONL file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write('{"id": "test_001", "type": "redteam"}\n')
        f.write('{"id": "test_002", "type": "benign"}\n')
        f.write("\n")  # Empty line
        f.write('{"id": "test_003", "type": "redteam"}\n')
        tmp_path = Path(f.name)

    try:
        records = parse_jsonl(tmp_path)
        assert len(records) == 3
        assert records[0]["id"] == "test_001"
        assert records[1]["id"] == "test_002"
        assert records[2]["id"] == "test_003"
    finally:
        tmp_path.unlink()


def test_load_dataset():
    """Test loading dataset with ID mapping."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write('{"id": "rt_001", "type": "redteam", "prompt": "test"}\n')
        f.write('{"id": "b_001", "type": "benign", "prompt": "test2"}\n')
        tmp_path = Path(f.name)

    try:
        dataset_map = load_dataset(tmp_path)
        assert len(dataset_map) == 2
        assert "rt_001" in dataset_map
        assert "b_001" in dataset_map
        assert dataset_map["rt_001"]["type"] == "redteam"
        assert dataset_map["b_001"]["type"] == "benign"
    finally:
        tmp_path.unlink()


def test_ensure_directory():
    """Test directory creation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_dir = Path(tmpdir) / "subdir" / "nested"
        ensure_directory(test_dir)
        assert test_dir.exists()
        assert test_dir.is_dir()

        # Test file path (creates parent directory)
        test_file = Path(tmpdir) / "another" / "file.txt"
        ensure_directory(test_file)
        assert test_file.parent.exists()
        assert test_file.parent.is_dir()


def main():
    """Run all tests."""
    print("Running tests for eval_utils.py...")

    tests = [
        test_parse_jsonl,
        test_load_dataset,
        test_ensure_directory,
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
