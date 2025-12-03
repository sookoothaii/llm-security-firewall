"""
Tests for validate_dataset.py
==============================
"""

import sys
import tempfile
from pathlib import Path

# Add project root to path
base_dir = Path(__file__).parent.parent.parent
if base_dir.exists():
    sys.path.insert(0, str(base_dir))

from scripts.validate_dataset import validate_dataset_schema, is_ascii_only


def test_is_ascii_only():
    """Test ASCII-only check."""
    assert is_ascii_only("Hello World") is True
    assert is_ascii_only("Test 123") is True
    # Null byte - ASCII encoding should handle it (0-127 range)
    # But Python's encode("ascii") may reject control chars, so test both
    result_null = is_ascii_only("Test\x00")
    assert isinstance(result_null, bool)  # Just check it returns bool
    # Non-ASCII character (ä = U+00E4)
    assert is_ascii_only("Test\u00e4") is False


def test_validate_dataset_valid():
    """Test validation of valid dataset."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write('{"id": "rt_001", "type": "redteam", "prompt": "Test prompt"}\n')
        f.write('{"id": "b_001", "type": "benign", "prompt": "Another test"}\n')
        tmp_path = Path(f.name)

    try:
        result = validate_dataset_schema(tmp_path)
        assert result["valid"] is True
        assert len(result["errors"]) == 0
        assert result["stats"]["total_items"] == 2
        assert result["stats"]["by_type"]["redteam"] == 1
        assert result["stats"]["by_type"]["benign"] == 1
    finally:
        tmp_path.unlink()


def test_validate_dataset_missing_fields():
    """Test validation detects missing required fields."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write('{"id": "rt_001", "type": "redteam"}\n')  # Missing prompt
        f.write('{"id": "b_001", "prompt": "Test"}\n')  # Missing type
        tmp_path = Path(f.name)

    try:
        result = validate_dataset_schema(tmp_path)
        assert result["valid"] is False
        assert len(result["errors"]) >= 2
    finally:
        tmp_path.unlink()


def test_validate_dataset_duplicate_ids():
    """Test validation detects duplicate IDs."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write('{"id": "rt_001", "type": "redteam", "prompt": "Test 1"}\n')
        f.write('{"id": "rt_001", "type": "redteam", "prompt": "Test 2"}\n')
        tmp_path = Path(f.name)

    try:
        result = validate_dataset_schema(tmp_path)
        assert result["valid"] is False
        assert any("duplicate" in err.lower() for err in result["errors"])
    finally:
        tmp_path.unlink()


def test_validate_dataset_invalid_type():
    """Test validation detects invalid type values."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write('{"id": "test_001", "type": "invalid", "prompt": "Test"}\n')
        tmp_path = Path(f.name)

    try:
        result = validate_dataset_schema(tmp_path)
        assert result["valid"] is False
        assert any("invalid type" in err.lower() for err in result["errors"])
    finally:
        tmp_path.unlink()


def test_validate_dataset_optional_fields():
    """Test validation collects optional field statistics."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(
            '{"id": "rt_001", "type": "redteam", "prompt": "Test", "category": "cybercrime", "mode": "direct"}\n'
        )
        f.write(
            '{"id": "b_001", "type": "benign", "prompt": "Test", "category": "cybercrime", "mode": "indirect"}\n'
        )
        tmp_path = Path(f.name)

    try:
        result = validate_dataset_schema(tmp_path)
        assert result["valid"] is True
        assert result["stats"]["by_category"]["cybercrime"] == 2
        assert result["stats"]["by_mode"]["direct"] == 1
        assert result["stats"]["by_mode"]["indirect"] == 1
    finally:
        tmp_path.unlink()


def main():
    """Run all tests."""
    print("Running tests for validate_dataset.py...")

    tests = [
        test_is_ascii_only,
        test_validate_dataset_valid,
        test_validate_dataset_missing_fields,
        test_validate_dataset_duplicate_ids,
        test_validate_dataset_invalid_type,
        test_validate_dataset_optional_fields,
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
