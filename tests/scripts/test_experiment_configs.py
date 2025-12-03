"""
Tests for experiment_configs.py
=================================
"""

import json
import sys
import tempfile
from pathlib import Path

# Add project root to path
base_dir = Path(__file__).parent.parent.parent
if base_dir.exists():
    sys.path.insert(0, str(base_dir))

from scripts.experiment_configs import (
    get_smoke_test_config,
    get_medium_config,
    load_config_from_dict,
    load_config_from_json,
)


def test_get_smoke_test_config():
    """Test smoke test configuration."""
    config = get_smoke_test_config()
    # May return "smoke_test" (legacy) or "smoke_test_core" (new)
    assert config["experiment_id"] in ("smoke_test", "smoke_test_core")
    assert "dataset_path" in config
    assert "policies" in config
    assert "baseline" in config["policies"]
    assert config["num_workers"] >= 1


def test_get_medium_config():
    """Test medium configuration."""
    config = get_medium_config()
    # May return "medium" (legacy) or "core_suite_full" (new)
    assert config["experiment_id"] in ("medium", "core_suite_full")
    assert "dataset_path" in config
    assert "policies" in config


def test_load_config_from_dict():
    """Test loading config from dictionary."""
    config_dict = {
        "experiment_id": "test",
        "dataset_path": "/path/to/dataset.jsonl",
        "policies": ["baseline", "kids"],
        "num_workers": 2,
    }
    config = load_config_from_dict(config_dict)
    assert config["experiment_id"] == "test"
    assert config["policies"] == ["baseline", "kids"]
    assert config["num_workers"] == 2


def test_load_config_from_dict_invalid():
    """Test loading invalid config."""
    # Missing required key
    try:
        load_config_from_dict({"experiment_id": "test"})
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

    # Invalid policy
    try:
        load_config_from_dict(
            {
                "experiment_id": "test",
                "dataset_path": "/path/to/dataset.jsonl",
                "policies": ["invalid_policy"],
            }
        )
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_load_config_from_json():
    """Test loading config from JSON file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        config_dict = {
            "experiment_id": "json_test",
            "dataset_path": "/path/to/dataset.jsonl",
            "policies": ["baseline", "default"],
            "num_workers": 1,
        }
        json.dump(config_dict, f)
        tmp_path = Path(f.name)

    try:
        config = load_config_from_json(tmp_path)
        assert config["experiment_id"] == "json_test"
        assert config["policies"] == ["baseline", "default"]
    finally:
        tmp_path.unlink()


def main():
    """Run all tests."""
    print("Running tests for experiment_configs.py...")

    tests = [
        test_get_smoke_test_config,
        test_get_medium_config,
        test_load_config_from_dict,
        test_load_config_from_dict_invalid,
        test_load_config_from_json,
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
