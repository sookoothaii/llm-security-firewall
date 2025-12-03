"""
Tests for bootstrap confidence intervals
==========================================
"""

import sys
from pathlib import Path

# Add project root to path
base_dir = Path(__file__).parent.parent.parent
if base_dir.exists():
    sys.path.insert(0, str(base_dir))

from scripts.compute_answerpolicy_effectiveness import bootstrap_confidence_interval


def test_bootstrap_ci_basic():
    """Test basic bootstrap CI computation."""
    # 10 successes out of 20 total
    lower, upper = bootstrap_confidence_interval(
        successes=10,
        total=20,
        num_samples=100,
        seed=42,
    )

    assert 0.0 <= lower <= 1.0
    assert 0.0 <= upper <= 1.0
    assert lower <= upper


def test_bootstrap_ci_edge_cases():
    """Test edge cases."""
    # All successes
    lower, upper = bootstrap_confidence_interval(
        successes=10,
        total=10,
        num_samples=100,
        seed=42,
    )
    assert lower == upper
    assert lower == 1.0

    # No successes
    lower, upper = bootstrap_confidence_interval(
        successes=0,
        total=10,
        num_samples=100,
        seed=42,
    )
    assert lower == upper
    assert lower == 0.0

    # Zero total
    lower, upper = bootstrap_confidence_interval(
        successes=0,
        total=0,
        num_samples=100,
        seed=42,
    )
    assert lower == 0.0
    assert upper == 0.0


def test_bootstrap_ci_reproducibility():
    """Test that bootstrap CI is reproducible with same seed."""
    lower1, upper1 = bootstrap_confidence_interval(
        successes=5,
        total=20,
        num_samples=100,
        seed=123,
    )

    lower2, upper2 = bootstrap_confidence_interval(
        successes=5,
        total=20,
        num_samples=100,
        seed=123,
    )

    assert abs(lower1 - lower2) < 1e-10
    assert abs(upper1 - upper2) < 1e-10


def main():
    """Run all tests."""
    print("Running tests for bootstrap confidence intervals...")

    tests = [
        test_bootstrap_ci_basic,
        test_bootstrap_ci_edge_cases,
        test_bootstrap_ci_reproducibility,
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
