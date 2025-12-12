#!/usr/bin/env python3
"""
Apply critical fixes identified in bypass analysis.

This script applies:
1. Kids Policy threshold adjustment (0.65 -> 0.8)
2. Stealth character removal in normalization layer

Note: Concatenation-aware pattern matching is already implemented in patterns.py
"""

import sys
from pathlib import Path


def update_kids_policy_threshold():
    """Update CUMULATIVE_RISK_THRESHOLD in kids policy."""
    filepath = Path("kids_policy/firewall_engine_v2.py")

    if not filepath.exists():
        print(f"ERROR: Kids policy file not found: {filepath}")
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    updated = False
    for i, line in enumerate(lines):
        if "CUMULATIVE_RISK_THRESHOLD = 0.65" in line:
            lines[i] = (
                "        self.CUMULATIVE_RISK_THRESHOLD = 0.8  # Increased from 0.65 to reduce false positives\n"
            )
            updated = True
            print(f"OK: Updated line {i + 1}: {lines[i].strip()}")
            break

    if updated:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)
        return True
    else:
        print("WARNING: Could not find CUMULATIVE_RISK_THRESHOLD = 0.65 in file")
        return False


def verify_stealth_char_removal():
    """Verify that stealth character removal is implemented."""
    filepath = Path("src/hak_gal/layers/inbound/normalization_layer.py")

    if not filepath.exists():
        print(f"ERROR: Normalization layer file not found: {filepath}")
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Check if method exists
    if "_remove_stealth_chars" in content:
        print("OK: Stealth character removal already implemented")
        return True
    else:
        print("WARNING: Stealth character removal not found in normalization layer")
        print("  This should have been added manually. Check the implementation.")
        return False


def verify_concatenation_matching():
    """Verify that concatenation-aware pattern matching is implemented."""
    filepath = Path("src/llm_firewall/rules/patterns.py")

    if not filepath.exists():
        print(f"ERROR: Patterns file not found: {filepath}")
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Check if functions exist
    if (
        "detect_concatenated_pattern" in content
        and "build_concatenation_aware_regex" in content
    ):
        print("OK: Concatenation-aware pattern matching already implemented")
        return True
    else:
        print("WARNING: Concatenation-aware pattern matching not found")
        print("  This should have been added manually. Check the implementation.")
        return False


def main():
    """Apply all critical fixes."""
    print("Applying Critical Fixes")
    print("=" * 60)

    fixes = [
        ("Kids Policy Threshold", update_kids_policy_threshold),
        ("Stealth Character Removal", verify_stealth_char_removal),
        ("Concatenation Pattern Matching", verify_concatenation_matching),
    ]

    results = []

    for fix_name, fix_func in fixes:
        print(f"\nChecking: {fix_name}")
        try:
            success = fix_func()
            results.append((fix_name, success))
        except Exception as e:
            print(f"ERROR: {e}")
            results.append((fix_name, False))

    # Summary
    print(f"\n{'=' * 60}")
    print("FIX APPLICATION SUMMARY")
    print("=" * 60)

    applied = sum(1 for _, success in results if success)
    total = len(results)

    for fix_name, success in results:
        status = "OK" if success else "FAILED"
        print(f"{fix_name:30} {status}")

    print(f"\nTotal fixes: {total} | Applied: {applied} | Failed: {total - applied}")

    if applied == total:
        print("\nAll critical fixes verified successfully!")
        print("\nRun tests to verify:")
        print("  python -m pytest tests/security/test_implemented_fixes.py -v")
    else:
        print(f"\n{total - applied} fix(es) need manual intervention.")
        sys.exit(1)


if __name__ == "__main__":
    main()
