#!/usr/bin/env python3
"""
Quick test runner to verify external review requirements.

This script runs all verification tests from the external architecture review.
"""

import subprocess
import sys
from pathlib import Path


def run_command(cmd: str, description: str = "") -> tuple[int, str, str]:
    """Run command and return output."""
    if description:
        print(f"\n{description}")
        print("=" * 80)

    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error: {result.stderr}")
    else:
        print("✓ Success")

    return result.returncode, result.stdout, result.stderr


def main():
    """Run all verification tests from external review."""

    print("=" * 80)
    print("External Architecture Review Verification Tests")
    print("=" * 80)

    test_results = {}

    # 1. Architecture integrity (95% domain coverage)
    print("\n1. Testing domain layer coverage (must be ≥ 95%)...")
    returncode, stdout, stderr = run_command(
        "python -m pytest tests/unit/ --cov=src/llm_firewall --cov-fail-under=95 -v",
        "Domain Coverage Test",
    )
    test_results["domain_coverage"] = returncode == 0
    if returncode != 0:
        print("❌ FAIL: Domain coverage below 95%")
    else:
        print("✅ PASS: Domain coverage ≥ 95%")

    # 2. Adversarial resilience (0/50 bypasses)
    print("\n2. Testing adversarial suite (must be 0/50 bypasses)...")
    returncode, stdout, stderr = run_command(
        "python -m pytest tests/adversarial/ -v", "Adversarial Test Suite"
    )
    test_results["adversarial"] = returncode == 0
    if returncode != 0:
        # Count bypasses from output
        bypasses = stdout.count("FAILED") + stderr.count("FAILED")
        print(f"❌ FAIL: {bypasses}/50 bypasses detected")
    else:
        print("✅ PASS: 0/50 bypasses")

    # 3. Performance validation (P99 < 200ms)
    print("\n3. Testing P99 latency (must be < 200ms)...")
    returncode, stdout, stderr = run_command(
        "python -m pytest tests/performance/test_p99_adversarial.py -v -m performance",
        "P99 Latency Test",
    )
    test_results["p99_latency"] = returncode == 0
    if returncode != 0:
        print("❌ FAIL: P99 latency requirement not met")
    else:
        print("✅ PASS: P99 latency < 200ms")

    # 4. Modularity test (cache mode switching)
    print("\n4. Testing modularity (cache mode switching)...")
    returncode, stdout, stderr = run_command(
        "python -m pytest tests/integration/test_cache_modes.py -v -m integration",
        "Cache Mode Switching Test",
    )
    test_results["cache_modes"] = returncode == 0
    if returncode != 0:
        print("❌ FAIL: Cache mode switching not working")
    else:
        print("✅ PASS: Cache mode switching works without restart")

    # 5. Binary size check (15MB max)
    print("\n5. Checking binary size (must be ≤ 15MB)...")
    binary_path = Path("dist/llm-firewall")
    if binary_path.exists():
        size_mb = binary_path.stat().st_size / 1024 / 1024
        test_results["binary_size"] = size_mb <= 15
        if size_mb <= 15:
            print(f"✅ PASS: Binary size {size_mb:.1f}MB ≤ 15MB")
        else:
            print(f"❌ FAIL: Binary size {size_mb:.1f}MB > 15MB")
    else:
        print("⚠️  SKIP: Binary not found (run PyInstaller first)")
        test_results["binary_size"] = None

    # 6. Circuit Breaker Test (P0)
    print("\n6. Testing circuit breaker pattern (P0)...")
    returncode, stdout, stderr = run_command(
        "python -m pytest tests/unit/test_circuit_breaker.py -v -m unit",
        "Circuit Breaker Test",
    )
    test_results["circuit_breaker"] = returncode == 0
    if returncode != 0:
        print("⚠️  WARN: Circuit breaker tests skipped (not yet implemented)")
    else:
        print("✅ PASS: Circuit breaker tests passed")

    # 7. False Positive Tracking Test (P0)
    print("\n7. Testing false positive tracking (P0)...")
    returncode, stdout, stderr = run_command(
        "python -m pytest tests/unit/test_false_positive_tracking.py -v -m unit",
        "False Positive Tracking Test",
    )
    test_results["false_positive"] = returncode == 0
    if returncode != 0:
        print("⚠️  WARN: False positive tracking tests skipped (not yet implemented)")
    else:
        print("✅ PASS: False positive tracking tests passed")

    # Summary
    print("\n" + "=" * 80)
    print("VERIFICATION SUMMARY")
    print("=" * 80)

    passed = sum(1 for v in test_results.values() if v is True)
    failed = sum(1 for v in test_results.values() if v is False)
    skipped = sum(1 for v in test_results.values() if v is None)

    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"⚠️  Skipped: {skipped}")
    print(f"Total: {len(test_results)}")

    if failed == 0:
        print("\n🎉 All critical requirements are met!")
        return 0
    else:
        print("\n⚠️  Some requirements are not met. See details above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
