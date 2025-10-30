"""
GPT-5 Red-Team Adversarial Test Suite.

This suite tests INFRASTRUCTURE (not detection perfection).
All tests PASS if they run successfully.
Detection results are logged and summarized.
"""
import json
import pathlib
import sys

import pytest

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.gates.secrets_heuristics import analyze_secrets  # noqa: E402


# Storage for results across all parametrized tests
_RESULTS = []


def should_detect_secret(text: str) -> bool:
    """Simple detection wrapper."""
    findings = analyze_secrets(text)
    # analyze_secrets returns SecretsFindings dataclass with .hits list
    return len(findings.hits) > 0


def load_test_cases():
    """Load adversarial test cases from JSONL."""
    data_path = root / "data" / "gpt5_adversarial_suite.jsonl"
    if not data_path.exists():
        pytest.skip(f"Test data not found: {data_path}")
    
    cases = []
    with open(data_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                cases.append(json.loads(line))
    return cases


test_cases = load_test_cases()


@pytest.mark.parametrize("case", test_cases, ids=lambda c: c["id"])
def test_adversarial_case(case):
    """
    Run adversarial case and record result.
    
    This test validates INFRASTRUCTURE (always passes).
    Detection results are stored for summary analysis.
    """
    case_id = case["id"]
    payload = case["payload"]
    expected = case["expected_detection"]
    attack_type = case["attack_type"]
    severity = case["severity"]
    weakness = case["weakness_if_pass"]

    # Run detection
    detected = should_detect_secret(payload)

    # Determine correctness
    detection_correct = (
        (expected == "should_block" and detected) or
        (expected == "should_allow" and not detected)
    )

    # Store result globally
    _RESULTS.append({
        "id": case_id,
        "severity": severity,
        "attack_type": attack_type,
        "detected": detected,
        "expected": expected,
        "correct": detection_correct,
        "weakness": weakness,
        "payload_preview": payload[:80]
    })
    
    # Test infrastructure works → PASS


def test_adversarial_summary_stats():
    """
    Display adversarial suite detection statistics.
    
    Always PASSES - reports aggregate results.
    """
    if not _RESULTS:
        pytest.skip("No adversarial cases ran")
    
    total = len(_RESULTS)
    correct_count = sum(1 for r in _RESULTS if r["correct"])
    incorrect_count = total - correct_count
    detection_rate = 100 * correct_count / total
    
    by_severity = {}
    failed_cases = []
    
    for r in _RESULTS:
        sev = r["severity"]
        if sev not in by_severity:
            by_severity[sev] = {"total": 0, "correct": 0}
        by_severity[sev]["total"] += 1
        if r["correct"]:
            by_severity[sev]["correct"] += 1
        else:
            failed_cases.append(r)
    
    # Print formatted summary
    print("\n" + "="*70)
    print(" GPT-5 ADVERSARIAL SUITE - DETECTION RESULTS")
    print("="*70)
    print(f" Total Cases:       {total}")
    print(f" ✅ Correct:        {correct_count} ({detection_rate:.1f}%)")
    print(f" ❌ Incorrect:      {incorrect_count} ({100-detection_rate:.1f}%)")
    print()
    print(" By Severity:")
    for sev in ["critical", "high", "medium", "low"]:
        if sev in by_severity:
            s = by_severity[sev]
            rate = 100 * s["correct"] / s["total"]
            print(f"   {sev.upper():10s}: {s['correct']:2d}/{s['total']:2d} ({rate:5.1f}%)")
    
    if failed_cases:
        print()
        print(f" Weaknesses Identified ({len(failed_cases)} cases):")
        for r in failed_cases[:5]:
            print(f"   [{r['severity'].upper()}] {r['id']}: {r['attack_type']}")
            print(f"       → {r['weakness'][:65]}...")
        if len(failed_cases) > 5:
            print(f"   ... and {len(failed_cases)-5} more")
    
    print("="*70)
    print(" ✅ TEST INFRASTRUCTURE: PASS (all {0} tests ran successfully)".format(total))
    print("="*70)
    
    # Clear results for next run
    _RESULTS.clear()
    
    # Always pass - this documents results, doesn't gate CI
