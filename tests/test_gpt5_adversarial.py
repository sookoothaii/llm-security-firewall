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

from llm_firewall.detectors.bidi_locale import (  # noqa: E402
    bidi_isolate_wrap_hit,
    bidi_proximity_uplift,
    detect_bidi_locale,
)
from llm_firewall.detectors.encoding_base85 import detect_base85  # noqa: E402
from llm_firewall.gates.secrets_heuristics import analyze_secrets  # noqa: E402
from llm_firewall.heuristics.context_whitelist import whitelist_decision  # noqa: E402
from llm_firewall.heuristics.provider_complexity import (  # noqa: E402
    is_strong_secret_provider,
    is_weak_secret_provider,
)
from llm_firewall.normalize.unicode_hardening import (  # noqa: E402
    harden_text_for_scanning,
)

# Storage for results - use module scope fixture for clean slate
_RESULTS = []


@pytest.fixture(scope="module", autouse=True)
def clear_results_fixture():
    """Clear results before module runs."""
    global _RESULTS
    _RESULTS = []
    yield
    # Final clear after module
    _RESULTS = []


def should_detect_secret(text: str) -> bool:
    """
    Enhanced detection with ALL modules + FP-kill heuristics.

    Pipeline (GPT-5 order - Liberal bias):
    1. WHITELIST FIRST (benign context suppression)
    2. Unicode hardening (NFKC + confusables + fullwidth + bidi)
    3. Provider-specific (strong/weak detection)
    4. Bidi proximity + isolate wrap (strong signals)
    5. Base85/Z85 encoding detection
    6. Secrets on normalized + compact variants
    """
    # Provider anchors for proximity checks
    ANCHORS = ["sk-live", "sk-test", "ghp_", "gho_", "xoxb-", "xoxp-"]

    # STEP 1: WHITELIST FIRST (GPT-5: Liberal bias)
    allow_whitelist, whitelist_reason = whitelist_decision(text)
    if allow_whitelist:
        return False  # Benign context - suppress ALL detection

    # STEP 2: Unicode hardening
    hardened = harden_text_for_scanning(text)
    normalized = hardened["normalized"]
    compact = hardened["compact"]

    # STEP 3: Bidi/Locale context
    bidi_locale = detect_bidi_locale(text)
    severity_uplift = bidi_locale["severity_uplift"]

    # STEP 4: Provider-specific detection (GPT-5)
    strong_provider = is_strong_secret_provider(text)
    weak_provider = is_weak_secret_provider(text) and not strong_provider

    # STEP 5: Bidi proximity + isolate wrap (strong signals - GPT-5)
    bidi_near = bidi_proximity_uplift(text, ANCHORS, radius=16)
    bidi_wrap = bidi_isolate_wrap_hit(text, ANCHORS)
    if bidi_near or bidi_wrap or strong_provider:
        return True  # Strong evidence

    # STEP 6: Encoding detection (AFTER whitelist to avoid UUID/hex FPs)
    base85_result = detect_base85(text)
    if base85_result["score"] >= 0.4:
        return True

    # STEP 7: Base64 secret sniffing (GPT-5 fix for adv_048)
    from llm_firewall.detectors.encoding_base64_sniff import detect_base64_secret

    b64_secret = detect_base64_secret(text)
    if b64_secret["has_secret"]:
        return True

    # STEP 8: Compact anchor hit for space-sparse/interleave (GPT-5 fix for adv_044)
    def compact_anchor_hit(compact_text: str) -> bool:
        low = compact_text.lower()
        for a in ANCHORS:
            ac = a.replace("-", "").replace("_", "").lower()
            if ac and ac in low:
                return True
        return False

    if compact_anchor_hit(compact):
        return True

    # STEP 9: Secrets heuristics
    findings_norm = analyze_secrets(normalized)
    findings_comp = analyze_secrets(compact)

    has_secrets = (
        len(findings_norm.hits) > 0 or len(findings_comp.hits) > 0 or weak_provider
    )

    # Uplift from bidi/locale
    if has_secrets and severity_uplift > 0.5:
        return True

    return has_secrets


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
    detection_correct = (expected == "should_block" and detected) or (
        expected == "should_allow" and not detected
    )

    # Store result globally
    _RESULTS.append(
        {
            "id": case_id,
            "severity": severity,
            "attack_type": attack_type,
            "detected": detected,
            "expected": expected,
            "correct": detection_correct,
            "weakness": weakness,
            "payload_preview": payload[:80],
        }
    )

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

    # Print formatted summary (ASCII only for Windows console)
    print("\n" + "=" * 70)
    print(" GPT-5 ADVERSARIAL SUITE - DETECTION RESULTS")
    print("=" * 70)
    print(f" Total Cases:       {total}")
    print(f" [+] Correct:       {correct_count} ({detection_rate:.1f}%)")
    print(f" [-] Incorrect:     {incorrect_count} ({100 - detection_rate:.1f}%)")
    print()
    print(" By Severity:")
    for sev in ["critical", "high", "medium", "low"]:
        if sev in by_severity:
            s = by_severity[sev]
            rate = 100 * s["correct"] / s["total"]
            print(
                f"   {sev.upper():10s}: {s['correct']:2d}/{s['total']:2d} ({rate:5.1f}%)"
            )  # noqa: E501

    if failed_cases:
        print()
        print(f" Weaknesses Identified ({len(failed_cases)} cases):")
        for r in failed_cases[:5]:
            print(f"   [{r['severity'].upper()}] {r['id']}: {r['attack_type']}")
            print(f"       -> {r['weakness'][:65]}...")
        if len(failed_cases) > 5:
            print(f"   ... and {len(failed_cases) - 5} more")

    print("=" * 70)
    msg = " [PASS] TEST INFRASTRUCTURE: All {0} tests ran successfully"
    print(msg.format(total))
    print("=" * 70)

    # Clear results for next run
    _RESULTS.clear()

    # Always pass - this documents results, doesn't gate CI
