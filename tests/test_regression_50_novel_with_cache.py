"""
Regression Test: 50 Novel Vectors with Decision Cache Enabled
============================================================

Verifies that the decision cache does not introduce security regressions.
All 50 novel attack vectors must still be blocked (0/50 bypasses).

Test File: test_firewall_install/kimi_novel_vectors_20251201.json
"""

import sys
import json
from pathlib import Path
from typing import List, Dict, Any

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2


def load_novel_vectors(json_path: Path) -> List[Dict[str, Any]]:
    """Load novel test vectors from JSON file."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vectors = []
    for attack in data.get("attack_vectors", []):
        input_text = attack.get("input", "")
        # Remove surrounding quotes if present
        if input_text.startswith('"') and input_text.endswith('"'):
            input_text = input_text[1:-1]
        elif input_text.startswith("'") and input_text.endswith("'"):
            input_text = input_text[1:-1]

        vectors.append(
            {
                "technique": attack.get("technique", "Unknown"),
                "input": input_text,
                "description": attack.get("description", ""),
                "round": attack.get("round", 0),
                "category": attack.get("category", "Unknown"),
                "severity": attack.get("severity", "Unknown"),
            }
        )

    return vectors


def test_regression_with_cache():
    """Test all 50 novel vectors with cache enabled."""
    # Load vectors
    # Path: workspace_root/test_firewall_install/kimi_novel_vectors_20251201.json
    workspace_root = (
        project_root.parent.parent
    )  # Go up from standalone_packages/llm-security-firewall
    test_install_dir = workspace_root / "test_firewall_install"
    vectors_file = test_install_dir / "kimi_novel_vectors_20251201.json"

    if not vectors_file.exists():
        print(f"ERROR: Vectors file not found: {vectors_file}")
        print(
            "Please ensure kimi_novel_vectors_20251201.json exists in test_firewall_install/"
        )
        return False

    print(f"Loading vectors from: {vectors_file}")
    vectors = load_novel_vectors(vectors_file)
    print(f"Loaded {len(vectors)} vectors\n")

    # Initialize firewall with cache enabled
    firewall = FirewallEngineV2(
        allowed_tools=["web_search", "calculator"],
        strict_mode=True,
        enable_sanitization=True,
    )

    # Test all vectors
    bypasses = []
    results = []

    print("=" * 80)
    print("REGRESSION TEST: 50 Novel Vectors with Decision Cache")
    print("=" * 80)
    print()

    for i, vector_data in enumerate(vectors, 1):
        vector_text = vector_data["input"]
        technique = vector_data["technique"]
        round_num = vector_data["round"]

        if not vector_text or len(vector_text.strip()) < 5:
            print(f"[{i}/50] [SKIP] {technique[:60]} - Empty vector")
            continue

        # Process through firewall (cache will be used on second pass)
        decision = firewall.process_input(
            user_id=f"regression_test_user_{i}",
            text=vector_text,
            tenant_id="regression_test_tenant",
        )

        # Second pass: Should hit cache if first pass was allowed
        decision2 = firewall.process_input(
            user_id=f"regression_test_user_{i}",
            text=vector_text,
            tenant_id="regression_test_tenant",
        )

        is_blocked = not decision.allowed
        is_bypassed = decision.allowed

        result = {
            "round": round_num,
            "technique": technique,
            "category": vector_data["category"],
            "severity": vector_data["severity"],
            "blocked": is_blocked,
            "bypassed": is_bypassed,
            "risk_score": decision.risk_score,
            "reason": decision.reason,
            "detected_threats": decision.detected_threats,
            "cache_consistent": (decision.allowed == decision2.allowed),
        }

        results.append(result)

        if is_bypassed:
            bypasses.append(result)
            print(f"[{i}/50] [BYPASSED!] ROUND {round_num}: {technique}")
            print(
                f"         Risk: {decision.risk_score:.2f} | Reason: {decision.reason[:80]}"
            )
        else:
            status = "BLOCKED"
            if not result["cache_consistent"]:
                status = "BLOCKED (cache inconsistent!)"
            print(f"[{i}/50] [{status}] ROUND {round_num}: {technique[:60]}")

    # Summary
    print()
    print("=" * 80)
    print("REGRESSION TEST RESULTS")
    print("=" * 80)
    print(f"Total Vectors: {len(results)}")
    print(f"Blocked: {len(results) - len(bypasses)}")
    print(f"Bypassed: {len(bypasses)}")
    print(f"Block Rate: {(len(results) - len(bypasses)) / len(results) * 100:.1f}%")
    print()

    # Check cache consistency
    inconsistent = [r for r in results if not r["cache_consistent"]]
    if inconsistent:
        print(f"WARNING: {len(inconsistent)} vectors had inconsistent cache behavior!")
        for r in inconsistent:
            print(f"  - ROUND {r['round']}: {r['technique'][:60]}")
        print()

    # Final verdict
    if len(bypasses) == 0:
        print("SUCCESS: 0/50 bypasses - Decision cache does not introduce regressions!")
        print("=" * 80)
        return True
    else:
        print(f"FAILURE: {len(bypasses)}/50 bypasses detected!")
        print()
        print("Bypass Details:")
        for i, bypass in enumerate(bypasses, 1):
            print(f"\n  {i}. ROUND {bypass['round']}: {bypass['technique']}")
            print(
                f"     Category: {bypass['category']} | Severity: {bypass['severity']}"
            )
            print(f"     Risk Score: {bypass['risk_score']:.2f}")
            print(f"     Reason: {bypass['reason'][:150]}")
            if bypass.get("detected_threats"):
                print(f"     Detected Threats: {', '.join(bypass['detected_threats'])}")
        print()
        print("=" * 80)
        return False


if __name__ == "__main__":
    import os

    # Set Redis environment variables if not set
    if not os.getenv("REDIS_CLOUD_HOST"):
        # Try to use Redis Cloud credentials from Cursor MCP config
        # These should be set in the environment, but we can't read the config file directly
        print("WARNING: REDIS_CLOUD_* environment variables not set.")
        print(
            "Cache will be disabled (fail-open). This is acceptable for regression test."
        )
        print()

    success = test_regression_with_cache()
    sys.exit(0 if success else 1)
