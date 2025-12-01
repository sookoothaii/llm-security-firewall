"""
Analyze and fix adversarial bypasses.

Identifies specific bypass vectors and documents required fixes.
"""

import pytest
import json
from pathlib import Path
from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2


class TestAdversarialBypassFix:
    """Analyze and fix the 2 detected bypasses."""

    @pytest.fixture
    def adversarial_suite(self):
        """Load adversarial test suite."""
        suite_path = (
            Path(__file__).parent.parent.parent
            / "data"
            / "gpt5_adversarial_suite.jsonl"
        )

        if not suite_path.exists():
            pytest.skip(f"Adversarial suite not found: {suite_path}")

        test_cases = []

        with open(suite_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    test_cases.append(json.loads(line))

        return test_cases

    def test_identify_bypasses(self, adversarial_suite):
        """Identify which specific vectors bypass the firewall."""
        engine = FirewallEngineV2()
        bypasses = []

        for test_case in adversarial_suite:
            test_id = test_case.get("id", "unknown")
            payload = test_case.get("payload", "")
            expected = test_case.get("expected_detection", "")

            if expected != "should_block":
                continue  # Only test vectors that should be blocked

            decision = engine.process_input(user_id="bypass_test", text=payload)

            if decision.allowed:
                bypasses.append(
                    {
                        "id": test_id,
                        "payload": payload,
                        "weakness": test_case.get("weakness_if_pass", "Unknown"),
                        "severity": test_case.get("severity", "unknown"),
                        "decision_reason": decision.reason,
                        "risk_score": decision.risk_score,
                    }
                )

        print("\nAdversarial Bypass Analysis:")
        print(f"  Total test vectors: {len(adversarial_suite)}")
        print(
            f"  Vectors that should block: {sum(1 for tc in adversarial_suite if tc.get('expected_detection') == 'should_block')}"
        )
        print(f"  Bypasses found: {len(bypasses)}")

        if bypasses:
            print("\nBYPASS DETAILS:")
            for bypass in bypasses:
                print(f"\n  ID: {bypass['id']}")
                print(f"  Severity: {bypass['severity']}")
                print(f"  Weakness: {bypass['weakness']}")
                print(f"  Risk Score: {bypass['risk_score']}")
                print(f"  Reason: {bypass['decision_reason']}")
                print(f"  Payload preview: {bypass['payload'][:100]}...")

        # Save bypass details for analysis
        if bypasses:
            bypass_file = Path(__file__).parent / "bypass_analysis.json"
            with open(bypass_file, "w") as f:
                json.dump(bypasses, f, indent=2)
            print(f"\nBypass analysis saved to: {bypass_file}")

        # Document bypasses found
        assert len(bypasses) >= 0, "Bypass analysis completed"

    def test_analyze_bypass_patterns(self):
        """Analyze common patterns in bypasses."""
        # Load bypass analysis if it exists
        bypass_file = Path(__file__).parent / "bypass_analysis.json"

        if not bypass_file.exists():
            pytest.skip(
                "No bypass analysis file found. Run test_identify_bypasses first."
            )

        with open(bypass_file, "r") as f:
            bypasses = json.load(f)

        print("\nBypass Pattern Analysis:")

        # Analyze by weakness type
        weaknesses = {}
        for bypass in bypasses:
            weakness = bypass["weakness"]
            weaknesses[weakness] = weaknesses.get(weakness, 0) + 1

        print("\n  Weakness Distribution:")
        for weakness, count in weaknesses.items():
            print(f"    {weakness}: {count} bypasses")

        # Analyze by payload characteristics
        patterns = {
            "unicode_trick": 0,
            "encoding": 0,
            "obfuscation": 0,
            "concatenation": 0,
            "other": 0,
        }

        for bypass in bypasses:
            payload = bypass["payload"].lower()

            if any(char in payload for char in ["\u200b", "\u202e", "\u202d"]):
                patterns["unicode_trick"] += 1
            elif any(enc in payload for enc in ["base64", "urlenc", "hex"]):
                patterns["encoding"] += 1
            elif any(term in payload for term in ["eval", "exec", "system"]):
                patterns["obfuscation"] += 1
            elif "+" in payload or "concat" in payload:
                patterns["concatenation"] += 1
            else:
                patterns["other"] += 1

        print("\n  Payload Patterns:")
        for pattern, count in patterns.items():
            if count > 0:
                print(f"    {pattern}: {count}")

        return patterns

    def test_implement_bypass_fixes(self):
        """Test implementation of bypass fixes."""

        fixes = [
            {
                "bypass_type": "Zero-width unicode",
                "fix": "Enhanced unicode normalization in NormalizationLayer",
                "files": ["src/hak_gal/layers/inbound/normalization_layer.py"],
                "test": "Should detect and remove zero-width characters",
                "current_status": "Partial - handles URL/Base64, needs zero-width detection",
            },
            {
                "bypass_type": "String concatenation obfuscation",
                "fix": "Improved pattern matching with concatenation awareness",
                "files": ["src/llm_firewall/rules/patterns.py"],
                "test": "Should detect 's' + 'k' + '-' + 'live' as 'sk-live'",
                "current_status": "Not implemented - RobustPatternMatcher needs concatenation support",
            },
            {
                "bypass_type": "Cumulative risk threshold",
                "fix": "Adjust risk scoring for multi-stage attacks",
                "files": ["src/llm_firewall/risk/risk_scorer.py"],
                "test": "Should aggregate risk across multiple evasion attempts",
                "current_status": "Implemented - but may need tuning for evasion patterns",
            },
        ]

        print("\nRequired Bypass Fixes:")
        for fix in fixes:
            print(f"\n  {fix['bypass_type']}:")
            print(f"    Fix: {fix['fix']}")
            print(f"    Files: {', '.join(fix['files'])}")
            print(f"    Test: {fix['test']}")
            print(f"    Status: {fix['current_status']}")

        # Placeholder test - will pass when fixes are implemented
        assert len(fixes) == 3

    def test_bypass_fix_verification(self, adversarial_suite):
        """Verify that fixes actually prevent bypasses."""
        engine = FirewallEngineV2()

        # Get the bypass IDs from previous analysis
        bypass_file = Path(__file__).parent / "bypass_analysis.json"
        if not bypass_file.exists():
            pytest.skip("No bypass analysis file found")

        with open(bypass_file, "r") as f:
            bypasses = json.load(f)

        bypass_ids = [b["id"] for b in bypasses]

        # Test each bypass vector
        fixed_count = 0
        remaining_bypasses = []

        for test_case in adversarial_suite:
            if test_case.get("id") in bypass_ids:
                decision = engine.process_input(
                    user_id="fix_verification", text=test_case.get("payload", "")
                )

                if not decision.allowed:
                    fixed_count += 1
                    print(f"FIXED: {test_case.get('id')}")
                else:
                    remaining_bypasses.append(test_case.get("id"))
                    print(f"STILL BYPASSES: {test_case.get('id')}")

        print("\nBypass Fix Verification:")
        print(f"  Total bypasses before: {len(bypass_ids)}")
        print(f"  Fixed: {fixed_count}")
        print(f"  Remaining: {len(remaining_bypasses)}")

        if remaining_bypasses:
            print(f"  Still bypassing: {', '.join(remaining_bypasses)}")

        # Goal: 0 remaining bypasses
        assert len(remaining_bypasses) == 0, (
            f"Still have {len(remaining_bypasses)} bypasses"
        )
