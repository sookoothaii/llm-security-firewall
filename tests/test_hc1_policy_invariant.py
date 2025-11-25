#!/usr/bin/env python3
"""
Unit Test: HC1 Policy Invariant
================================

Tests that HC1 scenarios (testlab + authorized) NEVER get BLOCK action.

Invariant:
- If scope == "testlab" AND authorized == True
- Then final_action ∈ {ALLOW, WARN, REQUIRE_APPROVAL}
- NEVER BLOCK

Creator: Joerg Bollwahn
Date: 2025-11-17
License: MIT
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add paths
project_root = Path(__file__).parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))
sys.path.insert(0, str(project_root))

data_path = project_root / "data"
sys.path.insert(0, str(data_path))

from llm_firewall.detectors.action import Action
from llm_firewall.detectors.agentic_campaign import AgenticCampaignDetector
from data.campaign_dataset import generate_phase2_hard_cases


def test_hc1_never_blocks():
    """
    Test that HC1 scenarios never get BLOCK action.

    This is the core invariant for legitimate testlab operations.
    """
    # Generate HC1 scenario
    hc1_scenarios = generate_phase2_hard_cases(
        num_hc1=1,
        num_hc2=0,
        num_hc3=0,
        num_hc4=0,
        seed=42,
    )
    scenario = hc1_scenarios[0]

    # Verify scenario properties
    assert scenario.scope == "testlab", (
        f"Expected scope='testlab', got '{scenario.scope}'"
    )
    assert scenario.authorized is True, (
        f"Expected authorized=True, got '{scenario.authorized}'"
    )
    assert scenario.label.value == "benign", "HC1 should be benign"

    # Convert to tool events
    from data.campaign_dataset import convert_scenario_to_tool_events

    tool_events = convert_scenario_to_tool_events(scenario)
    assert len(tool_events) > 0, "HC1 should have tool events"

    # Initialize detector
    detector = AgenticCampaignDetector()

    # Process events sequentially (like in validation)
    actions = []
    for idx in range(1, len(tool_events) + 1):
        events_subset = tool_events[:idx]

        report = detector.detect_campaign(
            events_subset,
            session_id=scenario.campaign_id,
            operator_id=scenario.operator_id,
            scope=scenario.scope,
            authorized=scenario.authorized,
        )

        action_str = report.get("action", "PASS")
        try:
            action = Action.from_string(action_str)
        except ValueError:
            if action_str == "BLOCK":
                action = Action.BLOCK
            elif action_str == "REQUIRE_APPROVAL":
                action = Action.REQUIRE_APPROVAL
            elif action_str == "WARN":
                action = Action.WARN
            else:
                action = Action.ALLOW

        actions.append(action)

    # Final campaign decision = max of all event actions
    final_action_campaign = max(actions)

    # HC1 Invariant: Never BLOCK
    assert final_action_campaign != Action.BLOCK, (
        f"HC1 INVARIANT VIOLATION: Got BLOCK action! "
        f"Actions: {[a.name for a in actions]}, "
        f"Final: {final_action_campaign.name}"
    )

    # HC1 should get at least REQUIRE_APPROVAL for high-risk scenarios
    # (Risk should be high due to full kill-chain, but action should be softer)
    assert final_action_campaign in (
        Action.ALLOW,
        Action.WARN,
        Action.REQUIRE_APPROVAL,
    ), f"HC1 got unexpected action: {final_action_campaign.name}"

    print("[PASS] HC1 Invariant Test PASSED")
    print(f"   Actions: {[a.name for a in actions]}")
    print(f"   Final: {final_action_campaign.name}")
    print(f"   Risk: {report.get('combined_risk_score', 0.0):.3f}")


if __name__ == "__main__":
    test_hc1_never_blocks()
    print("\n[PASS] All HC1 invariant tests passed!")
