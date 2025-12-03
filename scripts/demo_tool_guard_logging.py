"""
Demo: Tool Guard Logging
========================

Demonstrates how tool call contexts could be attached to firewall decisions
for future tool-abuse evaluation.

This is a scaffolding example - not integrated into the actual firewall engine yet.

Author: Joerg Bollwahn
Date: 2025-12-03
License: MIT
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any

# Add parent directory to path for imports
base_dir = Path(__file__).parent.parent
if base_dir.exists():
    sys.path.insert(0, str(base_dir))

from scripts.tool_guard_types import ToolCallContext, ToolCallSession


def create_example_tool_call() -> ToolCallContext:
    """Create an example tool call context."""
    return ToolCallContext(
        tool_name="file_write",
        arguments={"path": "/tmp/secret.txt", "content": "sensitive data"},
        dangerous_pattern_flags=["file_write", "potential_data_exfiltration"],
        metadata={"risk_level": "high"},
    )


def create_example_session() -> ToolCallSession:
    """Create an example tool call session."""
    session = ToolCallSession(session_id="demo_session_001")
    session.add_tool_call(create_example_tool_call())
    session.add_tool_call(
        ToolCallContext(
            tool_name="network_request",
            arguments={"url": "https://external-api.com", "method": "POST"},
            dangerous_pattern_flags=["external_network"],
        )
    )
    return session


def attach_tool_context_to_decision(
    decision: Dict[str, Any], tool_session: ToolCallSession
) -> Dict[str, Any]:
    """
    Attach tool call context to a decision dictionary.

    This demonstrates how tool contexts could be integrated into decision logs.

    Args:
        decision: Firewall decision dictionary
        tool_session: Tool call session to attach

    Returns:
        Decision dictionary with tool context attached
    """
    # Ensure metadata exists
    if "metadata" not in decision:
        decision["metadata"] = {}

    # Attach tool context
    decision["metadata"]["tool_calls"] = tool_session.to_dict()

    return decision


def main() -> int:
    """Main entry point for demo."""
    print("Tool Guard Logging Demo")
    print("=" * 70)
    print("")

    # Create example session
    session = create_example_session()
    print(f"Created session: {session.session_id}")
    print(f"  Total tool calls: {session.total_calls}")
    print("")

    # Show tool calls
    for i, tc in enumerate(session.tool_calls, start=1):
        print(f"Tool Call {i}:")
        print(f"  Name: {tc.tool_name}")
        print(f"  Arguments: {tc.arguments}")
        print(f"  Flags: {tc.dangerous_pattern_flags}")
        print("")

    # Create example decision
    example_decision = {
        "item_id": "demo_001",
        "item_type": "redteam",
        "allowed": False,
        "reason": "Blocked by safety layer",
        "risk_score": 0.85,
        "metadata": {
            "answer_policy": {
                "enabled": True,
                "policy_name": "default",
            },
        },
    }

    print("Example decision (before):")
    print(json.dumps(example_decision, indent=2))
    print("")

    # Attach tool context
    decision_with_tools = attach_tool_context_to_decision(
        example_decision.copy(), session
    )

    print("Example decision (after attaching tool context):")
    print(json.dumps(decision_with_tools, indent=2))
    print("")

    print("=" * 70)
    print("Note: This is scaffolding. Tool context is not yet integrated")
    print("      into the actual firewall engine or decision pipeline.")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
