"""
Helper script to export FirewallDecision records to JSONL format.

This is a utility for tests/examples only. It does not change the core
logging strategy of the project.

Usage:
    python scripts/export_decisions_to_jsonl.py --output logs/decisions.jsonl

Author: Joerg Bollwahn
Date: 2025-12-02
License: MIT
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

# Import FirewallEngine for example usage
try:
    from llm_firewall.core.firewall_engine_v2 import FirewallEngine
    from llm_firewall.core.policy_provider import get_default_provider

    HAS_FIREWALL = True
except ImportError:
    HAS_FIREWALL = False
    FirewallEngine = None  # type: ignore
    get_default_provider = None  # type: ignore


def decision_to_dict(decision) -> Dict[str, Any]:
    """
    Convert FirewallDecision to dictionary for JSON serialization.

    Args:
        decision: FirewallDecision instance

    Returns:
        Dictionary representation
    """
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "sanitized_text": decision.sanitized_text,
        "detected_threats": decision.detected_threats or [],
        "metadata": decision.metadata or {},
    }


def export_decisions(decisions: List[Dict[str, Any]], output_path: Path) -> None:
    """
    Export decisions to JSONL file.

    Args:
        decisions: List of decision dictionaries
        output_path: Path to output JSONL file
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        for decision in decisions:
            f.write(json.dumps(decision, ensure_ascii=False) + "\n")

    print(f"Exported {len(decisions)} decisions to: {output_path}")


def example_usage() -> List[Dict[str, Any]]:
    """
    Example: Generate decisions from FirewallEngine for testing.

    Returns:
        List of decision dictionaries
    """
    if not HAS_FIREWALL:
        print(
            "Warning: FirewallEngine not available. Returning empty list.",
            file=sys.stderr,
        )
        return []

    engine = FirewallEngine()
    provider = get_default_provider()

    test_inputs = [
        "Normal text input",
        "How do I hack a password?",
        "Explain quantum computing",
    ]

    decisions = []
    for i, text in enumerate(test_inputs):
        decision = engine.process_input(
            text,
            use_answer_policy=True,
            policy_provider=provider,
            tenant_id="test_tenant",
        )
        decisions.append(decision_to_dict(decision))

    return decisions


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Export FirewallDecision records to JSONL format (for tests/examples)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output JSONL file path",
    )
    parser.add_argument(
        "--example",
        action="store_true",
        help="Generate example decisions from FirewallEngine (for testing)",
    )

    args = parser.parse_args()

    if args.example:
        if not HAS_FIREWALL:
            print(
                "Error: FirewallEngine not available. Cannot generate examples.",
                file=sys.stderr,
            )
            return 1

        decisions = example_usage()
        if not decisions:
            print("Error: No decisions generated.", file=sys.stderr)
            return 1

        export_decisions(decisions, args.output)
        return 0
    else:
        print(
            "Error: --example flag required. This script is for tests/examples only.",
            file=sys.stderr,
        )
        print(
            "To export decisions from your application, use decision_to_dict() helper.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
