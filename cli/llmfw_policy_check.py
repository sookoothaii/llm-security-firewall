"""
Policy Validation CLI Tool
Purpose: Validate policy YAML for conflicts and determinism
Creator: Joerg Bollwahn
Date: 2025-10-30

Usage:
    python cli/llmfw_policy_check.py policies/base.yaml
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from llm_firewall.policy.analyzer import analyze
from llm_firewall.policy.dsl import parse_yaml_spec


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Validate policy YAML for conflicts")
    parser.add_argument("policy_yaml", type=str, help="Path to policy YAML file")
    parser.add_argument(
        "--strict", action="store_true", help="Treat shadowing as error"
    )
    args = parser.parse_args()

    policy_path = Path(args.policy_yaml)

    if not policy_path.exists():
        print(f"ERROR: Policy file not found: {policy_path}")
        sys.exit(1)

    # Load and parse
    print(f"Loading policy: {policy_path}")
    with policy_path.open("r", encoding="utf-8") as f:
        spec = parse_yaml_spec(yaml.safe_load(f))

    print(f"  Version: {spec.version}")
    print(f"  Rules: {len(spec.rules)}")

    # Analyze for issues
    print("\nAnalyzing...")
    issues = analyze(spec)

    if not issues:
        print("OK: No issues found (policy is deterministic)")
        sys.exit(0)

    # Report issues
    print(f"\nFound {len(issues)} issue(s):\n")
    for issue in issues:
        print(f"[{issue.kind.upper()}] {issue.rule_ids[0]} <-> {issue.rule_ids[1]}")
        print(f"  {issue.message}\n")

    # Check for hard conflicts
    conflicts = [i for i in issues if i.kind == "conflict"]
    shadowed = [i for i in issues if i.kind == "shadowed"]

    if conflicts:
        print(f"UNSAT: {len(conflicts)} conflict(s) present (non-deterministic policy)")
        sys.exit(2)

    if shadowed and args.strict:
        print(f"ERROR: {len(shadowed)} shadowing issue(s) (--strict mode)")
        sys.exit(2)

    if shadowed:
        print(f"WARNING: {len(shadowed)} shadowing issue(s) (not critical)")
        sys.exit(0)


if __name__ == "__main__":
    main()
