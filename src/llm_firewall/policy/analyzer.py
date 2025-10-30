"""
Policy Analyzer - Static Analysis for Conflicts and Determinism
Purpose: SAT-like checking for policy conflicts before runtime
Creator: Joerg Bollwahn
Date: 2025-10-30

Key Innovation: Fail-fast on conflicts via static analysis.
Prevents non-deterministic policies from reaching production.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .dsl import PolicyCond, PolicyLeaf, PolicyRule, PolicySpec


@dataclass(frozen=True)
class AnalysisIssue:
    """
    Policy analysis issue.

    Attributes:
        kind: Issue type (conflict, shadowed, warning)
        rule_ids: Tuple of affected rule IDs
        message: Human-readable description
    """

    kind: str
    rule_ids: Tuple[str, str]
    message: str


def _age_interval(leaf: PolicyLeaf) -> Optional[Tuple[float, float]]:
    """
    Extract feasible age interval from user_age leaf.

    Args:
        leaf: PolicyLeaf with kind="user_age"

    Returns:
        Tuple of (min_age, max_age) or None if not age predicate

    Examples:
        "<18" -> (-inf, 18)
        ">=21" -> (21, inf)
        "30" -> (30, 30)
    """
    if leaf.kind != "user_age":
        return None

    value_str = str(leaf.value).strip()

    if value_str.startswith("<="):
        return (float("-inf"), float(value_str[2:]))
    if value_str.startswith(">="):
        return (float(value_str[2:]), float("inf"))
    if value_str.startswith("<"):
        return (float("-inf"), float(value_str[1:]) - 1e-9)
    if value_str.startswith(">"):
        return (float(value_str[1:]) + 1e-9, float("inf"))
    if value_str.replace(".", "").isdigit():
        val = float(value_str)
        return (val, val)

    raise ValueError(f"Unsupported age comparator: {value_str}")


def _collect_constraints(rule: PolicyRule) -> Dict[str, Any]:
    """
    Extract constraints from rule for overlap analysis.

    Conservative extraction:
    - topics_any: Set of acceptable topics
    - domains: Set of required domains
    - contains_any: Set of required tokens
    - age_intervals: List of age intervals (all must be satisfied)

    Args:
        rule: PolicyRule to analyze

    Returns:
        Dict with extracted constraints
    """
    constraints: Dict[str, Any] = {
        "topics_any": set(),
        "domains": set(),
        "contains_any": set(),
        "age_intervals": [],
    }

    def visit(cond: PolicyCond) -> None:
        if cond.leaf:
            leaf = cond.leaf

            if leaf.kind == "topic_in":
                values = leaf.value if isinstance(leaf.value, list) else [leaf.value]
                constraints["topics_any"].update(map(str, values))

            elif leaf.kind == "domain_is":
                constraints["domains"].add(str(leaf.value))

            elif leaf.kind == "contains_any":
                values = leaf.value if isinstance(leaf.value, list) else [leaf.value]
                constraints["contains_any"].update(map(str, values))

            elif leaf.kind == "user_age":
                interval = _age_interval(leaf)
                if interval:
                    constraints["age_intervals"].append(interval)

        elif cond.all:
            for subcond in cond.all:
                visit(subcond)

        elif cond.any:
            # Conservative: include all possibilities
            for subcond in cond.any:
                visit(subcond)

    visit(rule.when)
    return constraints


def _intervals_overlap(a: Tuple[float, float], b: Tuple[float, float]) -> bool:
    """
    Check if two intervals overlap.

    Args:
        a: First interval (min, max)
        b: Second interval (min, max)

    Returns:
        True if intervals overlap
    """
    return not (a[1] < b[0] or b[1] < a[0])


def may_overlap(rule1: PolicyRule, rule2: PolicyRule) -> bool:
    """
    Conservative overlap detection between two rules.

    Two rules may overlap if their constraints are compatible.
    Returns False only if provably disjoint.

    Args:
        rule1: First rule
        rule2: Second rule

    Returns:
        True if rules may overlap (conservative)
    """
    c1 = _collect_constraints(rule1)
    c2 = _collect_constraints(rule2)

    # Domains disjoint -> cannot overlap
    if c1["domains"] and c2["domains"]:
        if c1["domains"].isdisjoint(c2["domains"]):
            return False

    # Age intervals: if both specify, require at least one pair overlap
    intervals1 = c1.get("age_intervals", [])
    intervals2 = c2.get("age_intervals", [])

    if intervals1 and intervals2:
        has_overlap = any(
            _intervals_overlap(i1, i2) for i1 in intervals1 for i2 in intervals2
        )
        if not has_overlap:
            return False

    # Conservative: assume possible overlap
    return True


def analyze(spec: PolicySpec) -> List[AnalysisIssue]:
    """
    Analyze policy for conflicts and issues.

    Detects:
    - Conflicts: Equal priority rules with different actions that may overlap
    - Shadowing: Higher-priority rule may always fire before lower-priority

    Args:
        spec: PolicySpec to analyze

    Returns:
        List of analysis issues
    """
    issues: List[AnalysisIssue] = []

    # Pairwise analysis
    for i in range(len(spec.rules)):
        for j in range(i + 1, len(spec.rules)):
            rule_a = spec.rules[i]
            rule_b = spec.rules[j]

            # Check for conflicts (equal priority, different actions, may overlap)
            if (
                may_overlap(rule_a, rule_b)
                and rule_a.action != rule_b.action
                and rule_a.priority == rule_b.priority
            ):
                issues.append(
                    AnalysisIssue(
                        kind="conflict",
                        rule_ids=(rule_a.id, rule_b.id),
                        message=(
                            f"Rules share priority {rule_a.priority} may overlap with "
                            f"different actions ({rule_a.action} vs {rule_b.action})"
                        ),
                    )
                )

            # Check for shadowing (higher priority may always fire first)
            if (
                rule_a.priority < rule_b.priority
                and may_overlap(rule_a, rule_b)
                and rule_a.action == rule_b.action
            ):
                issues.append(
                    AnalysisIssue(
                        kind="shadowed",
                        rule_ids=(rule_a.id, rule_b.id),
                        message=(
                            f"{rule_a.id} (priority {rule_a.priority}) may shadow "
                            f"{rule_b.id} (priority {rule_b.priority}) with same action"
                        ),
                    )
                )

    return issues
