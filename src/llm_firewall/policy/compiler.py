"""
Policy Compiler - DSL to Executable Program
Purpose: Compile declarative policies to runtime-executable programs
Creator: Joerg Bollwahn
Date: 2025-10-30

Key Features:
- Deterministic rule evaluation
- Priority-based matching (first match wins)
- Feature-based condition matching
- Risk uplift calculation
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .dsl import PolicyCond, PolicyLeaf, PolicySpec


@dataclass(frozen=True)
class CompiledRule:
    """
    Compiled policy rule (runtime representation).

    Attributes:
        id: Rule ID
        priority: Priority (lower = higher)
        action: Action to take
        reason: Reason for action
        max_steps: Maximum steps (for allow_high_level)
        cond: Condition AST
    """

    id: str
    priority: int
    action: str
    reason: str
    max_steps: Optional[int]
    cond: PolicyCond


@dataclass(frozen=True)
class PolicyProgram:
    """
    Compiled policy program.

    Attributes:
        defaults: Default values from spec
        rules: Compiled rules (sorted by priority)
    """

    defaults: Dict[str, Any]
    rules: List[CompiledRule]


def _match_leaf(leaf: PolicyLeaf, features: Dict[str, Any]) -> bool:
    """
    Match leaf condition against features.

    Args:
        leaf: Leaf condition
        features: Runtime features dict

    Returns:
        True if leaf condition matches
    """
    if leaf.kind == "contains_any":
        text = str(features.get("text", "")).lower()
        values = leaf.value if isinstance(leaf.value, list) else [leaf.value]
        return any(str(token).lower() in text for token in values)

    if leaf.kind == "topic_in":
        topics = set(map(str, features.get("topics", [])))
        values = leaf.value if isinstance(leaf.value, list) else [leaf.value]
        value_set = set(map(str, values))
        return bool(topics & value_set)

    if leaf.kind == "domain_is":
        return str(features.get("domain", "")) == str(leaf.value)

    if leaf.kind == "user_age":
        comparator = str(leaf.value).strip()
        age = features.get("user_age")

        if age is None:
            return False

        try:
            age_float = float(age)
        except (ValueError, TypeError):
            return False

        # Parse comparator
        if comparator.startswith("<="):
            return age_float <= float(comparator[2:])
        if comparator.startswith(">="):
            return age_float >= float(comparator[2:])
        if comparator.startswith("<"):
            return age_float < float(comparator[1:])
        if comparator.startswith(">"):
            return age_float > float(comparator[1:])
        if comparator.replace(".", "").isdigit():
            return age_float == float(comparator)

        return False

    raise ValueError(f"Unknown leaf kind: {leaf.kind}")


def _match(cond: PolicyCond, features: Dict[str, Any]) -> bool:
    """
    Match condition against features recursively.

    Args:
        cond: Condition to match
        features: Runtime features

    Returns:
        True if condition matches
    """
    if cond.leaf:
        return _match_leaf(cond.leaf, features)

    if cond.all:
        return all(_match(subcond, features) for subcond in cond.all)

    if cond.any:
        return any(_match(subcond, features) for subcond in cond.any)

    return False


def compile_spec(spec: PolicySpec) -> PolicyProgram:
    """
    Compile PolicySpec to executable PolicyProgram.

    Args:
        spec: Policy specification

    Returns:
        Compiled program with sorted rules
    """
    compiled_rules = [
        CompiledRule(
            id=rule.id,
            priority=rule.priority,
            action=rule.action,
            reason=rule.reason,
            max_steps=rule.max_steps,
            cond=rule.when,
        )
        for rule in spec.rules
    ]

    return PolicyProgram(defaults=spec.defaults, rules=compiled_rules)


def evaluate(program: PolicyProgram, features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate policy program against features.

    First matching rule wins (rules sorted by priority).

    Args:
        program: Compiled policy program
        features: Runtime features dict

    Returns:
        Dict with action, reason, risk_uplift, rule_id, optional max_steps
    """
    # Evaluate rules in priority order
    for rule in program.rules:
        if _match(rule.cond, features):
            result: Dict[str, Any] = {
                "action": rule.action,
                "reason": rule.reason or rule.id,
                "rule_id": rule.id,
            }

            # Calculate risk uplift based on action
            if rule.action == "block":
                result["risk_uplift"] = float(
                    program.defaults.get("risk_uplift_block", 1.0)
                )
            elif rule.action == "allow_high_level":
                result["risk_uplift"] = float(
                    program.defaults.get("risk_uplift_allow_high_level", 0.2)
                )
                result["max_steps"] = (
                    rule.max_steps
                    if rule.max_steps is not None
                    else program.defaults.get("max_steps", 0)
                )
            else:  # allow
                result["risk_uplift"] = 0.0

            return result

    # No rule matched - use default
    return {
        "action": program.defaults.get("action", "allow"),
        "reason": "default",
        "risk_uplift": 0.0,
        "rule_id": "<default>",
    }
