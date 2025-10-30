"""
Policy Domain-Specific Language (DSL) - Parser and Data Structures
Purpose: Declarative policy specification with type-safe parsing
Creator: Joerg Bollwahn
Date: 2025-10-30

Key Features:
- YAML-based policy specification
- Type-safe parsing with validation
- Priority-based rule ordering
- Support for complex conditions (all/any/leaf)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class PolicyLeaf:
    """
    Leaf condition in policy AST.

    Attributes:
        kind: Predicate type (contains_any, topic_in, user_age, domain_is)
        value: Predicate value (string, list, or comparison)
    """

    kind: str
    value: Any


@dataclass(frozen=True)
class PolicyCond:
    """
    Policy condition (recursive AST node).

    Supports:
    - all: Conjunction (AND) of subconditions
    - any: Disjunction (OR) of subconditions
    - leaf: Leaf predicate

    Exactly one of {all, any, leaf} must be set.
    """

    all: Optional[List[PolicyCond]] = None
    any: Optional[List[PolicyCond]] = None
    leaf: Optional[PolicyLeaf] = None

    def __post_init__(self) -> None:
        """Validate that exactly one field is set."""
        set_count = sum(
            [self.all is not None, self.any is not None, self.leaf is not None]
        )
        if set_count != 1:
            raise ValueError("PolicyCond must have exactly one of {all, any, leaf}")


@dataclass(frozen=True)
class PolicyRule:
    """
    Single policy rule.

    Attributes:
        id: Unique rule identifier
        priority: Priority (lower number = higher priority)
        when: Condition AST
        action: Action to take (allow, allow_high_level, block)
        reason: Human-readable reason
        max_steps: Maximum steps allowed (for allow_high_level)
    """

    id: str
    priority: int
    when: PolicyCond
    action: str
    reason: str = ""
    max_steps: Optional[int] = None


@dataclass(frozen=True)
class PolicySpec:
    """
    Complete policy specification.

    Attributes:
        version: Policy schema version
        defaults: Default values
        rules: List of policy rules (sorted by priority)
    """

    version: int
    defaults: Dict[str, Any]
    rules: List[PolicyRule]


# === Parser ===


def _to_leaf(d: Dict[str, Any]) -> PolicyLeaf:
    """
    Parse dict to PolicyLeaf.

    Args:
        d: Dict with single key-value pair

    Returns:
        PolicyLeaf instance

    Raises:
        ValueError: If dict doesn't have exactly one key or uses unknown predicate
    """
    if len(d) != 1:
        raise ValueError(f"Leaf must have exactly one key, got {list(d.keys())}")

    (key, value) = next(iter(d.items()))

    allowed_predicates = {"contains_any", "topic_in", "user_age", "domain_is"}
    if key not in allowed_predicates:
        raise ValueError(f"Unknown leaf predicate: {key}")

    return PolicyLeaf(kind=key, value=value)


def _to_cond(obj: Any) -> PolicyCond:
    """
    Parse object to PolicyCond recursively.

    Args:
        obj: Dict or other object

    Returns:
        PolicyCond instance

    Raises:
        ValueError: If obj is not a valid condition
    """
    if not isinstance(obj, dict):
        raise ValueError("Condition must be dict")

    if "all" in obj:
        subconds = [_to_cond(x) for x in obj["all"]]
        return PolicyCond(all=subconds)

    if "any" in obj:
        subconds = [_to_cond(x) for x in obj["any"]]
        return PolicyCond(any=subconds)

    # Leaf condition
    return PolicyCond(leaf=_to_leaf(obj))


def parse_yaml_spec(yaml_obj: Dict[str, Any]) -> PolicySpec:
    """
    Parse YAML object to PolicySpec.

    Args:
        yaml_obj: Parsed YAML dict

    Returns:
        PolicySpec with sorted rules (ascending priority)

    Raises:
        ValueError: On parse errors
    """
    version = int(yaml_obj.get("version", 1))
    defaults = dict(yaml_obj.get("defaults", {}))
    raw_rules = yaml_obj.get("rules", [])

    rules: List[PolicyRule] = []
    default_priority = defaults.get("priority_step", 10)

    for rule_dict in raw_rules:
        rule_id = str(rule_dict["id"])
        priority = int(rule_dict.get("priority", default_priority))

        # Parse condition
        when = _to_cond(rule_dict["when"])

        # Parse action
        then = rule_dict["then"]
        action = str(then.get("action", "allow"))
        reason = str(then.get("reason", ""))
        max_steps = then.get("max_steps")

        rules.append(PolicyRule(rule_id, priority, when, action, reason, max_steps))

    # Sort by ascending priority (lower number first)
    rules.sort(key=lambda r: r.priority)

    return PolicySpec(version=version, defaults=defaults, rules=rules)
