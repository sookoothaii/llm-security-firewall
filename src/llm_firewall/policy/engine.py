"""
Policy Engine - Runtime Policy Evaluation
Purpose: Load, validate, and execute declarative policies
Creator: Joerg Bollwahn
Date: 2025-10-30

Key Features:
- Fail-fast on policy conflicts (SAT-check at init)
- Deterministic evaluation (first matching rule wins)
- Risk uplift integration for Conformal Stacker
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from .analyzer import analyze
from .compiler import PolicyProgram, compile_spec, evaluate
from .dsl import parse_yaml_spec


@dataclass(frozen=True)
class PolicyOutcome:
    """
    Policy evaluation outcome.

    Attributes:
        action: Action to take (allow, allow_high_level, block)
        risk_uplift: Risk penalty to add to aggregator [0, 1]
        reason: Human-readable reason
        rule_id: Matched rule ID
        max_steps: Maximum steps allowed (for allow_high_level)
    """

    action: str
    risk_uplift: float
    reason: str
    rule_id: str
    max_steps: Optional[int] = None


class PolicyEngine:
    """
    Policy engine for runtime evaluation.

    Loads YAML policy, validates for conflicts, compiles to executable program.

    Example:
        >>> engine = PolicyEngine("policies/base.yaml")
        >>> outcome = engine.decide({"text": "api_key=xyz", "domain": "SCIENCE"})
        >>> if outcome.action == "block":
        ...     log_security_event("policy_blocked")
    """

    def __init__(self, yaml_path: str | Path):
        """
        Initialize policy engine.

        Args:
            yaml_path: Path to policy YAML file

        Raises:
            ValueError: If policy has conflicts (non-deterministic)
            FileNotFoundError: If policy file doesn't exist
        """
        yaml_path = Path(yaml_path)

        if not yaml_path.exists():
            raise FileNotFoundError(f"Policy file not found: {yaml_path}")

        # Load and parse YAML
        with yaml_path.open("r", encoding="utf-8") as f:
            yaml_obj = yaml.safe_load(f)

        spec = parse_yaml_spec(yaml_obj)

        # Static analysis - fail-fast on conflicts
        issues = analyze(spec)
        hard_conflicts = [i for i in issues if i.kind == "conflict"]

        if hard_conflicts:
            conflict_ids = ", ".join(
                f"{i.rule_ids[0]}<>{i.rule_ids[1]}" for i in hard_conflicts
            )
            raise ValueError(f"Policy is not deterministic (conflicts): {conflict_ids}")

        # Compile to executable program
        self.program: PolicyProgram = compile_spec(spec)
        self.yaml_path = yaml_path

    def decide(self, features: Dict[str, Any]) -> PolicyOutcome:
        """
        Evaluate policy against features.

        Args:
            features: Runtime features dict
                Required keys: text (str), domain (str)
                Optional keys: topics (list), user_age (float)

        Returns:
            PolicyOutcome with action and risk uplift

        Example:
            >>> outcome = engine.decide({
            ...     "text": "explain biohazard protocols",
            ...     "topics": ["biohazard"],
            ...     "domain": "SCIENCE"
            ... })
            >>> outcome.action  # "allow_high_level"
            >>> outcome.risk_uplift  # 0.20
        """
        result = evaluate(self.program, features)

        return PolicyOutcome(
            action=result["action"],
            risk_uplift=float(result["risk_uplift"]),
            reason=result.get("reason", ""),
            rule_id=result.get("rule_id", ""),
            max_steps=result.get("max_steps"),
        )

    def get_rules_count(self) -> int:
        """Return number of compiled rules."""
        return len(self.program.rules)

    def get_policy_version(self) -> int:
        """Return policy schema version."""
        return self.program.defaults.get("version", 1)
