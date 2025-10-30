"""
Policy Judge
============

Rule-based and ontology-driven policy enforcement.

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

import time
from typing import Any, Dict, List, Optional

from llm_firewall.core.types import (
    JudgeReport,
    ModelContext,
    RiskScore,
    Severity,
    TaxonomyRisk,
)


class PolicyJudge:
    """
    Rule-based policy judge.

    Checks against defined safety policies and content guidelines.
    Can be extended with ontology reasoner or LLM-based policy check.
    """

    name = "policy_judge"
    version = "1.0.0"

    def __init__(self, policy_rules: Optional[List[Dict[str, Any]]] = None):
        """
        Initialize policy judge.

        Args:
            policy_rules: List of policy rules (pattern, severity, category)
        """
        self.policy_rules = policy_rules or self._default_rules()

    def _default_rules(self) -> List[Dict[str, Any]]:
        """Default safety policy rules."""
        return [
            {
                "category": "instruction_bypass",
                "patterns": ["ignore previous", "disregard", "forget instructions"],
                "severity": Severity.HIGH,
                "weight": 0.8,
            },
            {
                "category": "role_hijack",
                "patterns": ["you are now", "pretend to be", "act as"],
                "severity": Severity.MEDIUM,
                "weight": 0.6,
            },
            {
                "category": "safety_bypass",
                "patterns": ["jailbreak", "unrestricted mode", "developer override"],
                "severity": Severity.HIGH,
                "weight": 0.9,
            },
            {
                "category": "information_extraction",
                "patterns": [
                    "show me the prompt",
                    "what are your instructions",
                    "reveal",
                ],
                "severity": Severity.MEDIUM,
                "weight": 0.5,
            },
        ]

    def score(self, ctx: ModelContext, prompt: str, draft: str) -> JudgeReport:
        """
        Score against policy rules.

        Args:
            ctx: Model context
            prompt: User input
            draft: LLM response

        Returns:
            JudgeReport with policy violations
        """
        t0 = time.perf_counter()

        text = (prompt + " " + draft).lower()

        # Check each rule
        violations: Dict[str, RiskScore] = {}
        max_severity = Severity.NONE
        total_risk = 0.0

        for rule in self.policy_rules:
            category = rule["category"]
            patterns = rule["patterns"]
            severity = rule["severity"]
            weight = rule["weight"]

            # Check if any pattern matches
            matches = [p for p in patterns if p in text]

            if matches:
                risk_value = min(1.0, len(matches) * 0.3 * weight)
                total_risk += risk_value
                max_severity = max(max_severity, severity)

                violations[category] = RiskScore(
                    value=risk_value,
                    band="unknown",
                    severity=severity,
                    calibrated=False,
                    method="rule_based",
                )

        # Overall risk
        overall_risk = min(1.0, total_risk)

        latency_ms = (time.perf_counter() - t0) * 1000

        overall = RiskScore(
            value=overall_risk,
            band="unknown",
            severity=max_severity,
            calibrated=False,
            method="policy_rules",
        )

        return JudgeReport(
            name=self.name,
            version=self.version,
            latency_ms=latency_ms,
            risks=TaxonomyRisk(categories=violations, overall=overall),
            features={
                "rules_checked": len(self.policy_rules),
                "violations_count": len(violations),
            },
            notes=f"Policy violations: {list(violations.keys())}"
            if violations
            else "No violations",
        )
