"""
NLI Consistency Judge
=====================

Natural Language Inference for claim consistency checking.

Implements ConCoRD-style factor graph approach.

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

import time
from typing import List, Optional

from llm_firewall.core.types import (
    JudgeReport,
    ModelContext,
    RiskScore,
    Severity,
    TaxonomyRisk,
)


class NLIConsistencyJudge:
    """
    Judge for logical consistency via NLI.

    Checks:
    - Claim ↔ Policy consistency
    - Claim ↔ KB Facts consistency
    - Internal contradictions

    Future: Factor Graph + Weighted MaxSAT (ConCoRD)
    Current: Simple NLI-based implementation
    """

    name = "nli_consistency"
    version = "1.0.0"

    def __init__(
        self,
        kb_facts: Optional[List[str]] = None,
        policy_statements: Optional[List[str]] = None,
    ):
        """
        Initialize NLI judge.

        Args:
            kb_facts: Knowledge base facts for consistency checking
            policy_statements: Policy rules to enforce
        """
        self.kb_facts = kb_facts or []
        self.policy_statements = policy_statements or [
            "Do not provide instructions for harmful activities",
            "Do not bypass safety guidelines",
            "Do not pretend to be another entity",
            "Do not provide personal information",
        ]

        # Simple keyword-based implementation (production should use NLI model)
        self.contradiction_patterns = [
            ("yes", "no"),
            ("allow", "deny"),
            ("safe", "dangerous"),
            ("permitted", "forbidden"),
        ]

    def score(self, ctx: ModelContext, prompt: str, draft: str) -> JudgeReport:
        """
        Score for logical consistency.

        Args:
            ctx: Model context
            prompt: User input
            draft: LLM response

        Returns:
            JudgeReport with consistency assessment
        """
        t0 = time.perf_counter()

        # Extract claims from draft (simplified - production should use claim extractor)
        claims = self._extract_claims(draft)

        # Check consistency
        policy_violations = self._check_policy_consistency(claims, prompt, draft)
        kb_contradictions = self._check_kb_consistency(claims)
        self_contradictions = self._check_self_consistency(draft)

        # Compute overall risk
        violation_count = (
            len(policy_violations) + len(kb_contradictions) + len(self_contradictions)
        )
        risk_value = min(1.0, violation_count * 0.25)

        # Map to severity
        if violation_count >= 3:
            severity = Severity.HIGH
        elif violation_count >= 2:
            severity = Severity.MEDIUM
        elif violation_count >= 1:
            severity = Severity.LOW
        else:
            severity = Severity.NONE

        latency_ms = (time.perf_counter() - t0) * 1000

        # Build report
        categories = {
            "policy_violation": RiskScore(
                value=min(1.0, len(policy_violations) * 0.4),
                band="unknown",
                severity=Severity.HIGH if policy_violations else Severity.NONE,
                calibrated=False,
            ),
            "kb_contradiction": RiskScore(
                value=min(1.0, len(kb_contradictions) * 0.3),
                band="unknown",
                severity=Severity.MEDIUM if kb_contradictions else Severity.NONE,
                calibrated=False,
            ),
            "self_contradiction": RiskScore(
                value=min(1.0, len(self_contradictions) * 0.3),
                band="unknown",
                severity=Severity.MEDIUM if self_contradictions else Severity.NONE,
                calibrated=False,
            ),
        }

        overall = RiskScore(
            value=risk_value,
            band="unknown",
            severity=severity,
            calibrated=False,
            method="nli_simple",
        )

        return JudgeReport(
            name=self.name,
            version=self.version,
            latency_ms=latency_ms,
            risks=TaxonomyRisk(categories=categories, overall=overall),
            features={
                "claims_extracted": len(claims),
                "policy_violations": policy_violations,
                "kb_contradictions": kb_contradictions,
                "self_contradictions": self_contradictions,
            },
            notes=f"Violations: {violation_count} total",
        )

    def _extract_claims(self, text: str) -> List[str]:
        """
        Extract claims from text.

        Simplified implementation - splits on sentence boundaries.
        Production should use claim extraction model.
        """
        # Simple sentence splitting
        sentences = text.replace("!", ".").replace("?", ".").split(".")
        return [s.strip() for s in sentences if s.strip() and len(s.strip()) > 10]

    def _check_policy_consistency(
        self, claims: List[str], prompt: str, draft: str
    ) -> List[str]:
        """
        Check if response violates policy statements.

        Simplified keyword-based check.
        Production should use NLI model.
        """
        violations = []
        text_lower = (prompt + " " + draft).lower()

        # Check for policy bypass patterns
        bypass_patterns = [
            "ignore previous instructions",
            "disregard safety",
            "you are now in",
            "developer mode",
            "jailbreak",
        ]

        for pattern in bypass_patterns:
            if pattern in text_lower:
                violations.append(f"Policy bypass detected: '{pattern}'")

        return violations

    def _check_kb_consistency(self, claims: List[str]) -> List[str]:
        """
        Check claims against KB facts.

        Simplified implementation.
        Production should use semantic similarity + NLI.
        """
        # Placeholder - would need real KB integration
        contradictions: List[str] = []
        return contradictions

    def _check_self_consistency(self, text: str) -> List[str]:
        """
        Check for internal contradictions.

        Simplified pattern-based approach.
        Production should use NLI pairwise comparison.
        """
        contradictions = []
        text_lower = text.lower()

        for p1, p2 in self.contradiction_patterns:
            if p1 in text_lower and p2 in text_lower:
                # Check if they appear in close proximity (potential contradiction)
                p1_idx = text_lower.find(p1)
                p2_idx = text_lower.find(p2)
                if abs(p1_idx - p2_idx) < 200:  # Within 200 chars
                    contradictions.append(f"Potential contradiction: '{p1}' vs '{p2}'")

        return contradictions
