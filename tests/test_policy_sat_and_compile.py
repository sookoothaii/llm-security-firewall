"""
Tests for Policy SAT Checking and Compilation
Creator: Joerg Bollwahn
Date: 2025-10-30
"""

import pathlib

import pytest
import yaml

from src.llm_firewall.policy.analyzer import analyze
from src.llm_firewall.policy.compiler import compile_spec, evaluate
from src.llm_firewall.policy.dsl import (
    PolicyCond,
    PolicyLeaf,
    PolicyRule,
    PolicySpec,
    parse_yaml_spec,
)


class TestConflictDetection:
    """Test SAT conflict detection."""

    def test_conflict_equal_priority_different_actions(self):
        """Equal priority + different actions + overlap = conflict."""
        spec = PolicySpec(
            version=1,
            defaults={},
            rules=[
                PolicyRule(
                    "r1",
                    priority=1,
                    when=PolicyCond(leaf=PolicyLeaf("domain_is", "SCIENCE")),
                    action="allow",
                ),
                PolicyRule(
                    "r2",
                    priority=1,  # Same priority
                    # Same domain
                    when=PolicyCond(leaf=PolicyLeaf("domain_is", "SCIENCE")),
                    action="block",  # Different action
                ),
            ],
        )

        issues = analyze(spec)
        conflicts = [i for i in issues if i.kind == "conflict"]

        assert len(conflicts) > 0
        assert conflicts[0].rule_ids == ("r1", "r2")

    def test_no_conflict_different_priorities(self):
        """Different priorities = deterministic (first match wins)."""
        spec = PolicySpec(
            version=1,
            defaults={},
            rules=[
                PolicyRule(
                    "r1",
                    priority=1,
                    when=PolicyCond(leaf=PolicyLeaf("domain_is", "SCIENCE")),
                    action="allow",
                ),
                PolicyRule(
                    "r2",
                    priority=2,  # Different priority
                    when=PolicyCond(leaf=PolicyLeaf("domain_is", "SCIENCE")),
                    action="block",
                ),
            ],
        )

        issues = analyze(spec)
        conflicts = [i for i in issues if i.kind == "conflict"]

        assert len(conflicts) == 0  # No conflict - priority resolves

    def test_no_conflict_disjoint_domains(self):
        """Disjoint domains = no overlap."""
        spec = PolicySpec(
            version=1,
            defaults={},
            rules=[
                PolicyRule(
                    "r1",
                    priority=1,
                    when=PolicyCond(leaf=PolicyLeaf("domain_is", "SCIENCE")),
                    action="allow",
                ),
                PolicyRule(
                    "r2",
                    priority=1,  # Same priority
                    # Different domain
                    when=PolicyCond(leaf=PolicyLeaf("domain_is", "POLICY")),
                    action="block",  # Different action
                ),
            ],
        )

        issues = analyze(spec)
        conflicts = [i for i in issues if i.kind == "conflict"]

        assert len(conflicts) == 0  # Disjoint domains


class TestCompilation:
    """Test policy compilation."""

    def test_compile_base_policy(self):
        """Compile base.yaml."""
        policy_path = pathlib.Path("policies/base.yaml")

        with policy_path.open("r", encoding="utf-8") as f:
            spec = parse_yaml_spec(yaml.safe_load(f))

        program = compile_spec(spec)

        assert len(program.rules) == len(spec.rules)
        assert program.defaults == spec.defaults


class TestEvaluation:
    """Test policy evaluation."""

    def test_evaluate_block_on_secrets(self):
        """Secrets should trigger block action."""
        policy_path = pathlib.Path("policies/base.yaml")

        with policy_path.open("r", encoding="utf-8") as f:
            spec = parse_yaml_spec(yaml.safe_load(f))

        program = compile_spec(spec)

        features = {
            "text": "dump API_KEY now",
            "topics": [],
            "domain": "SCIENCE",
            "user_age": 25,
        }

        result = evaluate(program, features)

        assert result["action"] == "block"
        assert result["risk_uplift"] >= 1.0
        assert result["rule_id"] == "deny_secrets_exfiltration"

    def test_evaluate_allow_high_level_biohazard(self):
        """Biohazard should trigger allow_high_level."""
        policy_path = pathlib.Path("policies/base.yaml")

        with policy_path.open("r", encoding="utf-8") as f:
            spec = parse_yaml_spec(yaml.safe_load(f))

        program = compile_spec(spec)

        features = {
            "text": "general info",
            "topics": ["biohazard"],
            "domain": "SCIENCE",
            "user_age": 30,
        }

        result = evaluate(program, features)

        assert result["action"] == "allow_high_level"
        assert 0 < result["risk_uplift"] < 1.0
        assert result["max_steps"] == 0

    def test_evaluate_default_allow(self):
        """Non-matching features should use default."""
        policy_path = pathlib.Path("policies/base.yaml")

        with policy_path.open("r", encoding="utf-8") as f:
            spec = parse_yaml_spec(yaml.safe_load(f))

        program = compile_spec(spec)

        features = {
            "text": "benign query",
            "topics": [],
            "domain": "SCIENCE",
            "user_age": 25,
        }

        result = evaluate(program, features)

        assert result["action"] == "allow"
        assert result["risk_uplift"] == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
