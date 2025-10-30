"""
Tests for Policy DSL Parsing
Creator: Joerg Bollwahn
Date: 2025-10-30
"""

import pathlib

import pytest
import yaml

from src.llm_firewall.policy.dsl import PolicyCond, PolicyLeaf, parse_yaml_spec


class TestPolicyLeaf:
    """Test PolicyLeaf validation."""

    def test_valid_leaf(self):
        """Valid leaf should not raise."""
        leaf = PolicyLeaf(kind="contains_any", value=["test"])
        assert leaf.kind == "contains_any"


class TestPolicyCond:
    """Test PolicyCond validation."""

    def test_exactly_one_field_required(self):
        """PolicyCond must have exactly one of {all, any, leaf}."""
        # Valid: exactly one field
        cond_leaf = PolicyCond(leaf=PolicyLeaf("domain_is", "SCIENCE"))
        assert cond_leaf.leaf is not None

        # Invalid: multiple fields
        with pytest.raises(ValueError, match="exactly one"):
            PolicyCond(
                all=[],
                any=[],  # Both set
            )

        # Invalid: no fields
        with pytest.raises(ValueError, match="exactly one"):
            PolicyCond()


class TestParseYAMLSpec:
    """Test YAML parsing."""

    def test_parse_base_policy(self):
        """Test parsing base.yaml."""
        policy_path = pathlib.Path("policies/base.yaml")
        assert policy_path.exists(), "base.yaml not found"

        with policy_path.open("r", encoding="utf-8") as f:
            yaml_obj = yaml.safe_load(f)

        spec = parse_yaml_spec(yaml_obj)

        assert spec.version == 1
        assert len(spec.rules) > 0
        assert "priority_step" in spec.defaults

    def test_rules_sorted_by_priority(self):
        """Rules should be sorted by ascending priority."""
        policy_path = pathlib.Path("policies/base.yaml")

        with policy_path.open("r", encoding="utf-8") as f:
            spec = parse_yaml_spec(yaml.safe_load(f))

        priorities = [rule.priority for rule in spec.rules]
        assert priorities == sorted(priorities), "Rules must be sorted by priority"

    def test_parse_minimal_spec(self):
        """Test parsing minimal spec."""
        yaml_obj = {
            "version": 1,
            "defaults": {"action": "allow"},
            "rules": [
                {
                    "id": "test_rule",
                    "priority": 10,
                    "when": {"domain_is": "TEST"},
                    "then": {"action": "block", "reason": "test"},
                }
            ],
        }

        spec = parse_yaml_spec(yaml_obj)
        assert len(spec.rules) == 1
        assert spec.rules[0].id == "test_rule"
        assert spec.rules[0].action == "block"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

