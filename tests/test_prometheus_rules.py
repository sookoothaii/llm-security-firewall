"""
Tests for Prometheus Rules YAML
Creator: Joerg Bollwahn
Date: 2025-10-30
"""

import pathlib

import yaml


class TestPrometheusRulesYAML:
    """Test Prometheus rules file validity."""

    def test_yaml_is_valid(self):
        """YAML file should be parseable."""
        rules_path = pathlib.Path("deploy/prometheus/rules_firewall.yaml")
        assert rules_path.exists(), "Prometheus rules file not found"

        content = rules_path.read_text()
        data = yaml.safe_load(content)

        assert data is not None
        assert "groups" in data

    def test_contains_recording_rules(self):
        """Should contain recording rules group."""
        rules_path = pathlib.Path("deploy/prometheus/rules_firewall.yaml")
        data = yaml.safe_load(rules_path.read_text())

        group_names = [g["name"] for g in data["groups"]]
        assert "llm_firewall_recording_rules" in group_names

    def test_contains_alerts(self):
        """Should contain alerts group."""
        rules_path = pathlib.Path("deploy/prometheus/rules_firewall.yaml")
        data = yaml.safe_load(rules_path.read_text())

        group_names = [g["name"] for g in data["groups"]]
        assert "llm_firewall_alerts" in group_names

    def test_has_asr_alert(self):
        """Should have ASR alert rule."""
        rules_path = pathlib.Path("deploy/prometheus/rules_firewall.yaml")
        data = yaml.safe_load(rules_path.read_text())

        alerts_group = next(
            g for g in data["groups"] if g["name"] == "llm_firewall_alerts"
        )
        alert_names = [rule["alert"] for rule in alerts_group["rules"]]

        assert "ASRBudgetExceeded" in alert_names

    def test_has_critical_leak_alert(self):
        """Should have critical-leak@20 alert."""
        rules_path = pathlib.Path("deploy/prometheus/rules_firewall.yaml")
        data = yaml.safe_load(rules_path.read_text())

        alerts_group = next(
            g for g in data["groups"] if g["name"] == "llm_firewall_alerts"
        )
        alert_names = [rule["alert"] for rule in alerts_group["rules"]]

        assert "CriticalLeakAt20" in alert_names

    def test_has_latency_alert(self):
        """Should have latency alert."""
        rules_path = pathlib.Path("deploy/prometheus/rules_firewall.yaml")
        data = yaml.safe_load(rules_path.read_text())

        alerts_group = next(
            g for g in data["groups"] if g["name"] == "llm_firewall_alerts"
        )
        alert_names = [rule["alert"] for rule in alerts_group["rules"]]

        assert "GuardLatencyP99High" in alert_names


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])

