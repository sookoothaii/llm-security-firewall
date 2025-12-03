"""
Tests for AnswerPolicy metrics analysis script.

Tests the core analysis logic (not CLI parsing).
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

# Add scripts directory to path for imports
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from analyze_answer_policy_metrics import (
    analyze_decisions,
    analyze_file,
    parse_jsonl,
)


class TestAnalyzeAnswerPolicyMetrics:
    """Test AnswerPolicy metrics analysis."""

    def test_parse_jsonl_valid(self):
        """Test parsing valid JSONL file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(
                '{"allowed": true, "metadata": {"answer_policy": {"enabled": true}}}\n'
            )
            f.write(
                '{"allowed": false, "metadata": {"answer_policy": {"enabled": false}}}\n'
            )
            temp_path = Path(f.name)

        try:
            decisions = parse_jsonl(temp_path)
            assert len(decisions) == 2
            assert decisions[0]["allowed"] is True
            assert decisions[1]["allowed"] is False
        finally:
            temp_path.unlink()

    def test_parse_jsonl_invalid_json(self):
        """Test parsing invalid JSON raises error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write('{"allowed": true}\n')
            f.write("invalid json\n")
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="Invalid JSON"):
                parse_jsonl(temp_path)
        finally:
            temp_path.unlink()

    def test_analyze_decisions_global_counts(self):
        """Test global counts computation."""
        decisions = [
            {
                "allowed": True,
                "metadata": {
                    "answer_policy": {
                        "enabled": True,
                        "policy_name": "kids",
                        "mode": "answer",
                        "p_correct": 0.95,
                        "threshold": 0.98,
                    }
                },
            },
            {
                "allowed": False,
                "metadata": {
                    "answer_policy": {
                        "enabled": True,
                        "policy_name": "kids",
                        "mode": "silence",
                        "p_correct": 0.85,
                        "threshold": 0.98,
                    }
                },
            },
            {
                "allowed": True,
                "metadata": {
                    "answer_policy": {
                        "enabled": False,
                        "policy_name": None,
                        "mode": None,
                        "p_correct": None,
                        "threshold": None,
                    }
                },
            },
            {
                "allowed": True,
                "metadata": {},  # Missing answer_policy
            },
        ]

        metrics = analyze_decisions(decisions)

        assert metrics["global"]["total"] == 4
        assert metrics["global"]["enabled"] == 2
        assert metrics["global"]["disabled"] == 1
        assert metrics["global"]["missing_metadata"] == 1

    def test_analyze_decisions_per_policy_stats(self):
        """Test per-policy statistics computation."""
        decisions = [
            {
                "allowed": True,
                "metadata": {
                    "answer_policy": {
                        "enabled": True,
                        "policy_name": "kids",
                        "mode": "answer",
                        "p_correct": 0.99,
                        "threshold": 0.98,
                    }
                },
            },
            {
                "allowed": False,
                "reason": "Epistemic gate: p_correct=0.85 < threshold=0.98",
                "metadata": {
                    "answer_policy": {
                        "enabled": True,
                        "policy_name": "kids",
                        "mode": "silence",
                        "p_correct": 0.85,
                        "threshold": 0.98,
                    }
                },
            },
            {
                "allowed": True,
                "metadata": {
                    "answer_policy": {
                        "enabled": True,
                        "policy_name": "default",
                        "mode": "answer",
                        "p_correct": 0.8,
                        "threshold": 0.75,
                    }
                },
            },
        ]

        metrics = analyze_decisions(decisions)

        # Kids policy
        kids_stats = metrics["policies"]["kids"]
        assert kids_stats["count"] == 2
        assert kids_stats["answer_count"] == 1
        assert kids_stats["silence_count"] == 1
        assert kids_stats["blocked_count"] == 1
        assert kids_stats["blocked_by_answer_policy"] == 1
        assert kids_stats["blocked_by_other"] == 0
        assert abs(kids_stats["p_correct_mean"] - 0.92) < 0.01  # (0.99 + 0.85) / 2

        # Default policy
        default_stats = metrics["policies"]["default"]
        assert default_stats["count"] == 1
        assert default_stats["answer_count"] == 1
        assert default_stats["silence_count"] == 0
        assert default_stats["blocked_count"] == 0

    def test_analyze_decisions_histogram(self):
        """Test histogram computation."""
        decisions = [
            {
                "allowed": True,
                "metadata": {
                    "answer_policy": {
                        "enabled": True,
                        "policy_name": "default",
                        "mode": "answer",
                        "p_correct": 0.1,  # [0.0-0.2]
                        "threshold": 0.75,
                    }
                },
            },
            {
                "allowed": False,
                "metadata": {
                    "answer_policy": {
                        "enabled": True,
                        "policy_name": "default",
                        "mode": "silence",
                        "p_correct": 0.3,  # (0.2-0.4]
                        "threshold": 0.75,
                    }
                },
            },
            {
                "allowed": True,
                "metadata": {
                    "answer_policy": {
                        "enabled": True,
                        "policy_name": "default",
                        "mode": "answer",
                        "p_correct": 0.9,  # (0.8-1.0]
                        "threshold": 0.75,
                    }
                },
            },
        ]

        metrics = analyze_decisions(decisions)

        histogram = metrics["histogram"]
        assert histogram["[0.0-0.2]"]["answer"] == 1
        assert histogram["(0.2-0.4]"]["silence"] == 1
        assert histogram["(0.8-1.0]"]["answer"] == 1

    def test_analyze_decisions_mixed_policies(self):
        """Test analysis with multiple policies."""
        decisions = [
            {
                "allowed": True,
                "metadata": {
                    "answer_policy": {
                        "enabled": True,
                        "policy_name": "kids",
                        "mode": "answer",
                        "p_correct": 0.99,
                        "threshold": 0.98,
                    }
                },
            },
            {
                "allowed": True,
                "metadata": {
                    "answer_policy": {
                        "enabled": True,
                        "policy_name": "default",
                        "mode": "answer",
                        "p_correct": 0.8,
                        "threshold": 0.75,
                    }
                },
            },
            {
                "allowed": True,
                "metadata": {
                    "answer_policy": {
                        "enabled": True,
                        "policy_name": "internal_debug",
                        "mode": "answer",
                        "p_correct": 0.5,
                        "threshold": 0.0,
                    }
                },
            },
        ]

        metrics = analyze_decisions(decisions)

        assert len(metrics["policies"]) == 3
        assert "kids" in metrics["policies"]
        assert "default" in metrics["policies"]
        assert "internal_debug" in metrics["policies"]

    def test_analyze_file_integration(self):
        """Test full file analysis integration."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            decisions = [
                {
                    "allowed": True,
                    "metadata": {
                        "answer_policy": {
                            "enabled": True,
                            "policy_name": "kids",
                            "mode": "answer",
                            "p_correct": 0.99,
                            "threshold": 0.98,
                        }
                    },
                },
                {
                    "allowed": False,
                    "reason": "Epistemic gate",
                    "metadata": {
                        "answer_policy": {
                            "enabled": True,
                            "policy_name": "kids",
                            "mode": "silence",
                            "p_correct": 0.85,
                            "threshold": 0.98,
                        }
                    },
                },
            ]

            for decision in decisions:
                f.write(json.dumps(decision) + "\n")
            temp_path = Path(f.name)

        try:
            metrics = analyze_file(temp_path)

            assert metrics["global"]["total"] == 2
            assert metrics["global"]["enabled"] == 2
            assert "kids" in metrics["policies"]
            assert metrics["policies"]["kids"]["count"] == 2
        finally:
            temp_path.unlink()
