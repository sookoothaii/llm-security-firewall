"""Tests for policy decode budgets and auto-strict guard."""
from types import SimpleNamespace

from llm_firewall.policy_config import from_hydra


def test_decode_budgets_loaded():
    """Test decode budget limits are loaded from config."""
    cfg = SimpleNamespace(
        llm_firewall=SimpleNamespace(
            policy={
                "mode": "permissive",
                "max_inflate_bytes": 32768,
                "max_zip_files": 3,
                "max_zip_read_bytes": 16384,
                "max_png_chunks": 4,
            }
        )
    )
    policy = from_hydra(cfg)
    assert policy.max_inflate_bytes == 32768
    assert policy.max_zip_files == 3
    assert policy.max_zip_read_bytes == 16384
    assert policy.max_png_chunks == 4


def test_auto_strict_config_loaded():
    """Test auto-strict guard configuration."""
    cfg = SimpleNamespace(
        llm_firewall=SimpleNamespace(
            policy={
                "mode": "permissive",
                "auto_strict_enabled": True,
                "auto_strict_alarm_threshold": 5,
                "auto_strict_window_seconds": 600,
                "auto_strict_duration_seconds": 300,
            }
        )
    )
    policy = from_hydra(cfg)
    assert policy.auto_strict_enabled is True
    assert policy.auto_strict_alarm_threshold == 5
    assert policy.auto_strict_window_seconds == 600
    assert policy.auto_strict_duration_seconds == 300


def test_policy_defaults():
    """Test default policy values."""
    policy = from_hydra(None)
    assert policy.max_inflate_bytes == 65536  # 64 KB
    assert policy.max_zip_files == 5
    assert policy.max_zip_read_bytes == 32768  # 32 KB
    assert policy.max_png_chunks == 8
    assert policy.auto_strict_enabled is True
    assert policy.auto_strict_alarm_threshold == 3
    assert policy.auto_strict_window_seconds == 300  # 5 min
    assert policy.auto_strict_duration_seconds == 300  # 5 min

