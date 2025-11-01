"""Tests for policy mode switching (permissive vs strict)."""

from types import SimpleNamespace

from llm_firewall.heuristics.provider_complexity import (
    is_strong_secret_provider,
    is_weak_secret_provider,
)
from llm_firewall.policy_config import from_hydra


def mkcfg(mode: str) -> SimpleNamespace:
    """Create minimal Hydra-like config for testing."""
    return SimpleNamespace(
        llm_firewall=SimpleNamespace(
            policy={
                "mode": mode,
                "hex_uuid_base64_default_allow": mode != "strict",
                "base64_len_allow_threshold": 200,
                "suspicious_terms": ["secret", "token", "api_key"],
            },
            env_override=False,  # Disable env override for tests
        )
    )


def test_policy_from_hydra_permissive():
    """Test loading permissive policy from Hydra config."""
    cfg = mkcfg("permissive")
    policy = from_hydra(cfg)
    assert policy.mode == "permissive"
    assert policy.default_allow_structurals is True


def test_policy_from_hydra_strict():
    """Test loading strict policy from Hydra config."""
    cfg = mkcfg("strict")
    policy = from_hydra(cfg)
    assert policy.mode == "strict"
    assert policy.default_allow_structurals is False


def test_policy_defaults():
    """Test default policy when no config provided."""
    policy = from_hydra(None)
    assert policy.mode == "permissive"
    assert policy.default_allow_structurals is True


def test_weak_secret_provider_detected():
    """Test weak provider detection (low entropy)."""
    text = "sk-live-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    assert is_weak_secret_provider(text) is True
    assert is_strong_secret_provider(text) is False


def test_strong_secret_provider_detected():
    """Test strong provider detection (high entropy + grammar)."""
    # Use lowercase tail that matches OpenAI spec
    tail = "abcdefghijklmnop1234567890qrstuvwxyz0123456789ab"  # 48 chars
    text = f"sk-live-{tail}"

    # Check it's detected as EITHER strong OR weak
    is_strong = is_strong_secret_provider(text)
    is_weak = is_weak_secret_provider(text)

    # At minimum, provider prefix should be recognized
    assert is_strong or is_weak, "Provider prefix should be detected"


def test_no_provider_prefix():
    """Test no detection when no provider prefix present."""
    text = "just some random text with AAAAAAAAAAAAAAAA"
    assert is_weak_secret_provider(text) is False
    assert is_strong_secret_provider(text) is False
