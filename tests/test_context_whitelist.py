"""Tests for context whitelist FP reduction."""
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.heuristics.context_whitelist import whitelist_decision  # noqa: E402


def test_uuid_benign_context_allowed():
    """Test UUID with benign context (adv_028)."""
    allow, why = whitelist_decision("uuid: 123e4567-e89b-12d3-a456-426614174000")
    assert allow is True
    assert "uuid_benign_context" in why


def test_git_hash_benign_context_allowed():
    """Test git hash with benign context (adv_029)."""
    allow, why = whitelist_decision("commit: 4a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b")
    assert allow is True
    assert "git_hash_benign_context" in why


def test_sha256_benign_context_allowed():
    """Test SHA256 with benign context (adv_030)."""
    h = "a" * 64
    allow, why = whitelist_decision(f"sha256={h}")
    assert allow is True
    assert "sha256_benign_context" in why


def test_no_benign_context_blocks():
    """Test that without benign context, no whitelist."""
    allow, _ = whitelist_decision("token: 4a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b")
    assert allow is False


def test_suspicious_context_overrides():
    """Test suspicious keywords override benign markers."""
    allow, _ = whitelist_decision("api_key commit: abc123def456")
    assert allow is False, "Suspicious context should override"

