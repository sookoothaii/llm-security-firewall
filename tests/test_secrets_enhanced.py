"""Tests for enhanced secrets heuristics (P0#3)."""

import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.gates.secrets_heuristics import analyze_secrets  # noqa: E402


def test_provider_patterns_enhanced():
    """Test enhanced provider-specific patterns."""
    # OpenAI variants
    text1 = "sk-proj-ABCDEF1234567890ABCDEF1234567890"
    result1 = analyze_secrets(text1)
    assert result1.patterns_matched > 0
    assert any("openai" in h.get("type", "") for h in result1.hits)

    # GitHub variants
    text2 = "gho_1234567890ABCDEF1234567890ABCDEF1234"
    result2 = analyze_secrets(text2)
    assert any("github" in h.get("type", "") for h in result2.hits)

    # HuggingFace
    text3 = "hf_ABCDEFGHIJ1234567890ABCDEFGHIJ1234567890"
    result3 = analyze_secrets(text3)
    assert any("huggingface" in h.get("type", "") for h in result3.hits)

    # AWS
    text4 = "AKIAIOSFODNN7EXAMPLE"
    result4 = analyze_secrets(text4)
    assert any("aws" in h.get("type", "") for h in result4.hits)

    # JWT
    text5 = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    result5 = analyze_secrets(text5)
    assert any("jwt" in h.get("type", "") for h in result5.hits)


def test_base32_base58_hex_detection():
    """Test Base32, Base58, and Hex high-entropy detection."""
    # Base32 (RFC 4648 - high entropy mix)
    text_b32 = "MFRGG3DFMZTWQ2LKNNWG23TPOA7A2KJ5MFRGG3DFMZTWQ2LK"  # High-entropy Base32
    result_b32 = analyze_secrets(text_b32)
    # Should detect via base32 pattern or high-entropy
    assert result_b32.patterns_matched > 0 or result_b32.high_entropy_spans > 0

    # Base58 (Bitcoin-style - actual high entropy)
    text_b58 = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss"
    result_b58 = analyze_secrets(text_b58)
    # Should match generic high-entropy or base58
    assert result_b58.patterns_matched > 0 or result_b58.high_entropy_spans > 0

    # Hex (long SHA-256 style)
    text_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    result_hex = analyze_secrets(text_hex)
    # Should match hex or high-entropy
    assert result_hex.patterns_matched > 0 or result_hex.high_entropy_spans > 0


def test_severity_scoring():
    """Test severity scores are properly bounded."""
    text = "-----BEGIN PRIVATE KEY----- and sk-ABCD1234567890 and password=test123"
    result = analyze_secrets(text)
    assert 0.0 <= result.severity <= 1.0
    # PEM should have high severity
    pem_hits = [h for h in result.hits if "pem" in h.get("type", "").lower()]
    if pem_hits:
        assert pem_hits[0]["severity"] >= 0.9


def test_empty_and_clean_text():
    """Test handling of empty and clean text."""
    result_empty = analyze_secrets("")
    assert result_empty.severity == 0.0
    assert len(result_empty.hits) == 0

    result_clean = analyze_secrets("Hello world, this is a clean message.")
    assert result_clean.severity <= 0.3  # Should be low or zero
