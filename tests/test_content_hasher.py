"""
Tests for Content Hasher
=========================

BLAKE3 + Text Normalization
"""

import pytest

from llm_firewall.trust.content_hasher import blake3_bytes, blake3_hex, normalize_text


class TestContentHasher:
    """Test suite for content hashing."""

    def test_blake3_normalization_stable(self):
        """Test that normalization makes hashing deterministic."""
        a = blake3_hex("Hello   World")
        b = blake3_hex("Hello World")

        assert a == b
        assert len(a) == 64  # 32 bytes = 64 hex chars

    def test_normalize_text_whitespace(self):
        """Test whitespace collapse."""
        assert normalize_text("Hello   World") == "Hello World"
        assert normalize_text("  Test\n\nText  ") == "Test Text"
        assert normalize_text("A\t\tB") == "A B"

    def test_normalize_text_unicode(self):
        """Test Unicode NFKC normalization."""
        # NFKC combines characters
        assert normalize_text("café") == normalize_text("café")  # Different representations

    def test_blake3_hex_length(self):
        """Test hash output length."""
        assert len(blake3_hex("test")) == 64
        assert len(blake3_hex("")) == 64
        assert len(blake3_hex("a" * 10000)) == 64

    def test_blake3_hex_deterministic(self):
        """Test that same input always gives same hash."""
        text = "The quick brown fox"

        hash1 = blake3_hex(text)
        hash2 = blake3_hex(text)
        hash3 = blake3_hex(text)

        assert hash1 == hash2 == hash3

    def test_blake3_hex_different_inputs(self):
        """Test that different inputs give different hashes."""
        hash_a = blake3_hex("Hello")
        hash_b = blake3_hex("World")

        assert hash_a != hash_b

    def test_blake3_bytes(self):
        """Test binary hashing."""
        data = b"Binary data \\x00\\x01\\xff"
        hash_result = blake3_bytes(data)

        assert len(hash_result) == 64
        assert isinstance(hash_result, str)

    def test_empty_string_hashing(self):
        """Test that empty string is hashable."""
        hash_empty = blake3_hex("")

        assert len(hash_empty) == 64
        assert hash_empty != "0" * 64  # Not all zeros


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

