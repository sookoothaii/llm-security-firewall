"""
Tests for Transparency Log Adapter
Creator: Joerg Bollwahn
Date: 2025-10-30

Note: These tests require PostgreSQL connection.
Set SKIP_DB_TESTS=1 to skip database-dependent tests.
"""

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from src.llm_firewall.adapters.write_log_adapter import (
    MerkleChainBuilder,
    TransparencyLogAdapter,
    WriteLogEntry,
)

# Skip DB tests if PostgreSQL not available or password not set
SKIP_DB = os.getenv("SKIP_DB_TESTS", "0") == "1" or not os.getenv("HAKGAL_DB_PASSWORD")

# Test connection params (adjust for your environment)
# Set HAKGAL_DB_PASSWORD env var or skip DB tests
TEST_DB_PARAMS = {
    "host": "127.0.0.1",
    "port": 5172,
    "database": "hakgal",
    "user": "hakgal",
    "password": os.getenv("HAKGAL_DB_PASSWORD", ""),
}


class TestWriteLogEntry:
    """Test WriteLogEntry validation."""

    def test_valid_entry(self):
        """Valid entry should not raise."""
        content_hash = b"\x00" * 32
        writer_id = uuid.uuid4()

        entry = WriteLogEntry(
            content_hash=content_hash,
            parent_hash=None,
            writer_instance_id=writer_id,
            source_trust=0.8,
        )
        assert entry.content_hash == content_hash
        assert entry.parent_hash is None

    def test_invalid_content_hash_length(self):
        """Content hash must be 32 bytes."""
        with pytest.raises(ValueError, match="32 bytes"):
            WriteLogEntry(
                content_hash=b"\x00" * 16,  # Wrong length
                parent_hash=None,
                writer_instance_id=uuid.uuid4(),
            )

    def test_invalid_parent_hash_length(self):
        """Parent hash must be None or 32 bytes."""
        with pytest.raises(ValueError, match="32 bytes"):
            WriteLogEntry(
                content_hash=b"\x00" * 32,
                parent_hash=b"\x00" * 16,  # Wrong length
                writer_instance_id=uuid.uuid4(),
            )

    def test_trust_out_of_range(self):
        """Trust must be in [0,1]."""
        with pytest.raises(ValueError, match="source_trust must be in"):
            WriteLogEntry(
                content_hash=b"\x00" * 32,
                parent_hash=None,
                writer_instance_id=uuid.uuid4(),
                source_trust=1.5,
            )


class TestMerkleChainBuilder:
    """Test Merkle chain building utilities."""

    def test_hash_content(self):
        """Test content hashing."""
        content = "test content"
        hash1 = MerkleChainBuilder.hash_content(content)
        hash2 = MerkleChainBuilder.hash_content(content)

        assert len(hash1) == 32
        assert hash1 == hash2  # Deterministic

    def test_hash_bytes(self):
        """Test bytes hashing."""
        data = b"test data"
        hash1 = MerkleChainBuilder.hash_bytes(data)
        hash2 = MerkleChainBuilder.hash_bytes(data)

        assert len(hash1) == 32
        assert hash1 == hash2

    def test_create_genesis_entry(self):
        """Test genesis entry creation."""
        writer_id = uuid.uuid4()
        entry = MerkleChainBuilder.create_genesis_entry(
            content="genesis content", writer_id=writer_id, source_trust=1.0
        )

        assert entry.parent_hash is None
        assert entry.writer_instance_id == writer_id
        assert entry.source_trust == 1.0
        assert len(entry.content_hash) == 32

    def test_create_chained_entry(self):
        """Test chained entry creation."""
        parent_hash = b"\x00" * 32
        writer_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        entry = MerkleChainBuilder.create_chained_entry(
            content="chained content",
            parent_hash=parent_hash,
            writer_id=writer_id,
            source_url="https://example.com",
            source_trust=0.8,
            ttl_expiry=now + timedelta(days=7),
        )

        assert entry.parent_hash == parent_hash
        assert entry.source_url == "https://example.com"
        assert entry.source_trust == 0.8
        assert entry.ttl_expiry is not None


@pytest.mark.skipif(SKIP_DB, reason="PostgreSQL not available")
class TestTransparencyLogAdapter:
    """Test TransparencyLogAdapter (requires PostgreSQL)."""

    @pytest.fixture
    def adapter(self):
        """Create adapter instance."""
        try:
            return TransparencyLogAdapter(TEST_DB_PARAMS)
        except Exception as e:
            pytest.skip(f"PostgreSQL not available: {e}")

    @pytest.fixture(autouse=True)
    def cleanup_test_data(self, adapter):
        """Clean up test data after each test."""
        yield
        # Note: evidence_write_log is append-only with delete trigger
        # In production, cleanup would be via archival, not deletion

    def test_append_write_genesis(self, adapter):
        """Test appending genesis entry."""
        writer_id = uuid.uuid4()
        entry = MerkleChainBuilder.create_genesis_entry(
            content=f"test genesis {uuid.uuid4()}",
            writer_id=writer_id,
            source_trust=1.0,
        )

        log_id = adapter.append_write(entry)
        assert log_id > 0

    def test_append_write_chained(self, adapter):
        """Test appending chained entry."""
        writer_id = uuid.uuid4()

        # Create genesis
        genesis = MerkleChainBuilder.create_genesis_entry(
            content=f"genesis {uuid.uuid4()}", writer_id=writer_id
        )
        adapter.append_write(genesis)

        # Create chained entry
        chained = MerkleChainBuilder.create_chained_entry(
            content=f"chained {uuid.uuid4()}",
            parent_hash=genesis.content_hash,
            writer_id=writer_id,
            source_trust=0.8,
        )
        log_id = adapter.append_write(chained)
        assert log_id > 0

    def test_append_duplicate_hash_raises(self, adapter):
        """Test that duplicate content hash raises."""
        writer_id = uuid.uuid4()
        content = f"unique content {uuid.uuid4()}"

        entry1 = MerkleChainBuilder.create_genesis_entry(
            content=content, writer_id=writer_id
        )
        adapter.append_write(entry1)

        # Try to append same content again
        entry2 = MerkleChainBuilder.create_genesis_entry(
            content=content, writer_id=writer_id
        )
        with pytest.raises(ValueError, match="already exists"):
            adapter.append_write(entry2)

    def test_get_latest_hash(self, adapter):
        """Test getting latest hash."""
        writer_id = uuid.uuid4()
        entry = MerkleChainBuilder.create_genesis_entry(
            content=f"latest test {uuid.uuid4()}", writer_id=writer_id
        )
        adapter.append_write(entry)

        latest = adapter.get_latest_hash()
        assert latest == entry.content_hash

    def test_get_chain_stats(self, adapter):
        """Test chain statistics."""
        stats = adapter.get_chain_stats()
        assert "total_entries" in stats
        assert "genesis_count" in stats
        assert "broken_links" in stats
        assert stats["total_entries"] >= 0

    def test_quarantine_workflow(self, adapter):
        """Test quarantine add/approve/reject workflow."""
        writer_id = uuid.uuid4()
        entry = MerkleChainBuilder.create_genesis_entry(
            content=f"quarantine test {uuid.uuid4()}", writer_id=writer_id
        )
        log_id = adapter.append_write(entry)

        # Add to quarantine
        q_id = adapter.add_to_quarantine(
            write_log_id=log_id,
            content_hash=entry.content_hash,
            reason="low_trust",
            metadata={"test": True},
        )
        assert q_id > 0

        # First judge approval
        result = adapter.approve_quarantine(q_id, judge_name="judge_1", is_second=False)
        assert result is True

        # Second judge approval
        result = adapter.approve_quarantine(q_id, judge_name="judge_2", is_second=True)
        assert result is True

    def test_quarantine_reject(self, adapter):
        """Test quarantine rejection."""
        writer_id = uuid.uuid4()
        entry = MerkleChainBuilder.create_genesis_entry(
            content=f"reject test {uuid.uuid4()}", writer_id=writer_id
        )
        log_id = adapter.append_write(entry)

        q_id = adapter.add_to_quarantine(
            write_log_id=log_id, content_hash=entry.content_hash, reason="test"
        )

        result = adapter.reject_quarantine(q_id, judge_name="judge_reject")
        assert result is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
