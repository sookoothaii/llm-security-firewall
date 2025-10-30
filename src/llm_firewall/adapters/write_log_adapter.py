"""
Transparency Log Adapter - Infrastructure Layer
Purpose: PostgreSQL adapter for write-path logging with Merkle chain
Creator: Joerg Bollwahn
Date: 2025-10-30

Hexagonal Architecture: Adapter implements port for domain logic.
"""

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

try:
    import pg8000.native
except ImportError:
    pg8000 = None  # type: ignore


@dataclass
class WriteLogEntry:
    """
    Write log entry for transparency log.

    Attributes:
        content_hash: SHA-256 hash of content (bytes)
        parent_hash: Previous Merkle node hash (None for genesis)
        writer_instance_id: UUID of writer instance
        source_url: Source URL (None for internal)
        source_trust: Trust score [0,1]
        ttl_expiry: TTL expiry datetime (None = no expiry)
        signature: Writer signature (placeholder, bytes)
        metadata: JSONB metadata dict
    """

    content_hash: bytes
    parent_hash: Optional[bytes]
    writer_instance_id: uuid.UUID
    source_url: Optional[str] = None
    source_trust: float = 0.0
    ttl_expiry: Optional[datetime] = None
    signature: Optional[bytes] = None
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        """Validate entry."""
        if not isinstance(self.content_hash, bytes) or len(self.content_hash) != 32:
            raise ValueError("content_hash must be 32 bytes (SHA-256)")
        if self.parent_hash is not None and (
            not isinstance(self.parent_hash, bytes) or len(self.parent_hash) != 32
        ):
            raise ValueError("parent_hash must be None or 32 bytes (SHA-256)")
        if not 0 <= self.source_trust <= 1:
            raise ValueError("source_trust must be in [0,1]")


class TransparencyLogAdapter:
    """
    PostgreSQL adapter for transparency log operations.

    Implements append-only Merkle log with:
    - SHA-256 content hashing
    - Parent-hash chain linkage
    - Immutability enforcement (triggers)
    - Merkle root tracking
    """

    def __init__(self, connection_params: Dict[str, Any]):
        """
        Initialize adapter.

        Args:
            connection_params: PostgreSQL connection params
                {host, port, database, user, password}
        """
        if pg8000 is None:
            raise ImportError("pg8000 not available - install via: pip install pg8000")

        self.connection_params = connection_params

    def _get_connection(self) -> Any:  # type: ignore[misc]
        """Get database connection."""
        return pg8000.native.Connection(**self.connection_params)

    def append_write(self, entry: WriteLogEntry) -> int:
        """
        Append write to transparency log.

        Args:
            entry: Write log entry

        Returns:
            Log entry ID (BIGINT)

        Raises:
            ValueError: If content hash already exists
            RuntimeError: On database error
        """
        conn = self._get_connection()
        try:
            result = conn.run(
                """
                INSERT INTO evidence_write_log (
                    writer_instance_id,
                    content_hash,
                    parent_hash,
                    source_url,
                    source_trust,
                    ttl_expiry,
                    signature,
                    meta
                )
                VALUES (
                    :writer_id, :content_hash, :parent_hash, :source_url,
                    :trust, :ttl, :sig, :meta::jsonb
                )
                RETURNING id
                """,
                writer_id=entry.writer_instance_id,
                content_hash=entry.content_hash,
                parent_hash=entry.parent_hash,
                source_url=entry.source_url,
                trust=entry.source_trust,
                ttl=entry.ttl_expiry,
                sig=entry.signature,
                meta=entry.metadata or {},
            )
            return result[0][0]  # Return ID
        except Exception as e:
            if "unique_content_hash" in str(e):
                raise ValueError(
                    f"Content hash already exists: {entry.content_hash.hex()}"
                )
            raise RuntimeError(f"Failed to append write: {e}")
        finally:
            conn.close()

    def get_latest_hash(self) -> Optional[bytes]:
        """
        Get latest content hash in chain.

        Returns:
            Latest content_hash (bytes) or None if empty
        """
        conn = self._get_connection()
        try:
            result = conn.run(
                """
                SELECT content_hash
                FROM evidence_write_log
                ORDER BY id DESC
                LIMIT 1
                """
            )
            return result[0][0] if result else None
        finally:
            conn.close()

    def verify_chain_integrity(self, start_id: int, end_id: int) -> bool:
        """
        Verify Merkle chain integrity between two IDs.

        Args:
            start_id: Starting log ID
            end_id: Ending log ID

        Returns:
            True if chain is valid (each parent_hash matches previous content_hash)
        """
        conn = self._get_connection()
        try:
            result = conn.run(
                """
                SELECT id, content_hash, parent_hash
                FROM evidence_write_log
                WHERE id >= :start_id AND id <= :end_id
                ORDER BY id ASC
                """,
                start_id=start_id,
                end_id=end_id,
            )

            if not result:
                return True  # Empty range is valid

            # Check chain linkage
            for i in range(1, len(result)):
                prev_content_hash = result[i - 1][1]
                current_parent_hash = result[i][2]

                if current_parent_hash != prev_content_hash:
                    return False

            return True
        finally:
            conn.close()

    def get_chain_stats(self) -> Dict[str, int]:
        """
        Get transparency log statistics.

        Returns:
            dict with total_entries, genesis_count, broken_links
        """
        conn = self._get_connection()
        try:
            total = conn.run("SELECT COUNT(*) FROM evidence_write_log")[0][0]
            genesis = conn.run(
                "SELECT COUNT(*) FROM evidence_write_log WHERE parent_hash IS NULL"
            )[0][0]

            # Check for broken links (parent_hash not matching any content_hash)
            broken = conn.run(
                """
                SELECT COUNT(*)
                FROM evidence_write_log w
                WHERE w.parent_hash IS NOT NULL
                  AND NOT EXISTS (
                    SELECT 1 FROM evidence_write_log p
                    WHERE p.content_hash = w.parent_hash
                  )
                """
            )[0][0]

            return {
                "total_entries": total,
                "genesis_count": genesis,
                "broken_links": broken,
            }
        finally:
            conn.close()

    def add_to_quarantine(
        self,
        write_log_id: int,
        content_hash: bytes,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        """
        Add entry to quarantine queue.

        Args:
            write_log_id: Reference to write log entry
            content_hash: Content hash (32 bytes)
            reason: Quarantine reason
            metadata: Additional metadata

        Returns:
            Quarantine entry ID
        """
        conn = self._get_connection()
        try:
            result = conn.run(
                """
                INSERT INTO evidence_quarantine (
                    write_log_id, content_hash, reason, meta
                )
                VALUES (:log_id, :hash, :reason, :meta::jsonb)
                RETURNING id
                """,
                log_id=write_log_id,
                hash=content_hash,
                reason=reason,
                meta=metadata or {},
            )
            return result[0][0]
        finally:
            conn.close()

    def approve_quarantine(
        self, quarantine_id: int, judge_name: str, is_second: bool = False
    ) -> bool:
        """
        Approve quarantine entry (first or second judge).

        Args:
            quarantine_id: Quarantine entry ID
            judge_name: Name/ID of approving judge
            is_second: True if second judge approval

        Returns:
            True if approved, False if not found/already approved
        """
        conn = self._get_connection()
        try:
            if is_second:
                # Second approval - set status to approved
                result = conn.run(
                    """
                    UPDATE evidence_quarantine
                    SET second_judge = :judge, status = 'approved'
                    WHERE id = :qid AND first_judge IS NOT NULL AND second_judge IS NULL
                    RETURNING id
                    """,
                    judge=judge_name,
                    qid=quarantine_id,
                )
            else:
                # First approval
                result = conn.run(
                    """
                    UPDATE evidence_quarantine
                    SET first_judge = :judge
                    WHERE id = :qid AND first_judge IS NULL
                    RETURNING id
                    """,
                    judge=judge_name,
                    qid=quarantine_id,
                )
            return len(result) > 0
        finally:
            conn.close()

    def reject_quarantine(self, quarantine_id: int, judge_name: str) -> bool:
        """
        Reject quarantine entry.

        Args:
            quarantine_id: Quarantine entry ID
            judge_name: Name/ID of rejecting judge

        Returns:
            True if rejected, False if not found
        """
        conn = self._get_connection()
        try:
            result = conn.run(
                """
                UPDATE evidence_quarantine
                SET status = 'rejected', first_judge = :judge
                WHERE id = :qid AND status = 'pending'
                RETURNING id
                """,
                judge=judge_name,
                qid=quarantine_id,
            )
            return len(result) > 0
        finally:
            conn.close()


class MerkleChainBuilder:
    """
    Merkle chain builder for content hashing.

    Pure utility class - no database operations.
    """

    @staticmethod
    def hash_content(content: str) -> bytes:
        """
        Compute SHA-256 hash of content.

        Args:
            content: Content string

        Returns:
            32-byte SHA-256 hash
        """
        return hashlib.sha256(content.encode("utf-8")).digest()

    @staticmethod
    def hash_bytes(data: bytes) -> bytes:
        """
        Compute SHA-256 hash of bytes.

        Args:
            data: Raw bytes

        Returns:
            32-byte SHA-256 hash
        """
        return hashlib.sha256(data).digest()

    @staticmethod
    def create_genesis_entry(
        content: str,
        writer_id: uuid.UUID,
        source_trust: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> WriteLogEntry:
        """
        Create genesis entry (no parent).

        Args:
            content: Content to hash
            writer_id: Writer instance UUID
            source_trust: Trust score
            metadata: Additional metadata

        Returns:
            WriteLogEntry with parent_hash=None
        """
        return WriteLogEntry(
            content_hash=MerkleChainBuilder.hash_content(content),
            parent_hash=None,
            writer_instance_id=writer_id,
            source_trust=source_trust,
            metadata=metadata,
        )

    @staticmethod
    def create_chained_entry(
        content: str,
        parent_hash: bytes,
        writer_id: uuid.UUID,
        source_url: Optional[str] = None,
        source_trust: float = 0.7,
        ttl_expiry: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> WriteLogEntry:
        """
        Create chained entry (with parent).

        Args:
            content: Content to hash
            parent_hash: Previous content hash (32 bytes)
            writer_id: Writer instance UUID
            source_url: Source URL
            source_trust: Trust score
            ttl_expiry: TTL expiry datetime
            metadata: Additional metadata

        Returns:
            WriteLogEntry with parent_hash set
        """
        return WriteLogEntry(
            content_hash=MerkleChainBuilder.hash_content(content),
            parent_hash=parent_hash,
            writer_instance_id=writer_id,
            source_url=source_url,
            source_trust=source_trust,
            ttl_expiry=ttl_expiry,
            metadata=metadata,
        )
