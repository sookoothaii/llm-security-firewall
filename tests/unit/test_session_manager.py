"""
HAK_GAL v2.2-ALPHA: Unit Tests for Session & Crypto Management

Tests privacy-first session management with daily salt rotation.

Creator: Joerg Bollwahn
License: MIT
"""

import pytest
from datetime import date, datetime
from unittest.mock import patch

from hak_gal.utils.crypto import CryptoUtils
from hak_gal.core.session_manager import SessionManager, SessionState


class TestCryptoUtils:
    """Test CryptoUtils daily salt and session ID hashing."""

    def test_get_daily_salt_same_date(self):
        """Test that same date returns same salt."""
        crypto = CryptoUtils(secret_key=b"test_secret_key_32_bytes_long!")
        salt1 = crypto.get_daily_salt("2025-01-15")
        salt2 = crypto.get_daily_salt("2025-01-15")

        assert salt1 == salt2
        assert len(salt1) == 64  # SHA256 hex = 64 chars

    def test_get_daily_salt_different_dates(self):
        """Test that different dates return different salts."""
        crypto = CryptoUtils(secret_key=b"test_secret_key_32_bytes_long!")
        salt1 = crypto.get_daily_salt("2025-01-15")
        salt2 = crypto.get_daily_salt("2025-01-16")

        assert salt1 != salt2

    def test_get_daily_salt_today(self):
        """Test get_daily_salt() without date parameter uses today."""
        crypto = CryptoUtils(secret_key=b"test_secret_key_32_bytes_long!")
        salt1 = crypto.get_daily_salt()
        salt2 = crypto.get_daily_salt(date.today().isoformat())

        assert salt1 == salt2

    def test_hash_session_id_same_user_same_day(self):
        """Test that same user on same day gets same hash."""
        crypto = CryptoUtils(secret_key=b"test_secret_key_32_bytes_long!")

        with patch.object(crypto, "get_daily_salt", return_value="fixed_salt_for_test"):
            hash1 = crypto.hash_session_id("user_123")
            hash2 = crypto.hash_session_id("user_123")

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex = 64 chars

    def test_hash_session_id_different_users(self):
        """Test that different users get different hashes."""
        crypto = CryptoUtils(secret_key=b"test_secret_key_32_bytes_long!")

        with patch.object(crypto, "get_daily_salt", return_value="fixed_salt_for_test"):
            hash1 = crypto.hash_session_id("user_123")
            hash2 = crypto.hash_session_id("user_456")

        assert hash1 != hash2

    def test_hash_session_id_salt_rotation(self):
        """Test that salt rotation changes hash for same user."""
        crypto = CryptoUtils(secret_key=b"test_secret_key_32_bytes_long!")

        # Same user, different dates (salt rotation)
        with patch.object(crypto, "get_daily_salt", return_value="salt_day1"):
            hash_day1 = crypto.hash_session_id("user_123")

        with patch.object(crypto, "get_daily_salt", return_value="salt_day2"):
            hash_day2 = crypto.hash_session_id("user_123")

        # Different salts should produce different hashes
        assert hash_day1 != hash_day2

    def test_hash_session_id_no_raw_storage(self):
        """Test that raw IDs are never stored (privacy check)."""
        crypto = CryptoUtils(secret_key=b"test_secret_key_32_bytes_long!")

        # Hash should not contain raw ID
        raw_id = "user_123"
        hashed = crypto.hash_session_id(raw_id)

        # Hash should not be equal to raw ID
        assert hashed != raw_id
        # Hash should not contain raw ID as substring
        assert raw_id not in hashed


class TestSessionManager:
    """Test SessionManager unified state management."""

    @pytest.fixture
    def crypto(self):
        """Create CryptoUtils instance with fixed secret."""
        return CryptoUtils(secret_key=b"test_secret_key_32_bytes_long!")

    @pytest.fixture
    def manager(self, crypto):
        """Create SessionManager instance."""
        return SessionManager(crypto_utils=crypto)

    def test_get_or_create_session_creates_new(self, manager):
        """Test that get_or_create_session creates new session."""
        session = manager.get_or_create_session("user_123")

        assert isinstance(session, SessionState)
        assert session.trajectory_buffer == []
        assert session.context_data == {}
        assert isinstance(session.created_at, datetime)

    def test_get_or_create_session_returns_existing(self, manager):
        """Test that get_or_create_session returns existing session."""
        session1 = manager.get_or_create_session("user_123")
        session2 = manager.get_or_create_session("user_123")

        # Should be same object (same hashed_id)
        assert session1 is session2

    def test_same_user_same_day_same_session(self, manager):
        """Test that same user on same day gets same session."""
        # Mock same date for both calls
        with patch.object(manager.crypto, "get_daily_salt", return_value="fixed_salt"):
            session1 = manager.get_or_create_session("user_123")
            session2 = manager.get_or_create_session("user_123")

        assert session1 is session2

    def test_salt_rotation_creates_new_session(self, manager):
        """Test that salt rotation (date change) creates new session."""
        # Day 1
        with patch.object(manager.crypto, "get_daily_salt", return_value="salt_day1"):
            session_day1 = manager.get_or_create_session("user_123")
            session_day1.context_data["test"] = "day1"

        # Day 2 (salt rotation)
        with patch.object(manager.crypto, "get_daily_salt", return_value="salt_day2"):
            session_day2 = manager.get_or_create_session("user_123")

        # Different hashes -> different sessions
        assert session_day1 is not session_day2
        # Day 2 session should be empty (new session)
        assert "test" not in session_day2.context_data

    def test_update_context(self, manager):
        """Test update_context stores data."""
        manager.update_context("user_123", "tx_count_1h", 42)

        context = manager.get_context("user_123")
        assert context["tx_count_1h"] == 42

    def test_update_context_persists(self, manager):
        """Test that context data persists across calls."""
        manager.update_context("user_123", "tx_count_1h", 10)
        manager.update_context("user_123", "tx_count_1h", 20)

        context = manager.get_context("user_123")
        assert context["tx_count_1h"] == 20  # Last update wins

    def test_add_vector(self, manager):
        """Test add_vector stores embedding."""
        vector = [0.1, 0.2, 0.3, 0.4, 0.5]
        manager.add_vector("user_123", vector)

        buffer = manager.get_trajectory_buffer("user_123")
        assert len(buffer) == 1
        assert buffer[0] == vector

    def test_add_vector_multiple(self, manager):
        """Test adding multiple vectors."""
        vectors = [
            [0.1, 0.2, 0.3],
            [0.4, 0.5, 0.6],
            [0.7, 0.8, 0.9],
        ]

        for vec in vectors:
            manager.add_vector("user_123", vec)

        buffer = manager.get_trajectory_buffer("user_123")
        assert len(buffer) == 3
        assert buffer == vectors

    def test_unified_state_trajectory_and_context(self, manager):
        """Test that trajectory and context share same session."""
        # Add vector (Inbound layer)
        manager.add_vector("user_123", [0.1, 0.2, 0.3])

        # Update context (Outbound layer)
        manager.update_context("user_123", "tx_count_1h", 50)

        # Both should be in same session
        session = manager.get_session("user_123")
        assert session is not None
        assert len(session.trajectory_buffer) == 1
        assert session.context_data["tx_count_1h"] == 50

    def test_get_context_nonexistent_session(self, manager):
        """Test get_context returns empty dict for nonexistent session."""
        context = manager.get_context("nonexistent_user")

        assert context == {}

    def test_get_trajectory_buffer_nonexistent_session(self, manager):
        """Test get_trajectory_buffer returns empty list for nonexistent session."""
        buffer = manager.get_trajectory_buffer("nonexistent_user")

        assert buffer == []

    def test_clear_session(self, manager):
        """Test clear_session removes session."""
        manager.get_or_create_session("user_123")
        assert manager.list_sessions() == 1

        removed = manager.clear_session("user_123")
        assert removed is True
        assert manager.list_sessions() == 0

        # Session should be gone
        session = manager.get_session("user_123")
        assert session is None

    def test_clear_nonexistent_session(self, manager):
        """Test clear_session returns False for nonexistent session."""
        removed = manager.clear_session("nonexistent_user")
        assert removed is False

    def test_list_sessions(self, manager):
        """Test list_sessions returns correct count."""
        assert manager.list_sessions() == 0

        manager.get_or_create_session("user_1")
        assert manager.list_sessions() == 1

        manager.get_or_create_session("user_2")
        assert manager.list_sessions() == 2

        # Same user again should not increase count
        manager.get_or_create_session("user_1")
        assert manager.list_sessions() == 2

    def test_privacy_no_raw_id_storage(self, manager):
        """Test that raw user IDs are never stored (privacy check)."""
        manager.get_or_create_session("user_123")
        manager.update_context("user_123", "test", "value")

        # Check that _sessions only contains hashed IDs
        for hashed_id in manager._sessions.keys():
            # Hashed ID should not contain raw ID
            assert "user_123" not in hashed_id
            # Hashed ID should be hex (64 chars for SHA256)
            assert len(hashed_id) == 64
            assert all(c in "0123456789abcdef" for c in hashed_id)
