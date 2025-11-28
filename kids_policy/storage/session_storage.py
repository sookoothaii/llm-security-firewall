#!/usr/bin/env python3
"""
Session Storage Interface and Implementations
==============================================
Storage backends for Layer 4 session context (in-memory, Redis, etc.)

Author: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-28
Status: Layer 4 Implementation
"""

import time
import threading
from abc import ABC, abstractmethod
from typing import Optional
from ..session_context import SessionContext


class SessionStorage(ABC):
    """Abstract interface for session storage backends"""

    @abstractmethod
    def load_session(self, user_id: str) -> Optional[SessionContext]:
        """Load session context for user"""
        pass

    @abstractmethod
    def save_session(self, user_id: str, session: SessionContext):
        """Save session context for user"""
        pass

    @abstractmethod
    def delete_session(self, user_id: str):
        """Delete session context for user"""
        pass

    @abstractmethod
    def cleanup_expired_sessions(self, ttl_seconds: int = 86400):
        """Clean up sessions older than TTL (default: 24 hours)"""
        pass


class InMemorySessionStorage(SessionStorage):
    """In-memory session storage (thread-safe)"""

    def __init__(self):
        self._sessions: dict[str, SessionContext] = {}
        self._lock = threading.RLock()

    def load_session(self, user_id: str) -> Optional[SessionContext]:
        """Load session context for user"""
        with self._lock:
            session = self._sessions.get(user_id)
            if session:
                # Check if session expired (24 hours TTL)
                age = time.time() - session.last_activity
                if age > 86400:  # 24 hours
                    del self._sessions[user_id]
                    return None
            return session

    def save_session(self, user_id: str, session: SessionContext):
        """Save session context for user"""
        with self._lock:
            self._sessions[user_id] = session

    def delete_session(self, user_id: str):
        """Delete session context for user"""
        with self._lock:
            if user_id in self._sessions:
                del self._sessions[user_id]

    def cleanup_expired_sessions(self, ttl_seconds: int = 86400):
        """Clean up sessions older than TTL"""
        current_time = time.time()
        with self._lock:
            expired_keys = [
                user_id
                for user_id, session in self._sessions.items()
                if (current_time - session.last_activity) > ttl_seconds
            ]
            for user_id in expired_keys:
                del self._sessions[user_id]

        return len(expired_keys)
