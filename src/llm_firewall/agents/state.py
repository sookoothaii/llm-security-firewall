"""
Campaign State Store
====================

Abstraction for storing campaign event history.

Supports in-memory (testing) and persistent (Redis/DB) backends.
"""

from abc import ABC, abstractmethod
from typing import List, Dict

from llm_firewall.detectors.tool_killchain import ToolEvent


class CampaignStateStore(ABC):
    """
    Abstract interface for campaign state storage.

    Implementations should persist event history per session
    to enable High-Watermark logic across multiple agent turns.
    """

    @abstractmethod
    def add_event(self, session_id: str, event: ToolEvent) -> None:
        """
        Add an event to the campaign history.

        Args:
            session_id: Session identifier
            event: Tool event to add
        """
        pass

    @abstractmethod
    def get_events(self, session_id: str) -> List[ToolEvent]:
        """
        Get all events for a session.

        Args:
            session_id: Session identifier

        Returns:
            List of tool events (chronological order)
        """
        pass

    @abstractmethod
    def clear_session(self, session_id: str) -> None:
        """
        Clear all events for a session.

        Args:
            session_id: Session identifier
        """
        pass


class InMemoryStateStore(CampaignStateStore):
    """
    Simple in-memory implementation for testing/single-instance deployments.

    For production: Use RedisStateStore or DatabaseStateStore.
    """

    def __init__(self):
        """Initialize in-memory store."""
        self._store: Dict[str, List[ToolEvent]] = {}

    def add_event(self, session_id: str, event: ToolEvent) -> None:
        """Add event to in-memory store."""
        if session_id not in self._store:
            self._store[session_id] = []
        self._store[session_id].append(event)

    def get_events(self, session_id: str) -> List[ToolEvent]:
        """Get events from in-memory store."""
        return self._store.get(session_id, []).copy()

    def clear_session(self, session_id: str) -> None:
        """Clear session from in-memory store."""
        if session_id in self._store:
            del self._store[session_id]
