"""
HAK_GAL v2.2-ALPHA: Session Manager

Unified state management for Inbound (Trajectory) and Outbound (ToolGuard) layers.
Privacy-first: Only stores hashed session IDs, never raw user IDs.

Creator: Joerg Bollwahn
License: MIT
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from pydantic import BaseModel, Field

from hak_gal.utils.crypto import CryptoUtils

logger = logging.getLogger(__name__)


class SessionState(BaseModel):
    """
    Session state model (Pydantic).

    Holds trajectory vectors (for Inbound) and context data (for Outbound ToolGuard).
    """

    trajectory_buffer: List[List[float]] = Field(
        default_factory=list, description="Embedding vectors for SessionTrajectory"
    )
    context_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Context data for ToolGuard (e.g., tx_count_1h)",
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow, description="Session creation timestamp"
    )

    class Config:
        """Pydantic config."""

        json_encoders = {datetime: lambda v: v.isoformat()}


class SessionManager:
    """
    Unified session manager for Inbound and Outbound layers.

    Architecture:
    - Privacy-first: Only stores hashed session IDs (via CryptoUtils)
    - In-Memory storage: Dictionary mapping hashed_id -> SessionState
    - Unified state: Trajectory (Inbound) and Context (Outbound) share same session

    Features:
    - get_or_create_session(): Transparent hashing of raw_user_id
    - update_context(): Update ToolGuard state
    - add_vector(): Update Trajectory state
    """

    def __init__(self, crypto_utils: Optional[CryptoUtils] = None):
        """
        Initialize Session Manager.

        Args:
            crypto_utils: CryptoUtils instance (default: creates new)
        """
        self.crypto = crypto_utils or CryptoUtils()
        self._sessions: Dict[str, SessionState] = {}  # hashed_id -> SessionState

    def get_or_create_session(
        self, raw_user_id: str, tenant_id: str = "default"
    ) -> SessionState:
        """
        Get or create session for user (handles hashing transparently).

        CRITICAL FIX (v2.3.2): tenant_id required for tenant isolation.

        Same user_id + tenant_id on same day -> same hash -> same session.
        Different day -> different hash -> new session (salt rotation).

        Args:
            raw_user_id: Raw user identifier (e.g., "user_123")
            tenant_id: Tenant identifier (default: "default" for backward compatibility)

        Returns:
            SessionState instance

        Raises:
            SystemError: If hashing fails (fail-closed)
            ValueError: If tenant_id is missing (fail-closed)
        """
        # CRITICAL FIX (v2.3.2): tenant_id required
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required (v2.3.2: Tenant Bleeding Fix)")

        # Hash user ID with tenant_id (privacy: never store raw_id)
        hashed_id = self.crypto.hash_session_id(raw_user_id, tenant_id)

        # Get or create session
        if hashed_id not in self._sessions:
            session = SessionState()
            self._sessions[hashed_id] = session
            logger.debug(
                f"Created new session for hashed_id: {hashed_id[:16]}... (raw_id never stored)"
            )
        else:
            session = self._sessions[hashed_id]

        return session

    def update_context(
        self, raw_user_id: str, key: str, value: Any, tenant_id: str = "default"
    ) -> None:
        """
        Update context data for ToolGuard (e.g., transaction counts).

        CRITICAL FIX (v2.3.2): tenant_id required for tenant isolation.

        Args:
            raw_user_id: Raw user identifier
            key: Context key (e.g., "tx_count_1h")
            value: Context value
            tenant_id: Tenant identifier (default: "default" for backward compatibility)

        Raises:
            SystemError: If session creation fails
            ValueError: If tenant_id is missing (fail-closed)
        """
        session = self.get_or_create_session(raw_user_id, tenant_id)
        session.context_data[key] = value
        logger.debug(f"Updated context: {key} = {value}")

    def add_vector(
        self, raw_user_id: str, vector: List[float], tenant_id: str = "default"
    ) -> None:
        """
        Add embedding vector to trajectory buffer (for SessionTrajectory).

        CRITICAL FIX (v2.3.2): tenant_id required for tenant isolation.

        Args:
            raw_user_id: Raw user identifier
            vector: Embedding vector (list of floats)
            tenant_id: Tenant identifier (default: "default" for backward compatibility)

        Raises:
            SystemError: If session creation fails
            ValueError: If tenant_id is missing (fail-closed)
        """
        session = self.get_or_create_session(raw_user_id, tenant_id)
        session.trajectory_buffer.append(vector)
        logger.debug(
            f"Added vector to trajectory (buffer size: {len(session.trajectory_buffer)})"
        )

    def get_context(
        self, raw_user_id: str, tenant_id: str = "default"
    ) -> Dict[str, Any]:
        """
        Get context data for ToolGuard.

        CRITICAL FIX (v2.3.2): tenant_id required for tenant isolation.

        Args:
            raw_user_id: Raw user identifier
            tenant_id: Tenant identifier (default: "default" for backward compatibility)

        Returns:
            Context data dictionary (empty if session doesn't exist)

        Raises:
            ValueError: If tenant_id is missing (fail-closed)
        """
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required (v2.3.2: Tenant Bleeding Fix)")

        hashed_id = self.crypto.hash_session_id(raw_user_id, tenant_id)
        session = self._sessions.get(hashed_id)
        if session is None:
            return {}
        return session.context_data.copy()

    def get_trajectory_buffer(
        self, raw_user_id: str, tenant_id: str = "default"
    ) -> List[List[float]]:
        """
        Get trajectory buffer for SessionTrajectory.

        CRITICAL FIX (v2.3.2): tenant_id required for tenant isolation.

        Args:
            raw_user_id: Raw user identifier
            tenant_id: Tenant identifier (default: "default" for backward compatibility)

        Returns:
            List of embedding vectors (empty if session doesn't exist)

        Raises:
            ValueError: If tenant_id is missing (fail-closed)
        """
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required (v2.3.2: Tenant Bleeding Fix)")

        hashed_id = self.crypto.hash_session_id(raw_user_id, tenant_id)
        session = self._sessions.get(hashed_id)
        if session is None:
            return []
        return session.trajectory_buffer.copy()

    def get_session(
        self, raw_user_id: str, tenant_id: str = "default"
    ) -> Optional[SessionState]:
        """
        Get session state (if exists).

        CRITICAL FIX (v2.3.2): tenant_id required for tenant isolation.

        Args:
            raw_user_id: Raw user identifier
            tenant_id: Tenant identifier (default: "default" for backward compatibility)

        Returns:
            SessionState or None if not found

        Raises:
            ValueError: If tenant_id is missing (fail-closed)
        """
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required (v2.3.2: Tenant Bleeding Fix)")

        hashed_id = self.crypto.hash_session_id(raw_user_id, tenant_id)
        return self._sessions.get(hashed_id)

    def clear_session(self, raw_user_id: str, tenant_id: str = "default") -> bool:
        """
        Clear session (remove from storage).

        CRITICAL FIX (v2.3.2): tenant_id required for tenant isolation.

        Args:
            raw_user_id: Raw user identifier
            tenant_id: Tenant identifier (default: "default" for backward compatibility)

        Returns:
            True if session was found and removed

        Raises:
            ValueError: If tenant_id is missing (fail-closed)
        """
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required (v2.3.2: Tenant Bleeding Fix)")

        hashed_id = self.crypto.hash_session_id(raw_user_id, tenant_id)
        if hashed_id in self._sessions:
            del self._sessions[hashed_id]
            logger.debug(f"Cleared session for hashed_id: {hashed_id[:16]}...")
            return True
        return False

    def list_sessions(self) -> int:
        """
        Get number of active sessions.

        Returns:
            Number of active sessions
        """
        return len(self._sessions)

    async def get_session_centroid(self, session_id: str) -> Optional[List[float]]:
        """
        Get session centroid for SemanticVectorCheck (async compatibility).

        Note: session_id is already hashed (includes tenant_id in hash).
        This method is for backward compatibility with SemanticVectorCheck.

        Args:
            session_id: Hashed session identifier

        Returns:
            Centroid vector (list of floats) or None if session doesn't exist
        """
        session = self._sessions.get(session_id)
        if session is None or not session.trajectory_buffer:
            return None

        # Calculate mean of trajectory buffer (simple centroid)
        import numpy as np

        vectors = np.array(session.trajectory_buffer, dtype=np.float32)
        centroid = np.mean(vectors, axis=0)
        return centroid.tolist()

    async def add_trajectory_vector(self, session_id: str, vector: List[float]) -> None:
        """
        Add trajectory vector to session (async compatibility).

        Note: session_id is already hashed (includes tenant_id in hash).
        This method is for backward compatibility with SemanticVectorCheck.

        Args:
            session_id: Hashed session identifier
            vector: Embedding vector (list of floats)
        """
        if session_id not in self._sessions:
            # Create new session if doesn't exist
            self._sessions[session_id] = SessionState()

        session = self._sessions[session_id]
        session.trajectory_buffer.append(vector)
        logger.debug(
            f"Added vector to trajectory (buffer size: {len(session.trajectory_buffer)})"
        )
