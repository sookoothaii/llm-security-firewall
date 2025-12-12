"""
HAK_GAL v2.5.1: Session Manager with Redis Backend

Unified state management for Inbound (Trajectory) and Outbound (ToolGuard) layers.
Privacy-first: Only stores hashed session IDs, never raw user IDs.

v2.5.1 Changes:
- Added Redis backend support for distributed deployments
- Automatic fallback to in-memory if Redis unavailable
- TTL-based session expiration (default: 3600s)
- Thread-safe operations

Creator: Joerg Bollwahn
License: MIT
"""

import logging
import os
import json
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime

from pydantic import BaseModel, Field

from hak_gal.utils.crypto import CryptoUtils

logger = logging.getLogger(__name__)

# Try to import redis (optional dependency)
try:
    import redis

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None  # type: ignore


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
    - Redis backend (optional): Persistent storage with TTL for distributed deployments
    - In-Memory fallback: Dictionary mapping hashed_id -> SessionState if Redis unavailable
    - Unified state: Trajectory (Inbound) and Context (Outbound) share same session

    Features:
    - get_or_create_session(): Transparent hashing of raw_user_id
    - update_context(): Update ToolGuard state
    - add_vector(): Update Trajectory state
    - Redis persistence with automatic TTL expiration
    - Thread-safe operations (for in-memory fallback)

    Environment Variables:
        REDIS_URL: Redis connection URL (e.g., redis://localhost:6379/0)
        REDIS_HOST: Redis host (default: 127.0.0.1)
        REDIS_PORT: Redis port (default: 6379)
        REDIS_PASSWORD: Redis password (optional)
        REDIS_DB: Redis database number (default: 0)
        REDIS_SESSION_TTL: Session TTL in seconds (default: 3600)
    """

    def __init__(
        self,
        crypto_utils: Optional[CryptoUtils] = None,
        use_redis: Optional[bool] = None,
    ):
        """
        Initialize Session Manager with optional Redis backend.

        Args:
            crypto_utils: CryptoUtils instance (default: creates new)
            use_redis: Force Redis usage (True) or in-memory (False).
                      If None, auto-detect from REDIS_URL environment variable.
        """
        self.crypto = crypto_utils or CryptoUtils()
        self._sessions: Dict[
            str, SessionState
        ] = {}  # Fallback: hashed_id -> SessionState
        self._lock = threading.Lock()  # Thread safety for in-memory fallback

        # Session TTL (default: 1 hour)
        self.session_ttl = int(os.getenv("REDIS_SESSION_TTL", 3600))

        # Redis configuration
        self.use_redis = False
        self.redis_client = None

        # Auto-detect Redis if not explicitly disabled
        if use_redis is False:
            logger.info(
                "SessionManager: Redis explicitly disabled, using in-memory storage"
            )
            return

        if not HAS_REDIS:
            logger.warning(
                "SessionManager: redis package not installed. "
                "Install with: pip install redis>=5.0.0. "
                "Falling back to in-memory storage."
            )
            return

        # Try to connect to Redis
        try:
            redis_url = os.getenv("REDIS_URL")
            if redis_url:
                # Parse Redis URL
                self.redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                )
            else:
                # Use individual environment variables
                redis_host = os.getenv("REDIS_HOST", "127.0.0.1")
                redis_port = int(os.getenv("REDIS_PORT", 6379))
                redis_password = os.getenv("REDIS_PASSWORD", None)
                redis_db = int(os.getenv("REDIS_DB", 0))

                self.redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    password=redis_password if redis_password else None,
                    db=redis_db,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                )

            # Test connection
            self.redis_client.ping()
            self.use_redis = True
            logger.info(
                f"SessionManager: Redis connection established (TTL: {self.session_ttl}s)"
            )

        except (redis.ConnectionError, redis.TimeoutError, Exception) as e:
            logger.warning(
                f"SessionManager: Redis connection failed: {e}. "
                "Falling back to in-memory storage (sessions not persistent across restarts)."
            )
            self.redis_client = None
            self.use_redis = False

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
        if self.use_redis and self.redis_client:
            # Redis backend
            redis_key = f"session:{hashed_id}"
            data = self.redis_client.get(redis_key)

            if data:
                # Deserialize from JSON
                session_dict = json.loads(data)
                session = SessionState(**session_dict)
                # Refresh TTL on access
                self.redis_client.setex(
                    redis_key, self.session_ttl, json.dumps(session.model_dump())
                )
            else:
                # Create new session
                session = SessionState()
                self.redis_client.setex(
                    redis_key, self.session_ttl, json.dumps(session.model_dump())
                )
                logger.debug(
                    f"Created new session in Redis for hashed_id: {hashed_id[:16]}... "
                    "(raw_id never stored)"
                )
        else:
            # In-memory fallback
            with self._lock:
                if hashed_id not in self._sessions:
                    session = SessionState()
                    self._sessions[hashed_id] = session
                    logger.debug(
                        f"Created new session in-memory for hashed_id: {hashed_id[:16]}... "
                        "(raw_id never stored)"
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

        # Persist to Redis if using Redis backend
        if self.use_redis and self.redis_client:
            hashed_id = self.crypto.hash_session_id(raw_user_id, tenant_id)
            redis_key = f"session:{hashed_id}"
            self.redis_client.setex(
                redis_key, self.session_ttl, json.dumps(session.model_dump())
            )

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

        # Persist to Redis if using Redis backend
        if self.use_redis and self.redis_client:
            hashed_id = self.crypto.hash_session_id(raw_user_id, tenant_id)
            redis_key = f"session:{hashed_id}"
            self.redis_client.setex(
                redis_key, self.session_ttl, json.dumps(session.model_dump())
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

        if self.use_redis and self.redis_client:
            redis_key = f"session:{hashed_id}"
            data = self.redis_client.get(redis_key)
            if data:
                session_dict = json.loads(data)
                session = SessionState(**session_dict)
                return session.context_data.copy()
            return {}
        else:
            with self._lock:
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

        if self.use_redis and self.redis_client:
            redis_key = f"session:{hashed_id}"
            data = self.redis_client.get(redis_key)
            if data:
                session_dict = json.loads(data)
                session = SessionState(**session_dict)
                return session.trajectory_buffer.copy()
            return []
        else:
            with self._lock:
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

        if self.use_redis and self.redis_client:
            redis_key = f"session:{hashed_id}"
            data = self.redis_client.get(redis_key)
            if data:
                session_dict = json.loads(data)
                return SessionState(**session_dict)
            return None
        else:
            with self._lock:
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

        if self.use_redis and self.redis_client:
            redis_key = f"session:{hashed_id}"
            deleted = self.redis_client.delete(redis_key) > 0
            if deleted:
                logger.debug(
                    f"Cleared session in Redis for hashed_id: {hashed_id[:16]}..."
                )
            return deleted
        else:
            with self._lock:
                if hashed_id in self._sessions:
                    del self._sessions[hashed_id]
                    logger.debug(
                        f"Cleared session in-memory for hashed_id: {hashed_id[:16]}..."
                    )
                    return True
                return False

    def list_sessions(self) -> int:
        """
        Get number of active sessions.

        Returns:
            Number of active sessions
        """
        if self.use_redis and self.redis_client:
            try:
                # Count all session keys
                count = len(list(self.redis_client.scan_iter("session:*")))
                return count
            except Exception as e:
                logger.warning(f"Failed to count Redis sessions: {e}")
                return 0
        else:
            with self._lock:
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
        if self.use_redis and self.redis_client:
            redis_key = f"session:{session_id}"
            data = self.redis_client.get(redis_key)
            if not data:
                return None
            session_dict = json.loads(data)
            session = SessionState(**session_dict)
        else:
            with self._lock:
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
        if self.use_redis and self.redis_client:
            redis_key = f"session:{session_id}"
            data = self.redis_client.get(redis_key)

            if data:
                session_dict = json.loads(data)
                session = SessionState(**session_dict)
            else:
                session = SessionState()

            session.trajectory_buffer.append(vector)
            self.redis_client.setex(
                redis_key, self.session_ttl, json.dumps(session.model_dump())
            )
            logger.debug(
                f"Added vector to trajectory in Redis (buffer size: {len(session.trajectory_buffer)})"
            )
        else:
            with self._lock:
                if session_id not in self._sessions:
                    # Create new session if doesn't exist
                    self._sessions[session_id] = SessionState()

                session = self._sessions[session_id]
                session.trajectory_buffer.append(vector)
                logger.debug(
                    f"Added vector to trajectory in-memory (buffer size: {len(session.trajectory_buffer)})"
                )
