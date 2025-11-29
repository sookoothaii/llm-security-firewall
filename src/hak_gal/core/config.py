"""
HAK_GAL v2.3.1: Runtime Configuration (Kill-Switch) - SECURED

Runtime-configurable flags and thresholds for emergency bypass and tuning.
SECURITY: HMAC-SHA256 signature required for all config changes.

Creator: Joerg Bollwahn
License: MIT
"""

import os
import secrets
import hmac
import hashlib
import logging
import time
from typing import Any, Dict, Set
from threading import Lock
from collections import deque

from hak_gal.core.exceptions import SecurityException

logger = logging.getLogger(__name__)


class RuntimeConfig:
    """
    Singleton runtime configuration with kill-switch capabilities.

    Allows runtime changes to security layer flags and thresholds
    for emergency bypass and operational tuning.
    """

    _instance = None
    _lock = Lock()

    def __new__(cls):
        """Singleton pattern: only one instance exists."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(RuntimeConfig, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize configuration with default values."""
        if self._initialized:
            return

        # Flags (bool): Enable/disable security layers
        self.ENABLE_INBOUND_REGEX: bool = True
        self.ENABLE_INBOUND_VECTOR: bool = True
        self.ENABLE_OUTBOUND_TOOLS: bool = True

        # Thresholds (float): Tuning parameters
        self.DRIFT_THRESHOLD: float = 0.6  # Default: 0.6 (more sensitive than 0.7)

        # Security: Admin secret for HMAC signature
        admin_secret_env = os.getenv("HAKGAL_ADMIN_SECRET")
        if admin_secret_env:
            self._admin_secret = admin_secret_env.encode("utf-8")
            logger.info("RuntimeConfig: Admin secret loaded from HAKGAL_ADMIN_SECRET")
        else:
            # Fallback: Generate strong random secret (not persistent across restarts)
            self._admin_secret = secrets.token_bytes(32)
            logger.warning(
                "RuntimeConfig: No HAKGAL_ADMIN_SECRET found. Using random secret "
                "(not persistent, config updates will fail after restart)."
            )

        # Internal state
        self._config_lock = Lock()
        self._initialized = True

        # Replay protection: Nonce cache (thread-safe)
        self._seen_nonces: Set[str] = set()
        self._nonce_timestamps: deque = (
            deque()
        )  # (nonce, expiry_time) tuples for cleanup
        self._nonce_cleanup_interval = 60.0  # Cleanup nonces older than 60 seconds

        logger.info(
            "RuntimeConfig initialized with defaults (SECURED + REPLAY PROTECTION)"
        )

    def update_config(
        self, key: str, value: Any, signature: str, timestamp: int, nonce: str
    ) -> bool:
        """
        Update configuration value at runtime (kill-switch) - SECURED + REPLAY PROTECTION.

        SECURITY:
        - Requires HMAC-SHA256 signature to prevent unauthorized config changes
        - Timestamp validation (within 30 seconds) prevents old requests
        - Nonce validation prevents replay attacks

        Args:
            key: Configuration key (e.g., "ENABLE_INBOUND_VECTOR")
            value: New value (must match expected type)
            signature: HMAC-SHA256 signature of (key + value + timestamp + nonce) using admin_secret
            timestamp: Unix timestamp (seconds since epoch)
            nonce: Unique identifier (UUID string) to prevent replay attacks

        Returns:
            True if update successful, False if key not found or invalid value

        Raises:
            SecurityException: If signature invalid, timestamp expired, or replay detected
            ValueError: If value type doesn't match expected type
        """
        with self._config_lock:
            # SECURITY: Cleanup old nonces (prevent memory leak)
            self._cleanup_expired_nonces()

            # SECURITY: Timestamp validation (must be within 30 seconds)
            current_time = int(time.time())
            time_diff = abs(current_time - timestamp)
            if time_diff > 30:
                logger.error(
                    f"SECURITY: Config update rejected - timestamp expired. "
                    f"Current: {current_time}, Request: {timestamp}, Diff: {time_diff}s"
                )
                raise SecurityException(
                    message="Request expired",
                    code="CONFIG_TIMESTAMP_EXPIRED",
                    metadata={
                        "key": key,
                        "timestamp": timestamp,
                        "current_time": current_time,
                    },
                )

            # SECURITY: Nonce validation (prevent replay attacks)
            if nonce in self._seen_nonces:
                logger.error(
                    f"SECURITY: Replay attack detected - nonce already used. "
                    f"Key: {key}, Nonce: {nonce}"
                )
                raise SecurityException(
                    message="Replay detected",
                    code="CONFIG_REPLAY_ATTACK",
                    metadata={"key": key, "nonce": nonce},
                )

            # SECURITY: Verify HMAC signature (includes timestamp and nonce)
            expected_signature = self._compute_signature(key, value, timestamp, nonce)
            if not hmac.compare_digest(signature, expected_signature):
                logger.error(
                    f"SECURITY: Unauthorized config change attempt for key={key}, "
                    f"signature mismatch"
                )
                raise SecurityException(
                    message="Unauthorized config change attempt",
                    code="CONFIG_EXPLOIT_BLOCKED",
                    metadata={"key": key},
                )

            # Mark nonce as seen (store with expiry time for cleanup)
            self._seen_nonces.add(nonce)
            expiry_time = current_time + self._nonce_cleanup_interval
            self._nonce_timestamps.append((nonce, expiry_time))

            if not hasattr(self, key):
                logger.warning(f"Unknown config key: {key}")
                return False

            # Type validation
            current_value = getattr(self, key)
            if not isinstance(value, type(current_value)):
                raise ValueError(
                    f"Type mismatch for {key}: expected {type(current_value).__name__}, "
                    f"got {type(value).__name__}"
                )

            # Update value
            old_value = current_value
            setattr(self, key, value)

            logger.warning(
                f"RuntimeConfig updated (SIGNED): {key} = {old_value} -> {value} "
                f"(KILL-SWITCH: {'ENABLED' if not value and 'ENABLE' in key else 'NORMAL'})"
            )

            return True

    def _cleanup_expired_nonces(self) -> None:
        """Cleanup expired nonces from cache (prevent memory leak)."""
        current_time = int(time.time())
        while self._nonce_timestamps:
            nonce, expiry_time = self._nonce_timestamps[0]
            if expiry_time > current_time:
                # All remaining nonces are still valid
                break
            # Remove expired nonce
            self._nonce_timestamps.popleft()
            self._seen_nonces.discard(nonce)

    def _compute_signature(
        self, key: str, value: Any, timestamp: int, nonce: str
    ) -> str:
        """
        Compute HMAC-SHA256 signature for config update (with replay protection).

        Args:
            key: Configuration key
            value: Configuration value
            timestamp: Unix timestamp
            nonce: Unique nonce

        Returns:
            Hexadecimal signature string
        """
        # Signature = HMAC_SHA256(key + value + timestamp + nonce, admin_secret)
        data = f"{key}{str(value)}{timestamp}{nonce}".encode("utf-8")
        mac = hmac.new(self._admin_secret, data, hashlib.sha256)
        return mac.hexdigest()

    def get_signature(self, key: str, value: Any, timestamp: int, nonce: str) -> str:
        """
        Get signature for a config update (for authorized clients).

        Args:
            key: Configuration key
            value: Configuration value
            timestamp: Unix timestamp (seconds since epoch)
            nonce: Unique nonce (UUID string)

        Returns:
            Hexadecimal signature string
        """
        return self._compute_signature(key, value, timestamp, nonce)

    def get_config(self, key: str) -> Any:
        """
        Get configuration value.

        Args:
            key: Configuration key

        Returns:
            Configuration value or None if key not found
        """
        return getattr(self, key, None)

    def get_all_config(self) -> Dict[str, Any]:
        """
        Get all configuration values.

        Returns:
            Dictionary of all config key-value pairs
        """
        return {
            "ENABLE_INBOUND_REGEX": self.ENABLE_INBOUND_REGEX,
            "ENABLE_INBOUND_VECTOR": self.ENABLE_INBOUND_VECTOR,
            "ENABLE_OUTBOUND_TOOLS": self.ENABLE_OUTBOUND_TOOLS,
            "DRIFT_THRESHOLD": self.DRIFT_THRESHOLD,
        }

    def reset_to_defaults(self) -> None:
        """Reset all configuration to default values."""
        with self._config_lock:
            self.ENABLE_INBOUND_REGEX = True
            self.ENABLE_INBOUND_VECTOR = True
            self.ENABLE_OUTBOUND_TOOLS = True
            self.DRIFT_THRESHOLD = 0.6

            logger.info("RuntimeConfig reset to defaults")
