"""
HAK_GAL v2.2-ALPHA: Cryptographic Utilities

HMAC computation and PII redaction for privacy-first logging.

Creator: Joerg Bollwahn
License: MIT
"""

import hmac
import hashlib
import os
import re
import logging
from typing import Optional, Dict

from hak_gal.core.exceptions import SystemError

logger = logging.getLogger(__name__)

# Privacy-first: Only log raw payloads if LOG_LEVEL=FORENSIC
FORENSIC_LOGGING = os.getenv("LOG_LEVEL", "").upper() == "FORENSIC"


def compute_hmac(data: bytes, secret: bytes) -> str:
    """
    Compute HMAC-SHA256 of data.

    Args:
        data: Data to hash
        secret: Secret key

    Returns:
        Hexadecimal HMAC string

    Raises:
        SystemError: If HMAC computation fails (fail-closed)
    """
    try:
        mac = hmac.new(secret, data, hashlib.sha256)
        return mac.hexdigest()
    except Exception as e:
        logger.error(f"HMAC computation failed: {e}")
        raise SystemError(
            f"HMAC computation failed: {e}",
            component="crypto",
        ) from e


def redact_pii(text: str, redaction_char: str = "*") -> str:
    """
    Redact PII (Personally Identifiable Information) from text.

    Privacy-first: Only log redacted text unless LOG_LEVEL=FORENSIC.

    Redacts:
    - Email addresses
    - Phone numbers
    - Credit card numbers
    - IP addresses
    - Social security numbers (US format)

    Args:
        text: Input text
        redaction_char: Character to use for redaction

    Returns:
        Redacted text (or original if FORENSIC_LOGGING is enabled)
    """
    if FORENSIC_LOGGING:
        return text

    # Email addresses
    text = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        lambda m: redaction_char * len(m.group()),
        text,
    )

    # Phone numbers (US format: (XXX) XXX-XXXX or XXX-XXX-XXXX)
    text = re.sub(
        r"\b(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
        lambda m: redaction_char * len(m.group()),
        text,
    )

    # Credit card numbers (16 digits, may have spaces/dashes)
    text = re.sub(
        r"\b\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b",
        lambda m: redaction_char * len(m.group()),
        text,
    )

    # IP addresses
    text = re.sub(
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        lambda m: redaction_char * len(m.group()),
        text,
    )

    # Social security numbers (US format: XXX-XX-XXXX)
    text = re.sub(
        r"\b\d{3}-\d{2}-\d{4}\b",
        lambda m: redaction_char * len(m.group()),
        text,
    )

    return text


class CryptoUtils:
    """
    Cryptographic utilities for session management.

    Features:
    - Daily salt rotation (based on current date)
    - HMAC-SHA256 hashing for session IDs
    - Privacy-first: Never stores raw IDs
    """

    def __init__(self, secret_key: Optional[bytes] = None):
        """
        Initialize CryptoUtils.

        Args:
            secret_key: Secret key for HMAC (default: random, not persistent)
        """
        if secret_key is None:
            import secrets

            secret_key = secrets.token_bytes(32)
            logger.warning(
                "No secret key provided. Using random key (not persistent across restarts)."
            )

        self.secret_key = secret_key
        self._daily_salt_cache: Dict[str, str] = {}  # date_str -> salt

    def get_daily_salt(self, date_str: Optional[str] = None) -> str:
        """
        Get or generate daily salt based on date.

        Salt rotates daily to ensure session IDs change each day
        (privacy: same user gets different hash on different days).

        Args:
            date_str: Optional date string (YYYY-MM-DD). If None, uses today.

        Returns:
            Daily salt string (hexadecimal)
        """
        if date_str is None:
            from datetime import date

            date_str = date.today().isoformat()

        # Check cache
        if date_str in self._daily_salt_cache:
            return self._daily_salt_cache[date_str]

        # Generate salt: HMAC(date_str, secret_key)
        salt_bytes = hmac.new(
            self.secret_key, date_str.encode("utf-8"), hashlib.sha256
        ).digest()
        salt_hex = salt_bytes.hex()

        self._daily_salt_cache[date_str] = salt_hex
        logger.debug(f"Generated daily salt for {date_str}")

        return salt_hex

    def hash_session_id(self, user_id: str, tenant_id: str) -> str:
        """
        Hash session ID using HMAC-SHA256 with daily salt.

        CRITICAL FIX (v2.3.2): Tenant isolation to prevent tenant bleeding.
        Signature MUST include tenant_id to ensure proper isolation.

        Important: Never stores raw_id. Only returns hash.

        Args:
            user_id: Raw user/session identifier (e.g., "user_123")
            tenant_id: Tenant identifier (e.g., "tenant_abc") - REQUIRED

        Returns:
            Hashed session ID (hexadecimal)

        Raises:
            ValueError: If tenant_id is missing or empty (fail-closed)
            SystemError: If hashing fails (fail-closed)
        """
        # CRITICAL: Validate tenant_id (prevent tenant bleeding)
        if not tenant_id or not tenant_id.strip():
            raise ValueError(
                "tenant_id is required for session ID hashing (v2.3.2: Tenant Bleeding Fix)"
            )

        try:
            # Get daily salt
            salt = self.get_daily_salt()

            # Compute HMAC: HMAC(tenant_id:user_id + salt, secret_key)
            # Order: tenant_id first to ensure tenant isolation
            data = f"{tenant_id}:{user_id}:{salt}".encode("utf-8")
            hashed = hmac.new(self.secret_key, data, hashlib.sha256)

            return hashed.hexdigest()
        except ValueError:
            # Re-raise ValueError (tenant_id validation)
            raise
        except Exception as e:
            logger.error(f"Session ID hashing failed: {e}")
            raise SystemError(
                f"Session ID hashing failed: {e}",
                component="CryptoUtils",
            ) from e
