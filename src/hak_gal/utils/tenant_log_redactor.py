"""
HAK_GAL v2.3.3: Per-Tenant Log Redaction

CRITICAL FIX (P2): GDPR-compliant log encryption.
Prevents log leakage of personally identifiable information (PII).

Architecture:
- Per-tenant Data Encryption Keys (DEK) from KMS/Vault
- AES-GCM encryption for sensitive fields
- Only tenant admin can decrypt logs

Creator: Joerg Bollwahn
Date: 2025-01-15
Status: P2 Implementation (v2.3.3)
License: MIT
"""

import logging
import base64
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

logger = logging.getLogger(__name__)


class TenantLogRedactor:
    """
    Per-Tenant Log Redaction with Field-Level Encryption.

    CRITICAL FIX (P2): GDPR Art. 32 compliance.

    Security Property:
    - Sensitive fields (user_hash, drift_score) are AES-GCM encrypted
    - Only tenant admin (with KMS access) can decrypt
    - SOC sees only encrypted blobs
    """

    # Fields that must be encrypted (PII)
    SENSITIVE_FIELDS = [
        "user_hash",
        "user_id",
        "drift_score",
        "risk_score",
        "session_id",
        "embedding_vector",
    ]

    def __init__(self, dek_fetcher=None):
        """
        Initialize Tenant Log Redactor.

        Args:
            dek_fetcher: Callable(tenant_id) -> bytes (Data Encryption Key from KMS/Vault)
                        If None, uses in-memory keys (NOT for production)
        """
        self.dek_fetcher = dek_fetcher
        self._key_cache: Dict[str, bytes] = {}

    async def _get_tenant_dek(self, tenant_id: str) -> bytes:
        """
        Get Data Encryption Key (DEK) for tenant.

        CRITICAL: In production, this MUST fetch from KMS/Vault.

        Args:
            tenant_id: Tenant identifier

        Returns:
            DEK as bytes (32 bytes for AES-256)

        Raises:
            SystemError: If key fetch fails
        """
        # Check cache
        if tenant_id in self._key_cache:
            return self._key_cache[tenant_id]

        # Fetch from KMS/Vault
        if self.dek_fetcher:
            try:
                dek = await self.dek_fetcher(tenant_id)
                if len(dek) != 32:
                    raise ValueError(f"DEK must be 32 bytes, got {len(dek)}")
                self._key_cache[tenant_id] = dek
                return dek
            except Exception as e:
                logger.error(
                    f"TenantLogRedactor: Failed to fetch DEK for tenant {tenant_id}: {e}"
                )
                raise SystemError(
                    f"Failed to fetch DEK for tenant {tenant_id}: {e}",
                    component="TenantLogRedactor",
                ) from e

        # Development fallback (NOT for production)
        logger.warning(
            f"TenantLogRedactor: Using in-memory DEK for tenant {tenant_id}. "
            "This is NOT secure for production. Configure dek_fetcher."
        )
        # Generate deterministic key from tenant_id (for testing only)
        from hashlib import sha256

        dek = sha256(f"tenant_{tenant_id}_dek".encode()).digest()
        self._key_cache[tenant_id] = dek
        return dek

    def _encrypt(self, dek: bytes, plaintext: str) -> str:
        """
        Encrypt plaintext using AES-GCM.

        Args:
            dek: Data Encryption Key (32 bytes)
            plaintext: Plaintext string to encrypt

        Returns:
            Base64-encoded ciphertext with nonce prepended
        """
        # Generate random nonce (12 bytes for GCM)
        nonce = secrets.token_bytes(12)

        # Encrypt
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

        # Prepend nonce and encode
        encrypted = nonce + ciphertext
        return base64.b64encode(encrypted).decode("utf-8")

    def _decrypt(self, dek: bytes, ciphertext_b64: str) -> str:
        """
        Decrypt ciphertext using AES-GCM.

        Args:
            dek: Data Encryption Key (32 bytes)
            ciphertext_b64: Base64-encoded ciphertext with nonce prepended

        Returns:
            Decrypted plaintext string
        """
        # Decode
        encrypted = base64.b64decode(ciphertext_b64.encode("utf-8"))

        # Extract nonce (first 12 bytes)
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]

        # Decrypt
        aesgcm = AESGCM(dek)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")

    async def redact(self, tenant_id: str, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact sensitive fields in log entry.

        CRITICAL: Encrypts PII fields (user_hash, drift_score, etc.)
        tenant_id remains in plaintext for routing.

        Args:
            tenant_id: Tenant identifier
            log_entry: Log entry dictionary

        Returns:
            Redacted log entry with encrypted sensitive fields
        """
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required (P2: Log Redaction)")

        # Get DEK for tenant
        dek = await self._get_tenant_dek(tenant_id)

        # Create redacted copy
        redacted = log_entry.copy()

        # Encrypt sensitive fields
        for field in self.SENSITIVE_FIELDS:
            if field in redacted and redacted[field] is not None:
                # Convert to string if needed
                value_str = str(redacted[field])
                # Encrypt
                redacted[field] = self._encrypt(dek, value_str)
                # Mark as encrypted
                redacted[f"{field}_encrypted"] = True

        # tenant_id remains in plaintext (needed for routing)
        redacted["tenant_id"] = tenant_id

        logger.debug(f"TenantLogRedactor: Redacted log entry for tenant {tenant_id}")

        return redacted

    async def decrypt(
        self, tenant_id: str, encrypted_log_entry: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Decrypt redacted log entry (for tenant admin only).

        Args:
            tenant_id: Tenant identifier
            encrypted_log_entry: Encrypted log entry

        Returns:
            Decrypted log entry with plaintext sensitive fields
        """
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required")

        # Get DEK for tenant
        dek = await self._get_tenant_dek(tenant_id)

        # Create decrypted copy
        decrypted = encrypted_log_entry.copy()

        # Decrypt sensitive fields
        for field in self.SENSITIVE_FIELDS:
            encrypted_field = f"{field}_encrypted"
            if field in decrypted and decrypted.get(encrypted_field, False):
                try:
                    decrypted[field] = self._decrypt(dek, decrypted[field])
                    del decrypted[encrypted_field]
                except Exception as e:
                    logger.warning(
                        f"TenantLogRedactor: Failed to decrypt {field} for tenant {tenant_id}: {e}"
                    )
                    decrypted[field] = "[DECRYPTION_FAILED]"

        return decrypted
