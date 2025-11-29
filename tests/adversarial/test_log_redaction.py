"""
HAK_GAL v2.3.3: Log Redaction Tests

CRITICAL TEST (P2): Proves GDPR-compliant log encryption.

Creator: Joerg Bollwahn
Date: 2025-01-15
Status: P2 Test Suite (v2.3.3)
License: MIT
"""

import pytest
from hak_gal.utils.tenant_log_redactor import TenantLogRedactor


@pytest.mark.asyncio
async def test_log_redaction_encryption():
    """
    CRITICAL TEST: Sensitive fields are encrypted in logs.

    This test proves that PII fields are encrypted and cannot be read without tenant key.
    """
    # Create redactor (using in-memory keys for testing)
    redactor = TenantLogRedactor(dek_fetcher=None)

    # Original log entry with sensitive data
    original_log = {
        "user_hash": "abc123def456",
        "drift_score": 0.75,
        "risk_score": 0.9,
        "tenant_id": "tenant_alpha",
        "message": "Security event detected",
    }

    # Redact (encrypt sensitive fields)
    redacted = await redactor.redact("tenant_alpha", original_log)

    # Verify sensitive fields are encrypted
    assert redacted["user_hash"] != original_log["user_hash"], (
        "user_hash should be encrypted"
    )
    assert redacted["drift_score"] != str(original_log["drift_score"]), (
        "drift_score should be encrypted"
    )
    assert redacted["risk_score"] != str(original_log["risk_score"]), (
        "risk_score should be encrypted"
    )

    # Verify tenant_id remains in plaintext (needed for routing)
    assert redacted["tenant_id"] == "tenant_alpha", (
        "tenant_id should remain in plaintext"
    )

    # Verify encrypted fields are base64-encoded (format check)
    import base64

    try:
        base64.b64decode(redacted["user_hash"])
        base64.b64decode(redacted["drift_score"])
    except Exception:
        pytest.fail("Encrypted fields should be base64-encoded")

    print("\n[SUCCESS] Log redaction encryption test passed!")
    print("  Sensitive fields are encrypted")
    print("  tenant_id remains in plaintext (for routing)")


@pytest.mark.asyncio
async def test_log_redaction_decryption():
    """
    CRITICAL TEST: Tenant admin can decrypt logs with correct key.

    This test proves that decryption works correctly with tenant key.
    """
    redactor = TenantLogRedactor(dek_fetcher=None)

    # Original log entry
    original_log = {
        "user_hash": "abc123def456",
        "drift_score": 0.75,
        "tenant_id": "tenant_alpha",
        "message": "Security event",
    }

    # Redact (encrypt)
    redacted = await redactor.redact("tenant_alpha", original_log)

    # Decrypt (with correct tenant key)
    decrypted = await redactor.decrypt("tenant_alpha", redacted)

    # Verify decrypted values match original
    assert decrypted["user_hash"] == original_log["user_hash"], (
        "Decryption failed for user_hash"
    )
    assert float(decrypted["drift_score"]) == original_log["drift_score"], (
        "Decryption failed for drift_score"
    )

    print("\n[SUCCESS] Log redaction decryption test passed!")
    print("  Tenant admin can decrypt logs with correct key")


@pytest.mark.asyncio
async def test_log_redaction_cross_tenant_isolation():
    """
    CRITICAL TEST: Tenant A cannot decrypt Tenant B's logs.

    This test proves that each tenant has its own encryption key.
    """
    redactor = TenantLogRedactor(dek_fetcher=None)

    # Encrypt log for Tenant A
    original_log = {
        "user_hash": "tenant_a_secret",
        "tenant_id": "tenant_alpha",
    }

    redacted_a = await redactor.redact("tenant_alpha", original_log)

    # Attempt to decrypt with Tenant B's key (should fail or produce garbage)
    try:
        decrypted_with_b_key = await redactor.decrypt("tenant_beta", redacted_a)

        # If decryption "succeeds" but produces wrong data, that's also a failure
        if decrypted_with_b_key.get("user_hash") == original_log["user_hash"]:
            pytest.fail("Tenant B should NOT be able to decrypt Tenant A's logs")
        else:
            # Decryption produced garbage (expected)
            assert decrypted_with_b_key.get("user_hash") != original_log["user_hash"]
            print("\n[SUCCESS] Cross-tenant isolation test passed!")
            print("  Tenant B cannot decrypt Tenant A's logs (produces garbage)")
    except Exception as e:
        # Decryption failed (also acceptable)
        print("\n[SUCCESS] Cross-tenant isolation test passed!")
        print(f"  Tenant B cannot decrypt Tenant A's logs (decryption failed: {e})")


@pytest.mark.asyncio
async def test_log_redaction_sensitive_fields_list():
    """
    Test that all sensitive fields are redacted.
    """
    redactor = TenantLogRedactor(dek_fetcher=None)

    # Log entry with all sensitive fields
    log_entry = {
        "user_hash": "hash123",
        "user_id": "user_123",
        "drift_score": 0.5,
        "risk_score": 0.8,
        "session_id": "session_abc",
        "embedding_vector": "[0.1, 0.2, 0.3]",
        "tenant_id": "tenant_alpha",
        "message": "Test",
    }

    redacted = await redactor.redact("tenant_alpha", log_entry)

    # Verify all sensitive fields are encrypted
    for field in redactor.SENSITIVE_FIELDS:
        if field in log_entry:
            assert redacted[field] != str(log_entry[field]), (
                f"{field} should be encrypted"
            )
            assert redacted.get(f"{field}_encrypted", False), (
                f"{field} should be marked as encrypted"
            )

    print("\n[SUCCESS] All sensitive fields are redacted!")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
