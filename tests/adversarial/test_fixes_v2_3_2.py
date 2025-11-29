"""
HAK_GAL v2.3.2: Emergency Fixes Validation

Tests to prove that the emergency fixes work correctly.

Creator: Joerg Bollwahn
Date: 2025-01-15
Status: Fix Validation (v2.3.2)
License: MIT
"""

import numpy as np
from hak_gal.layers.inbound.vector_guard import SessionTrajectory
from hak_gal.core.exceptions import PolicyViolation


def test_variance_tracking_fix():
    """
    Test that variance tracking detects whiplash attacks.

    CRITICAL FIX (v2.3.2): Variance tracking should block alternating patterns
    even if individual distances are below threshold.
    """
    print("\n" + "=" * 80)
    print("TEST: Variance Tracking Fix (Whiplash Detection)")
    print("=" * 80)

    trajectory = SessionTrajectory(window_size=50, alpha=0.3)

    # Initialize with base vector
    base_vector = np.random.rand(384).astype(np.float32)
    base_vector = base_vector / np.linalg.norm(base_vector)
    trajectory.add_embedding(base_vector.tolist())

    # Simulate whiplash attack: alternating distances
    # Pattern: 0.7, 0.1, 0.7, 0.1, ...
    blocked_count = 0
    allowed_count = 0

    for turn in range(1, 21):  # 20 turns
        if turn % 2 == 1:
            target_distance = 0.7  # Malicious
        else:
            target_distance = 0.1  # Benign

        # Generate vector at target distance
        centroid = trajectory.get_centroid()
        target_similarity = 1.0 - target_distance

        random_vec = np.random.rand(384).astype(np.float32)
        random_vec = random_vec / np.linalg.norm(random_vec)
        proj = np.dot(random_vec, centroid)

        orthogonal = random_vec - proj * centroid
        if np.linalg.norm(orthogonal) > 1e-6:
            orthogonal = orthogonal / np.linalg.norm(orthogonal)
        else:
            orthogonal = np.random.rand(384).astype(np.float32)
            orthogonal = orthogonal - np.dot(orthogonal, centroid) * centroid
            orthogonal = orthogonal / np.linalg.norm(orthogonal)

        current_vector = (
            target_similarity * centroid
            + np.sqrt(1.0 - target_similarity**2) * orthogonal
        )
        current_vector = current_vector / np.linalg.norm(current_vector)

        try:
            is_safe, distance = trajectory.check_drift(
                current_vector.tolist(), drift_threshold=0.6
            )
            if is_safe:
                allowed_count += 1
                print(f"  Turn {turn:2d}: ALLOWED (Distance: {distance:.3f})")
            else:
                blocked_count += 1
                print(f"  Turn {turn:2d}: BLOCKED (Distance: {distance:.3f})")
        except PolicyViolation as e:
            blocked_count += 1
            threat_types = e.detected_threats
            if "whiplash_attack" in threat_types:
                print(
                    f"  Turn {turn:2d}: BLOCKED (Whiplash detected! Distance: {getattr(e, 'risk_score', 0.0):.3f}) [VARIANCE FIX WORKS!]"
                )
            else:
                print(
                    f"  Turn {turn:2d}: BLOCKED (Distance: {getattr(e, 'risk_score', 0.0):.3f})"
                )

        # Add to trajectory
        trajectory.add_embedding(current_vector.tolist())

    print("\n" + "-" * 80)
    print("VARIANCE TRACKING FIX RESULTS:")
    print("-" * 80)
    print("Total Turns: 20")
    print(f"Blocked Turns: {blocked_count}")
    print(f"Allowed Turns: {allowed_count}")
    print(f"Block Rate: {blocked_count / 20 * 100:.1f}%")

    # Success criteria: Should block most turns after variance buffer fills (after turn 3)
    # With variance tracking, we expect high block rate
    if blocked_count >= 10:
        print("\n[SUCCESS] Variance tracking fix is working!")
        print("   High block rate indicates whiplash detection is active.")
    else:
        print("\n[WARNING] Variance tracking may not be working as expected.")
        print("   Expected higher block rate for whiplash attacks.")

    return blocked_count, allowed_count


def test_tenant_isolation():
    """
    Test that tenant_id prevents tenant bleeding.

    CRITICAL FIX (v2.3.2): Same user_id with different tenant_id should produce
    different session hashes.
    """
    print("\n" + "=" * 80)
    print("TEST: Tenant Isolation Fix")
    print("=" * 80)

    from hak_gal.utils.crypto import CryptoUtils

    crypto = CryptoUtils()

    user_id = "user_123"
    tenant_1 = "tenant_A"
    tenant_2 = "tenant_B"

    # Hash same user with different tenants
    hash_1 = crypto.hash_session_id(user_id, tenant_1)
    hash_2 = crypto.hash_session_id(user_id, tenant_2)

    print(f"\nUser ID: {user_id}")
    print(f"Tenant 1: {tenant_1}")
    print(f"  Hash: {hash_1[:32]}...")
    print(f"Tenant 2: {tenant_2}")
    print(f"  Hash: {hash_2[:32]}...")

    if hash_1 != hash_2:
        print("\n[SUCCESS] Tenant isolation working!")
        print("   Different tenants produce different hashes.")
    else:
        print("\n[FAILURE] Tenant isolation NOT working!")
        print("   Same hash for different tenants = tenant bleeding!")

    # Test that missing tenant_id raises ValueError
    try:
        crypto.hash_session_id(user_id, "")
        print("\n[FAILURE] Should raise ValueError for empty tenant_id!")
    except ValueError:
        print("\n[SUCCESS] Empty tenant_id correctly raises ValueError.")

    return hash_1 != hash_2


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("HAK_GAL v2.3.2: Emergency Fixes Validation")
    print("=" * 80)

    # Test 1: Variance Tracking
    blocked, allowed = test_variance_tracking_fix()

    # Test 2: Tenant Isolation
    tenant_isolated = test_tenant_isolation()

    # Summary
    print("\n" + "=" * 80)
    print("FIX VALIDATION SUMMARY")
    print("=" * 80)
    print("\nVariance Tracking Fix:")
    print(f"  Block Rate: {blocked / (blocked + allowed) * 100:.1f}%")
    print(f"  Status: {'[WORKING]' if blocked >= 10 else '[NEEDS REVIEW]'}")

    print("\nTenant Isolation Fix:")
    print(f"  Status: {'[WORKING]' if tenant_isolated else '[FAILED]'}")

    print("\n" + "=" * 80)
