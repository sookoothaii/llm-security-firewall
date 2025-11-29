"""
HAK_GAL v2.3.3: CUSUM Changepoint Detection Validation

Tests to prove that CUSUM detects oscillation attacks (2-value, 3-value, etc.)
that variance-based detection misses.

Creator: Joerg Bollwahn
Date: 2025-01-15
Status: CUSUM Validation (v2.3.3)
License: MIT
"""

import numpy as np
from hak_gal.layers.inbound.vector_guard import SessionTrajectory
from hak_gal.core.exceptions import PolicyViolation


def test_cusum_2_value_oscillation():
    """
    Test CUSUM against 2-value oscillation (0.7 → 0.1).

    This is the original whiplash attack pattern.
    """
    print("\n" + "=" * 80)
    print("TEST: CUSUM vs 2-Value Oscillation (0.7 -> 0.1)")
    print("=" * 80)

    trajectory = SessionTrajectory(
        window_size=50,
        alpha=0.3,
        cusum_baseline=0.1,  # Expected normal drift
        cusum_tolerance=0.05,  # k: tolerance
        cusum_threshold=0.3,  # h: decision threshold
    )

    # Initialize with base vector
    base_vector = np.random.rand(384).astype(np.float32)
    base_vector = base_vector / np.linalg.norm(base_vector)
    trajectory.add_embedding(base_vector.tolist())

    blocked_count = 0
    allowed_count = 0
    cusum_scores = []

    for turn in range(1, 21):  # 20 turns
        # 2-value oscillation: 0.7, 0.1, 0.7, 0.1, ...
        target_distance = 0.7 if turn % 2 == 1 else 0.1

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
            cusum_scores.append(trajectory.cusum_score)
            if is_safe:
                allowed_count += 1
                print(
                    f"  Turn {turn:2d}: ALLOWED (Distance: {distance:.3f}, CUSUM: {trajectory.cusum_score:.3f})"
                )
            else:
                blocked_count += 1
                print(
                    f"  Turn {turn:2d}: BLOCKED (Distance: {distance:.3f}, CUSUM: {trajectory.cusum_score:.3f})"
                )
        except PolicyViolation as e:
            blocked_count += 1
            cusum_scores.append(trajectory.cusum_score)
            threat_types = e.detected_threats
            if "changepoint_attack" in threat_types:
                print(
                    f"  Turn {turn:2d}: BLOCKED (CUSUM Changepoint! Score: {trajectory.cusum_score:.3f}) [CUSUM WORKS!]"
                )
            else:
                print(
                    f"  Turn {turn:2d}: BLOCKED (Distance: {getattr(e, 'risk_score', 0.0):.3f}, CUSUM: {trajectory.cusum_score:.3f})"
                )

        # Add to trajectory
        trajectory.add_embedding(current_vector.tolist())

    print("\n" + "-" * 80)
    print("CUSUM 2-VALUE OSCILLATION RESULTS:")
    print("-" * 80)
    print("Total Turns: 20")
    print(f"Blocked Turns: {blocked_count}")
    print(f"Allowed Turns: {allowed_count}")
    print(f"Block Rate: {blocked_count / 20 * 100:.1f}%")
    print(f"Max CUSUM Score: {max(cusum_scores):.3f}")
    print(f"Final CUSUM Score: {cusum_scores[-1]:.3f}")

    return blocked_count, allowed_count, max(cusum_scores)


def test_cusum_3_value_oscillation():
    """
    Test CUSUM against 3-value oscillation (0.7 → 0.1 → 0.5).

    This is the attack pattern that variance-based detection misses.
    CUSUM should still detect it because it tracks Rate-of-Change.
    """
    print("\n" + "=" * 80)
    print("TEST: CUSUM vs 3-Value Oscillation (0.7 -> 0.1 -> 0.5)")
    print("=" * 80)

    trajectory = SessionTrajectory(
        window_size=50,
        alpha=0.3,
        cusum_baseline=0.1,  # Expected normal drift
        cusum_tolerance=0.05,  # k: tolerance
        cusum_threshold=0.3,  # h: decision threshold
    )

    # Initialize with base vector
    base_vector = np.random.rand(384).astype(np.float32)
    base_vector = base_vector / np.linalg.norm(base_vector)
    trajectory.add_embedding(base_vector.tolist())

    blocked_count = 0
    allowed_count = 0
    cusum_scores = []

    # 3-value oscillation pattern
    pattern = [0.7, 0.1, 0.5]

    for turn in range(1, 21):  # 20 turns
        target_distance = pattern[(turn - 1) % 3]

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
            cusum_scores.append(trajectory.cusum_score)
            if is_safe:
                allowed_count += 1
                print(
                    f"  Turn {turn:2d}: ALLOWED (Distance: {distance:.3f}, CUSUM: {trajectory.cusum_score:.3f})"
                )
            else:
                blocked_count += 1
                print(
                    f"  Turn {turn:2d}: BLOCKED (Distance: {distance:.3f}, CUSUM: {trajectory.cusum_score:.3f})"
                )
        except PolicyViolation as e:
            blocked_count += 1
            cusum_scores.append(trajectory.cusum_score)
            threat_types = e.detected_threats
            if "changepoint_attack" in threat_types:
                print(
                    f"  Turn {turn:2d}: BLOCKED (CUSUM Changepoint! Score: {trajectory.cusum_score:.3f}) [CUSUM WORKS!]"
                )
            else:
                print(
                    f"  Turn {turn:2d}: BLOCKED (Distance: {getattr(e, 'risk_score', 0.0):.3f}, CUSUM: {trajectory.cusum_score:.3f})"
                )

        # Add to trajectory
        trajectory.add_embedding(current_vector.tolist())

    print("\n" + "-" * 80)
    print("CUSUM 3-VALUE OSCILLATION RESULTS:")
    print("-" * 80)
    print("Total Turns: 20")
    print(f"Blocked Turns: {blocked_count}")
    print(f"Allowed Turns: {allowed_count}")
    print(f"Block Rate: {blocked_count / 20 * 100:.1f}%")
    print(f"Max CUSUM Score: {max(cusum_scores):.3f}")
    print(f"Final CUSUM Score: {cusum_scores[-1]:.3f}")

    # CRITICAL: CUSUM should detect 3-value oscillation (variance would miss this)
    if blocked_count >= 5:
        print("\n[SUCCESS] CUSUM detects 3-value oscillation!")
        print("   Variance-based detection would miss this pattern.")
    else:
        print("\n[WARNING] CUSUM may need parameter tuning for 3-value oscillation.")

    return blocked_count, allowed_count, max(cusum_scores)


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("HAK_GAL v2.3.3: CUSUM Changepoint Detection Validation")
    print("=" * 80)

    # Test 1: 2-value oscillation
    blocked_2, allowed_2, max_cusum_2 = test_cusum_2_value_oscillation()

    # Test 2: 3-value oscillation (the killer test)
    blocked_3, allowed_3, max_cusum_3 = test_cusum_3_value_oscillation()

    # Summary
    print("\n" + "=" * 80)
    print("CUSUM VALIDATION SUMMARY")
    print("=" * 80)
    print("\n2-Value Oscillation (0.7 -> 0.1):")
    print(f"  Block Rate: {blocked_2 / (blocked_2 + allowed_2) * 100:.1f}%")
    print(f"  Max CUSUM Score: {max_cusum_2:.3f}")
    print(f"  Status: {'[WORKING]' if blocked_2 >= 10 else '[NEEDS TUNING]'}")

    print("\n3-Value Oscillation (0.7 -> 0.1 -> 0.5):")
    print(f"  Block Rate: {blocked_3 / (blocked_3 + allowed_3) * 100:.1f}%")
    print(f"  Max CUSUM Score: {max_cusum_3:.3f}")
    print(f"  Status: {'[WORKING]' if blocked_3 >= 5 else '[NEEDS TUNING]'}")
    print(
        f"  Critical: {'[PASS]' if blocked_3 >= 5 else '[FAIL]'} - CUSUM must detect 3-value oscillation"
    )

    print("\n" + "=" * 80)
