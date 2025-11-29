"""
HAK_GAL v2.3.1: Collapse Simulator (Proof of Failure)

This is NOT a standard unit test. It is a stress-test harness designed to prove
architectural weaknesses identified by the "Blind Spot Protocol" audit.

Creator: Joerg Bollwahn
Date: 2025-01-15
Status: Adversarial Testing (v2.3.1)
License: MIT
"""

import asyncio
import time
import numpy as np
from typing import Tuple
import statistics

from hak_gal.core.engine import FirewallEngine
from hak_gal.core.exceptions import PolicyViolation


class CollapseSimulator:
    """
    Stress-test harness for proving architectural weaknesses.

    Scenarios:
    - Scenario A: EMA Oscillation ("The Whiplash Attack")
    - Scenario B: Jitter Latency Explosion
    """

    def __init__(self):
        """Initialize simulator."""
        self.results = {}

    def scenario_a_ema_oscillation(self, drift_threshold: float = 0.6) -> dict:
        """
        Scenario A: EMA Oscillation ("The Whiplash Attack").

        Logic:
        - Simulate 50 turns alternating between malicious (distance 0.7) and benign (distance 0.1)
        - Goal: Prove that EMA (Alpha=0.3) drags centroid enough that malicious turns SLIP THROUGH
        - Metric: Count successful penetrations (turns > 0.6 distance that were NOT blocked)

        Args:
            drift_threshold: Cosine distance threshold (default: 0.6)

        Returns:
            Dict with penetration count, total turns, and detailed results
        """
        print("\n" + "=" * 80)
        print("SCENARIO A: EMA Oscillation (Whiplash Attack)")
        print("=" * 80)

        # Initialize FirewallEngine
        engine = FirewallEngine(
            drift_threshold=drift_threshold, embedding_model="all-MiniLM-L6-v2"
        )

        # Get the vector_check to access trajectory directly
        vector_check = engine.vector_check
        session_id = "test_user_whiplash"

        # Create trajectory manually to inject controlled distances
        trajectory = vector_check._get_trajectory(session_id)

        # Initialize with a benign vector (distance 0.0 to itself)
        base_vector = np.random.rand(384).astype(
            np.float32
        )  # all-MiniLM-L6-v2 = 384 dim
        base_vector = base_vector / np.linalg.norm(base_vector)  # Normalize
        trajectory.add_embedding(base_vector.tolist())

        # Track results
        penetrations = 0
        total_turns = 50
        blocked_turns = []
        allowed_turns = []
        distances_recorded = []

        print(f"\nRunning {total_turns} turns with alternating pattern:")
        print("  Odd turns:  Distance 0.7 (Malicious) -> Should be BLOCKED")
        print("  Even turns: Distance 0.1 (Benign) -> Should be ALLOWED")
        print(f"  Threshold: {drift_threshold}")
        print()

        for turn in range(1, total_turns + 1):
            # Determine target distance
            if turn % 2 == 1:  # Odd: Malicious
                target_distance = 0.7
                expected_action = "BLOCK"
            else:  # Even: Benign
                target_distance = 0.1
                expected_action = "ALLOW"

            # Generate vector at target distance from centroid
            centroid = trajectory.get_centroid()
            if centroid is None:
                # First turn - use base vector
                current_vector = base_vector.copy()
            else:
                # Generate vector at specific cosine distance from centroid
                # Cosine distance = 1 - cosine_similarity
                # We want: cosine_distance = target_distance
                # So: cosine_similarity = 1 - target_distance
                target_similarity = 1.0 - target_distance

                # Generate orthogonal component
                # If centroid is normalized, we can construct a vector at specific distance
                # Method: v = (1-d)*centroid + d*orthogonal_vector
                # But we need to ensure ||v|| = 1

                # Simpler: Generate random vector, then adjust to target distance
                random_vec = np.random.rand(384).astype(np.float32)
                random_vec = random_vec / np.linalg.norm(random_vec)

                # Project random_vec onto centroid
                proj = np.dot(random_vec, centroid)

                # Construct vector at target similarity
                # v = target_similarity * centroid + sqrt(1 - target_similarity^2) * orthogonal
                orthogonal = random_vec - proj * centroid
                if np.linalg.norm(orthogonal) > 1e-6:
                    orthogonal = orthogonal / np.linalg.norm(orthogonal)
                else:
                    # If random_vec is parallel to centroid, use a fixed orthogonal
                    orthogonal = np.random.rand(384).astype(np.float32)
                    orthogonal = orthogonal - np.dot(orthogonal, centroid) * centroid
                    orthogonal = orthogonal / np.linalg.norm(orthogonal)

                # Build vector at target distance
                current_vector = (
                    target_similarity * centroid
                    + np.sqrt(1.0 - target_similarity**2) * orthogonal
                )
                current_vector = current_vector / np.linalg.norm(current_vector)

            # Check drift
            try:
                is_safe, cosine_distance = trajectory.check_drift(
                    current_vector.tolist(), drift_threshold
                )

                distances_recorded.append(cosine_distance)

                if is_safe:
                    allowed_turns.append(turn)
                    action = "ALLOWED"
                    if target_distance > drift_threshold:
                        # FALSE NEGATIVE: Malicious turn was allowed!
                        penetrations += 1
                        print(
                            f"  Turn {turn:2d}: {action:7s} (Distance: {cosine_distance:.3f}) [FALSE NEGATIVE!]"
                        )
                    else:
                        print(
                            f"  Turn {turn:2d}: {action:7s} (Distance: {cosine_distance:.3f})"
                        )
                else:
                    blocked_turns.append(turn)
                    action = "BLOCKED"
                    if target_distance <= drift_threshold:
                        # FALSE POSITIVE: Benign turn was blocked
                        print(
                            f"  Turn {turn:2d}: {action:7s} (Distance: {cosine_distance:.3f}) [FALSE POSITIVE!]"
                        )
                    else:
                        print(
                            f"  Turn {turn:2d}: {action:7s} (Distance: {cosine_distance:.3f})"
                        )

            except PolicyViolation as e:
                # Drift detected - blocked
                blocked_turns.append(turn)
                # Extract distance from exception if possible
                cosine_distance = getattr(e, "risk_score", target_distance)
                distances_recorded.append(cosine_distance)
                action = "BLOCKED"
                if target_distance <= drift_threshold:
                    print(
                        f"  Turn {turn:2d}: {action:7s} (Distance: {cosine_distance:.3f}) [FALSE POSITIVE!]"
                    )
                else:
                    print(
                        f"  Turn {turn:2d}: {action:7s} (Distance: {cosine_distance:.3f})"
                    )

            # Add to trajectory (this updates EMA centroid)
            trajectory.add_embedding(current_vector.tolist())

        # Summary
        print("\n" + "-" * 80)
        print("SCENARIO A RESULTS:")
        print("-" * 80)
        print(f"Total Turns: {total_turns}")
        print(f"Malicious Turns (distance > {drift_threshold}): {total_turns // 2}")
        print(f"Successful Penetrations (False Negatives): {penetrations}")
        print(f"Penetration Rate: {penetrations / (total_turns // 2) * 100:.1f}%")
        print(f"Blocked Turns: {len(blocked_turns)}")
        print(f"Allowed Turns: {len(allowed_turns)}")
        if distances_recorded:
            print(
                f"Distance Stats: min={min(distances_recorded):.3f}, max={max(distances_recorded):.3f}, mean={statistics.mean(distances_recorded):.3f}"
            )

        result = {
            "scenario": "EMA_Oscillation",
            "total_turns": total_turns,
            "malicious_turns": total_turns // 2,
            "penetrations": penetrations,
            "penetration_rate": penetrations / (total_turns // 2) * 100
            if (total_turns // 2) > 0
            else 0.0,
            "blocked_turns": len(blocked_turns),
            "allowed_turns": len(allowed_turns),
            "distances": distances_recorded,
            "drift_threshold": drift_threshold,
        }

        self.results["scenario_a"] = result
        return result

    async def scenario_b_jitter_latency_explosion(
        self, num_concurrent: int = 500
    ) -> dict:
        """
        Scenario B: Jitter Latency Explosion.

        Logic:
        - Spawn 500 concurrent async tasks calling process_outbound
        - Metric: Measure P99 latency
        - Goal: Prove that asyncio.sleep jitter causes exponential latency growth under load

        Args:
            num_concurrent: Number of concurrent tasks (default: 500)

        Returns:
            Dict with latency statistics (P50, P95, P99, max)
        """
        print("\n" + "=" * 80)
        print("SCENARIO B: Jitter Latency Explosion")
        print("=" * 80)

        # Initialize FirewallEngine
        engine = FirewallEngine()

        # Register a simple guard for testing
        from hak_gal.layers.outbound.tool_guard import BaseToolGuard, SessionContext

        class DummyGuard(BaseToolGuard):
            async def validate(
                self, tool_name: str, args: dict, context: SessionContext
            ) -> bool:
                return True

        engine.register_tool_guard("test_tool", DummyGuard("test_tool", priority=50))

        print(f"\nSpawning {num_concurrent} concurrent async tasks...")
        print("Each task calls process_outbound (with jitter sleep)...")
        print()

        async def single_request(request_id: int) -> Tuple[int, float]:
            """Single outbound request with timing."""
            start_time = time.perf_counter()
            try:
                await engine.process_outbound(
                    user_id=f"user_{request_id}",
                    tool_name="test_tool",
                    tool_args={"arg1": "value1"},
                )
                elapsed = time.perf_counter() - start_time
                return (request_id, elapsed)
            except Exception as e:
                elapsed = time.perf_counter() - start_time
                print(f"  Request {request_id} failed: {e}")
                return (request_id, elapsed)

        # Spawn all tasks concurrently
        start_total = time.perf_counter()
        tasks = [single_request(i) for i in range(num_concurrent)]
        results = await asyncio.gather(*tasks)
        total_elapsed = time.perf_counter() - start_total

        # Extract latencies
        latencies = [elapsed for _, elapsed in results]
        latencies.sort()

        # Calculate percentiles
        p50 = latencies[int(len(latencies) * 0.50)] if latencies else 0.0
        p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0.0
        p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0.0
        p99_9 = latencies[int(len(latencies) * 0.999)] if len(latencies) > 0 else 0.0
        max_latency = max(latencies) if latencies else 0.0
        min_latency = min(latencies) if latencies else 0.0
        mean_latency = statistics.mean(latencies) if latencies else 0.0

        print("-" * 80)
        print("SCENARIO B RESULTS:")
        print("-" * 80)
        print(f"Total Requests: {num_concurrent}")
        print(f"Total Wall Time: {total_elapsed:.3f}s")
        print(f"Throughput: {num_concurrent / total_elapsed:.1f} req/s")
        print()
        print("Latency Statistics:")
        print(f"  Min:    {min_latency * 1000:.2f}ms")
        print(f"  P50:    {p50 * 1000:.2f}ms")
        print(f"  P95:    {p95 * 1000:.2f}ms")
        print(f"  P99:    {p99 * 1000:.2f}ms")
        print(f"  P99.9:  {p99_9 * 1000:.2f}ms")
        print(f"  Max:    {max_latency * 1000:.2f}ms")
        print(f"  Mean:   {mean_latency * 1000:.2f}ms")

        # Check if P99 exceeds reasonable threshold (e.g., 100ms)
        threshold_ms = 100.0
        if p99 * 1000 > threshold_ms:
            print(
                f"\n⚠️  WARNING: P99 latency ({p99 * 1000:.2f}ms) exceeds threshold ({threshold_ms}ms)"
            )
            print(
                "   This indicates exponential latency growth under load (Jitter DoS)."
            )

        result = {
            "scenario": "Jitter_Latency_Explosion",
            "num_concurrent": num_concurrent,
            "total_wall_time": total_elapsed,
            "throughput": num_concurrent / total_elapsed if total_elapsed > 0 else 0.0,
            "latencies": {
                "min": min_latency,
                "p50": p50,
                "p95": p95,
                "p99": p99,
                "p99_9": p99_9,
                "max": max_latency,
                "mean": mean_latency,
            },
        }

        self.results["scenario_b"] = result
        return result


async def main():
    """Run all collapse scenarios."""
    simulator = CollapseSimulator()

    # Scenario A: EMA Oscillation
    result_a = simulator.scenario_a_ema_oscillation(drift_threshold=0.6)

    # Scenario B: Jitter Latency Explosion
    result_b = await simulator.scenario_b_jitter_latency_explosion(num_concurrent=500)

    # Final summary
    print("\n" + "=" * 80)
    print("COLLAPSE SIMULATOR SUMMARY")
    print("=" * 80)
    print("\nScenario A (EMA Oscillation):")
    print(
        f"  Penetrations: {result_a['penetrations']}/{result_a['malicious_turns']} ({result_a['penetration_rate']:.1f}%)"
    )
    print("\nScenario B (Jitter Latency):")
    print(f"  P99 Latency: {result_b['latencies']['p99'] * 1000:.2f}ms")
    print(f"  Throughput: {result_b['throughput']:.1f} req/s")

    return simulator.results


if __name__ == "__main__":
    asyncio.run(main())
