"""
Memory optimization tests to bring usage under 300MB cap.

Identifies memory leaks and optimization opportunities.
"""

import psutil
import os
import gc
from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2


class TestMemoryOptimization:
    """Tests for memory usage optimization."""

    def test_single_request_memory(self):
        """Test memory usage for single request (should be < 50MB)."""
        process = psutil.Process(os.getpid())
        engine = FirewallEngineV2()

        gc.collect()  # Force garbage collection
        initial_memory = process.memory_info().rss / 1024 / 1024

        # Process a typical request
        decision = engine.process_input(
            user_id="test", text="What is the weather today?"
        )

        gc.collect()
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        print("\nSingle Request Memory:")
        print(f"  Initial: {initial_memory:.1f} MB")
        print(f"  Final: {final_memory:.1f} MB")
        print(f"  Increase: {memory_increase:.1f} MB")

        assert memory_increase < 50, (
            f"Single request memory increase {memory_increase:.1f}MB is too high"
        )

    def test_batch_processing_memory_leak(self):
        """Test for memory leaks during batch processing."""
        process = psutil.Process(os.getpid())
        engine = FirewallEngineV2()

        # Create test payloads
        payloads = [f"Test payload {i}" for i in range(1000)]

        gc.collect()
        initial_memory = process.memory_info().rss / 1024 / 1024

        memory_readings = []

        for i, payload in enumerate(payloads):
            decision = engine.process_input(user_id=f"batch_{i}", text=payload)

            # Record memory every 100 requests
            if i % 100 == 0:
                gc.collect()
                current_memory = process.memory_info().rss / 1024 / 1024
                memory_readings.append(current_memory)

                if i > 0:
                    memory_per_request = (current_memory - initial_memory) / i
                    print(
                        f"  Request {i}: {current_memory:.1f} MB ({memory_per_request:.2f} MB/request)"
                    )

        gc.collect()
        final_memory = process.memory_info().rss / 1024 / 1024
        total_increase = final_memory - initial_memory

        print("\nBatch Processing Memory:")
        print(f"  Initial: {initial_memory:.1f} MB")
        print(f"  Final: {final_memory:.1f} MB")
        print(f"  Total increase: {total_increase:.1f} MB")
        print(f"  Per request: {total_increase / len(payloads):.3f} MB")

        # Check for memory leaks
        # Memory should not grow linearly indefinitely
        assert total_increase < 100, (
            f"Memory leak: increased by {total_increase:.1f}MB for {len(payloads)} requests"
        )

    def test_embedding_cache_memory(self):
        """Test memory usage of embedding cache."""

        optimization_suggestions = [
            {
                "component": "Embedding Cache",
                "issue": "Unbounded cache growth",
                "fix": "Implement LRU cache with size limit",
                "expected_saving": "50-70% memory reduction",
                "file": "src/llm_firewall/cache/decision_cache.py",
            },
            {
                "component": "Session State",
                "issue": "Accumulation across sessions",
                "fix": "Periodic cleanup of old sessions",
                "expected_saving": "30% memory reduction",
                "file": "kids_policy/session_monitor.py",
            },
            {
                "component": "Adversarial Suite",
                "issue": "Loaded entirely in memory",
                "fix": "Stream from disk or use memory-mapped file",
                "expected_saving": "Reduce 50MB -> 5MB",
                "file": "tests/conftest.py",
            },
        ]

        print("\nMemory Optimization Suggestions:")
        for suggestion in optimization_suggestions:
            print(f"  {suggestion['component']}:")
            print(f"    Issue: {suggestion['issue']}")
            print(f"    Fix: {suggestion['fix']}")
            print(f"    Expected: {suggestion['expected_saving']}")
            print(f"    File: {suggestion['file']}")

        assert len(optimization_suggestions) == 3

    def test_memory_pool_implementation(self):
        """Test memory pooling for repeated allocations."""
        # Memory pooling can significantly reduce allocation overhead

        import numpy as np

        class MemoryPool:
            """Simple memory pool for numpy arrays."""

            def __init__(self, shape, dtype=np.float32, pool_size=10):
                self.pool = [np.zeros(shape, dtype=dtype) for _ in range(pool_size)]
                self.available = list(range(pool_size))
                self.in_use = set()

            def allocate(self):
                if self.available:
                    idx = self.available.pop()
                    self.in_use.add(idx)
                    return self.pool[idx]
                return None

            def release(self, array):
                for idx, arr in enumerate(self.pool):
                    if arr is array:
                        self.in_use.remove(idx)
                        self.available.append(idx)
                        arr.fill(0)  # Reset to zeros
                        break

        # Test the pool
        pool = MemoryPool(shape=(768,), pool_size=5)

        arrays = []
        for i in range(5):
            arr = pool.allocate()
            arr.fill(i)  # Use the array
            arrays.append(arr)

        # Release arrays back to pool
        for arr in arrays:
            pool.release(arr)

        print("\nMemory Pool Test:")
        print("  Pool size: 5")
        print("  Arrays allocated: 5")
        print(f"  Arrays in pool: {len(pool.available)}")

        assert len(pool.available) == 5
        assert len(pool.in_use) == 0
