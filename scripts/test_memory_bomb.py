import sys
import os

# Adjust path to import from src
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from llm_firewall.agents.memory import HierarchicalMemory
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)


def test_memory_bomb_protection():
    print("======================================================================")
    print("TEST: Memory Bomb Protection (LRU Eviction)")
    print("======================================================================")

    # 1. Initialize Memory
    memory = HierarchicalMemory(session_id="memory-bomb-test-001")

    # 2. Set Small Limit for Testing
    memory.MAX_FRAGMENT_HISTORY = 5
    print(
        f"[1] Memory Initialized with MAX_FRAGMENT_HISTORY={memory.MAX_FRAGMENT_HISTORY}"
    )

    # 3. Add 10 unique fragment hashes
    print("[2] Adding 10 unique fragments...")
    added_hashes = []
    for i in range(10):
        h = f"hash_{i}"
        memory.add_fragment(h)
        added_hashes.append(h)
        print(f"    Added: {h}")

    # 4. Assertions
    print("[3] Verifying Eviction Logic...")

    # Size Checks
    queue_size = len(memory.fragment_queue)
    set_size = len(memory.fragment_set)
    print(f"    Queue Size: {queue_size} (Expected: 5)")
    print(f"    Set Size:   {set_size} (Expected: 5)")

    assert queue_size == 5, f"Queue size is {queue_size}, expected 5"
    assert set_size == 5, f"Set size is {set_size}, expected 5"

    # Content Checks
    # First 5 (hash_0 to hash_4) should be GONE
    # Last 5 (hash_5 to hash_9) should be PRESENT

    for i in range(5):
        h = added_hashes[i]
        in_set = h in memory.fragment_set
        in_queue = h in memory.fragment_queue
        print(f"    Checking evicted {h}: Set={in_set}, Queue={in_queue}")
        assert not in_set, f"{h} should be evicted from set"
        assert not in_queue, f"{h} should be evicted from queue"

    for i in range(5, 10):
        h = added_hashes[i]
        in_set = h in memory.fragment_set
        in_queue = h in memory.fragment_queue
        print(f"    Checking present {h}: Set={in_set}, Queue={in_queue}")
        assert in_set, f"{h} should be present in set"
        assert in_queue, f"{h} should be present in queue"

    # 5. Persistence Test
    print("[4] Testing Persistence...")

    data = memory.to_dict()

    # Verify raw data structure
    assert "fragment_queue" in data, "fragment_queue missing from dict"
    assert len(data["fragment_queue"]) == 5, (
        f"Persisted queue size is {len(data['fragment_queue'])}, expected 5"
    )

    # Load back
    memory_loaded = HierarchicalMemory.from_dict(data)

    # Verify loaded state
    loaded_queue_size = len(memory_loaded.fragment_queue)
    loaded_set_size = len(memory_loaded.fragment_set)

    print(f"    Loaded Queue Size: {loaded_queue_size}")
    print(f"    Loaded Set Size:   {loaded_set_size}")

    assert loaded_queue_size == 5, "Loaded queue size mismatch"
    assert loaded_set_size == 5, "Loaded set size mismatch"

    # Verify content of loaded memory
    assert "hash_9" in memory_loaded.fragment_set, "hash_9 missing from loaded memory"
    assert "hash_0" not in memory_loaded.fragment_set, (
        "hash_0 present in loaded memory (should be evicted)"
    )

    print("\n[PASSED] Memory Bomb Protection verified.")


if __name__ == "__main__":
    test_memory_bomb_protection()
