
import time
import sys
import os
import math

# Adjust path to import from src
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from llm_firewall.agents.memory import HierarchicalMemory
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)

def test_risk_decay():
    print("======================================================================")
    print("TEST: Risk Decay (Behavioral Rehabilitation)")
    print("======================================================================")

    # 1. Initialize Memory
    memory = HierarchicalMemory(session_id="decay-test-001")
    print("[1] Memory Initialized. Default Risk:", memory.latent_risk_multiplier)
    
    # 2. Manually set High Risk
    memory.latent_risk_multiplier = 4.0
    # We also set max_phase_ever to 0 so the dynamic floor stays at 1.0 for this simple test
    # (Unless we want to test floor logic specifically, but let's test pure decay first)
    memory.max_phase_ever = 0 
    
    # Reset timestamp to NOW
    memory.last_decay_update = time.time()
    
    print(f"[2] Set High Risk: {memory.latent_risk_multiplier}")
    assert memory.latent_risk_multiplier == 4.0, "Failed to set initial risk"

    # 3. Simulate 24 hours (1 half-life) passed
    # Half-life is 24*3600 seconds
    print("[3] Simulating 24 hours passing...")
    memory.last_decay_update -= (24 * 3600)
    
    # 4. Trigger Decay via get_risk_score()
    current_score = memory.get_risk_score()
    print(f"[4] Risk Score after 24h: {current_score:.4f}")
    
    # Expected: 4.0 * (0.5 ^ 1) = 2.0. 
    # However, the formula is: excess = (4.0 - 1.0) = 3.0.
    # decayed_excess = 3.0 * 0.5 = 1.5.
    # new_risk = 1.0 + 1.5 = 2.5.
    # Wait, check the implementation logic I wrote:
    # new_risk = max(effective_floor, (self.latent_risk_multiplier - effective_floor) * decay_factor + effective_floor)
    # If floor is 1.0: new_risk = (4.0 - 1.0) * 0.5 + 1.0 = 1.5 + 1.0 = 2.5.
    
    # Let's verify the math:
    # Goal: Decay towards 1.0.
    # Start: 4.0. Dist to 1.0 is 3.0.
    # After 1 half-life, distance should be 1.5.
    # So score should be 1.0 + 1.5 = 2.5.
    
    assert 2.4 < current_score < 2.6, f"Expected ~2.5 after 24h, got {current_score}"
    
    # 5. Simulate another 24 hours (total 48h)
    print("[5] Simulating another 24 hours (total 48h)...")
    memory.last_decay_update -= (24 * 3600) # Move back another 24h
    
    current_score_2 = memory.get_risk_score()
    print(f"[5] Risk Score after 48h: {current_score_2:.4f}")
    
    # Expected: Distance 1.5 -> 0.75.
    # Score: 1.0 + 0.75 = 1.75.
    
    assert 1.7 < current_score_2 < 1.8, f"Expected ~1.75 after 48h, got {current_score_2}"
    
    # 6. Persistence Test
    print("[6] Testing Persistence of Decay...")
    
    # Save to dict
    data = memory.to_dict()
    
    # Verify last_decay_update is in dict
    assert "last_decay_update" in data, "last_decay_update missing from persistence"
    
    # Simulate loading back after offline time
    # Let's simulate that while offline, another 24h passed
    saved_time = data["last_decay_update"]
    data["last_decay_update"] = saved_time - (24 * 3600) 
    
    # Load back
    memory_loaded = HierarchicalMemory.from_dict(data)
    
    # Upon loading, it should apply decay immediately for the "offline" time
    # Previous score was ~1.75. Distance to 1.0 is 0.75.
    # Another half-life passes. Distance becomes 0.375.
    # New score should be ~1.375.
    
    loaded_score = memory_loaded.latent_risk_multiplier
    print(f"[6] Loaded Score (with offline decay): {loaded_score:.4f}")
    
    assert 1.3 < loaded_score < 1.45, f"Expected ~1.375 after offline decay, got {loaded_score}"
    
    print("\n[OK] Risk Decay Test PASSED")

if __name__ == "__main__":
    test_risk_decay()

