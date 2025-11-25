"""
Phoenix Test: Validates that sessions survive server restarts.

This script:
1. Checks if session exists in database
2. Creates a test session if needed
3. Verifies persistence after simulated restart
"""

import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from llm_firewall.storage import StorageManager
from llm_firewall.agents.memory import HierarchicalMemory
from llm_firewall.detectors.tool_killchain import ToolEvent
import time


def main():
    print("=" * 70)
    print("PHOENIX TEST: Validating Session Persistence")
    print("=" * 70)

    # Initialize storage
    storage = StorageManager()
    session_id = "phoenix-test-001"

    # Step 1: Check if session exists
    print(f"\n[Step 1] Checking for session: {session_id}")
    existing_session = storage.load_session(session_id)

    if existing_session:
        print("[OK] Session FOUND in database!")
        print(f"   Max Phase: {existing_session.max_phase_ever}")
        print(f"   Risk Multiplier: {existing_session.latent_risk_multiplier:.3f}")
        print(f"   Total Events: {sum(existing_session.tool_counts.values())}")
        print(f"   Buffer Size: {len(existing_session.tactical_buffer)}")
        print("\n[SUCCESS] PHOENIX TEST: PASSED - Session survived restart!")
    else:
        print("[WARN] Session NOT found in database")
        print("\n[Step 2] Creating test session...")

        # Create a test session
        memory = HierarchicalMemory(session_id=session_id)

        # Add a test event
        test_event = ToolEvent(
            timestamp=time.time(),
            tool="chat",
            category="user_input",
            target=None,
            success=True,
            metadata={"test": "phoenix"},
        )
        memory.add_event(test_event)

        # Save to storage
        success = storage.save_session(session_id, memory)
        if success:
            print("[OK] Test session created and saved!")
            print(f"   Max Phase: {memory.max_phase_ever}")
            print(f"   Risk Multiplier: {memory.latent_risk_multiplier:.3f}")
            print("\n[INFO] Next steps:")
            print("   1. Restart the proxy server (Ctrl+C and restart)")
            print("   2. Run this script again to verify persistence")
        else:
            print("[ERROR] Failed to save session!")

    # List all sessions
    print("\n[Step 3] All sessions in database:")
    all_sessions = storage.get_all_sessions()
    print(f"   Total sessions: {len(all_sessions)}")
    for s in all_sessions:
        print(f"   - {s['session_id']} (updated: {s['last_updated']})")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
