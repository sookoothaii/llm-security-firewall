"""
Example: Protecting an Agent Loop with RC10b
============================================

Demonstrates how to integrate RC10b into an agent execution loop.
"""

import time
from typing import Optional

from llm_firewall.agents.detector import AgenticCampaignDetector, CampaignResult
from llm_firewall.agents.state import InMemoryStateStore, CampaignStateStore
from llm_firewall.detectors.tool_killchain import ToolEvent


class SecurityError(Exception):
    """Raised when a security policy violation is detected."""
    pass


def execute_agent_tool(
    tool_name: str,
    tool_category: str,
    target: str,
    detector: AgenticCampaignDetector,
    state_store: CampaignStateStore,
    session_id: str,
) -> None:
    """
    Execute an agent tool with RC10b protection.
    
    Args:
        tool_name: Name of the tool to execute
        tool_category: Kill-chain category (e.g., "recon", "exfiltration")
        target: Target identifier
        detector: RC10b detector instance
        state_store: Campaign state store
        session_id: Session identifier
        
    Raises:
        SecurityError: If the tool execution is blocked by the firewall
    """
    # 1. Create Event
    event = ToolEvent(
        tool=tool_name,
        category=tool_category,
        target=target,
        timestamp=time.time(),
    )
    
    # 2. Update State
    state_store.add_event(session_id, event)
    history = state_store.get_events(session_id)
    
    # 3. Check Firewall
    result: CampaignResult = detector.detect(history)
    
    print(
        f"Action: {tool_name:15s} | "
        f"Risk: {result.score:.2f} | "
        f"Decision: {result.decision:8s} | "
        f"Phase: {result.phase}"
    )
    
    if result.reasons:
        print(f"  Reasons: {', '.join(result.reasons)}")
    
    if result.is_blocked:
        raise SecurityError(
            f"Blocked by Firewall! "
            f"Risk: {result.score:.2f}, "
            f"Reasons: {', '.join(result.reasons)}"
        )
    
    # 4. Execute (if allowed)
    # execute_tool(tool_name, target, ...)
    print(f"  -> Executing {tool_name} on {target}")


def simulate_gtg1002_attack():
    """
    Simulate a GTG-1002 Low-&-Slow attack.
    
    This demonstrates how RC10b prevents dilution by noise events.
    """
    print("=" * 70)
    print("Simulating GTG-1002 Low-&-Slow Attack")
    print("=" * 70)
    print()
    
    # Initialize
    detector = AgenticCampaignDetector()
    state_store = InMemoryStateStore()
    session_id = "user_123_session"
    
    try:
        # Phase 1: Noise (30x benign operations)
        print("Phase 1: Generating noise (30x benign operations)...")
        for i in range(30):
            execute_agent_tool(
                "read_file",
                "recon",
                f"doc_{i}.txt",
                detector,
                state_store,
                session_id,
            )
        
        # Phase 2: Critical action (hidden)
        print("\nPhase 2: Critical action (hidden)...")
        execute_agent_tool(
            "list_users",
            "collection",
            "users",
            detector,
            state_store,
            session_id,
        )
        
        # Phase 3: More noise
        print("\nPhase 3: More noise (10x benign operations)...")
        for i in range(10):
            execute_agent_tool(
                "check_status",
                "recon",
                f"status_{i}",
                detector,
                state_store,
                session_id,
            )
        
        # Phase 4: Final exfiltration (should be blocked)
        print("\nPhase 4: Final exfiltration attempt...")
        execute_agent_tool(
            "upload_data",
            "exfiltration",
            "evil.com",
            detector,
            state_store,
            session_id,
        )
        
        print("\n[ERROR] Attack succeeded - this should not happen!")
        
    except SecurityError as e:
        print(f"\n[SUCCESS] Attack stopped: {e}")
        print("\nHigh-Watermark prevented dilution by noise events.")


if __name__ == "__main__":
    simulate_gtg1002_attack()

