"""
Tool Kill-Chain Monitor (RC10: Agentic Campaign Detection)
==========================================================

Detects AI-orchestrated cyber campaigns by tracking tool usage sequences
and mapping them to kill-chain phases.

Based on Anthropic Report (2025): "Disrupting the first reported AI-orchestrated
cyber espionage campaign"

Kill-Chain Phases:
1. Initialization: Setup, tool discovery, pretext establishment
2. Reconnaissance: Network scanning, port enumeration, service discovery
3. Exploit Development: Vulnerability research, exploit crafting
4. Lateral Movement: Credential theft, privilege escalation, pivoting
5. Data Collection: Information gathering, file exfiltration
6. Documentation: Report generation, handover preparation

Mathematical Foundation:
- State machine tracking phase progression
- Risk scoring based on phase depth, branching factor, tempo, tool diversity
- Integration with E-Value Session Risk for sequential testing

Creator: Joerg Bollwahn (with GPT-5.1 analysis)
Date: 2025-11-17
License: MIT
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Set, Tuple

# Kill-Chain Phase Enum
class KillChainPhase(IntEnum):
    """Kill-chain phases (ordered progression)."""
    
    INITIALIZATION = 0
    RECONNAISSANCE = 1
    EXPLOIT_DEVELOPMENT = 2
    LATERAL_MOVEMENT = 3
    DATA_COLLECTION = 4
    DOCUMENTATION = 5


# Tool Category Mapping (configurable via YAML)
DEFAULT_TOOL_CATEGORIES: Dict[str, KillChainPhase] = {
    # Reconnaissance
    "nmap": KillChainPhase.RECONNAISSANCE,
    "masscan": KillChainPhase.RECONNAISSANCE,
    "nmap_scan": KillChainPhase.RECONNAISSANCE,
    "port_scan": KillChainPhase.RECONNAISSANCE,
    "service_scan": KillChainPhase.RECONNAISSANCE,
    "dns_lookup": KillChainPhase.RECONNAISSANCE,
    "whois": KillChainPhase.RECONNAISSANCE,
    "subdomain_enum": KillChainPhase.RECONNAISSANCE,
    
    # Exploit Development
    "exploit": KillChainPhase.EXPLOIT_DEVELOPMENT,
    "exploit_framework": KillChainPhase.EXPLOIT_DEVELOPMENT,
    "vuln_scan": KillChainPhase.EXPLOIT_DEVELOPMENT,
    "cve_search": KillChainPhase.EXPLOIT_DEVELOPMENT,
    "payload_gen": KillChainPhase.EXPLOIT_DEVELOPMENT,
    
    # Lateral Movement
    "credential_test": KillChainPhase.LATERAL_MOVEMENT,
    "ssh_connect": KillChainPhase.LATERAL_MOVEMENT,
    "rdp_connect": KillChainPhase.LATERAL_MOVEMENT,
    "smb_enum": KillChainPhase.LATERAL_MOVEMENT,
    "kerberos": KillChainPhase.LATERAL_MOVEMENT,
    "privilege_escalation": KillChainPhase.LATERAL_MOVEMENT,
    
    # Data Collection
    "db_query": KillChainPhase.DATA_COLLECTION,
    "file_read": KillChainPhase.DATA_COLLECTION,
    "data_export": KillChainPhase.DATA_COLLECTION,
    "screenshot": KillChainPhase.DATA_COLLECTION,
    "keylog": KillChainPhase.DATA_COLLECTION,
    
    # Documentation
    "generate_report": KillChainPhase.DOCUMENTATION,
    "create_handover": KillChainPhase.DOCUMENTATION,
}


@dataclass
class ToolEvent:
    """Single tool invocation event."""
    
    timestamp: float
    tool: str  # Tool name (e.g., "nmap", "mcp_filesystem_read")
    category: str  # Tool category (e.g., "net_scan", "file_read")
    target: Optional[str] = None  # Target identifier (IP, hostname, etc.)
    success: bool = True
    metadata: Dict[str, any] = field(default_factory=dict)


@dataclass
class KillChainState:
    """State tracking for kill-chain progression."""
    
    session_id: str
    operator_id: Optional[str] = None  # API key / user identifier
    
    # Phase tracking
    current_phase: KillChainPhase = KillChainPhase.INITIALIZATION
    phase_reached: Set[KillChainPhase] = field(default_factory=set)
    phase_timestamps: Dict[KillChainPhase, float] = field(default_factory=dict)
    
    # Tool usage
    tool_events: List[ToolEvent] = field(default_factory=list)
    tool_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    tool_categories: Set[str] = field(default_factory=set)
    
    # Target tracking
    targets: Set[str] = field(default_factory=set)
    target_phases: Dict[str, KillChainPhase] = field(default_factory=dict)
    
    # Metrics
    tempo: float = 0.0  # Events per second (rolling window)
    branching_factor: float = 0.0  # Number of parallel targets
    tool_diversity: int = 0  # Number of unique tools
    
    # Risk scoring
    risk_score: float = 0.0
    last_update: float = field(default_factory=time.time)


def map_tool_to_phase(tool: str, category: str, tool_categories: Dict[str, KillChainPhase]) -> Optional[KillChainPhase]:
    """
    Map tool/category to kill-chain phase.
    
    Args:
        tool: Tool name
        category: Tool category
        tool_categories: Mapping from tool/category to phase
        
    Returns:
        Kill-chain phase or None if not mappable
    """
    # Try exact tool name match
    if tool in tool_categories:
        return tool_categories[tool]
    
    # Try category match
    if category in tool_categories:
        return tool_categories[category]
    
    # Try prefix matching (e.g., "mcp_filesystem_read" -> "file_read")
    tool_lower = tool.lower()
    for key, phase in tool_categories.items():
        if key in tool_lower or tool_lower in key:
            return phase
    
    return None


def update_killchain_state(
    state: KillChainState,
    event: ToolEvent,
    tool_categories: Dict[str, KillChainPhase] = None,
    window_seconds: float = 300.0,  # 5-minute rolling window
    use_phase_floor: bool = True,
) -> KillChainState:
    """
    Update kill-chain state with new tool event.
    
    Args:
        state: Current kill-chain state
        event: New tool event
        tool_categories: Tool-to-phase mapping (defaults to DEFAULT_TOOL_CATEGORIES)
        window_seconds: Rolling window for tempo calculation
        
    Returns:
        Updated state
    """
    if tool_categories is None:
        tool_categories = DEFAULT_TOOL_CATEGORIES
    
    # Map tool to phase
    phase = map_tool_to_phase(event.tool, event.category, tool_categories)
    
    # Add event
    state.tool_events.append(event)
    state.tool_counts[event.tool] += 1
    state.tool_categories.add(event.category)
    
    # Update phase progression
    if phase is not None:
        if phase > state.current_phase:
            state.current_phase = phase
            state.phase_timestamps[phase] = event.timestamp
        
        state.phase_reached.add(phase)
        
        # Update target phase tracking
        if event.target:
            state.targets.add(event.target)
            current_target_phase = state.target_phases.get(event.target, KillChainPhase.INITIALIZATION)
            if phase > current_target_phase:
                state.target_phases[event.target] = phase
    
    # Calculate metrics
    now = event.timestamp
    
    # Tempo: events per second in rolling window
    window_start = now - window_seconds
    recent_events = [e for e in state.tool_events if e.timestamp >= window_start]
    if len(recent_events) > 1:
        time_span = recent_events[-1].timestamp - recent_events[0].timestamp
        state.tempo = len(recent_events) / max(time_span, 1.0)
    else:
        state.tempo = 0.0
    
    # Branching factor: number of unique targets in window
    recent_targets = {e.target for e in recent_events if e.target}
    state.branching_factor = len(recent_targets)
    
    # Tool diversity: number of unique tools
    state.tool_diversity = len(state.tool_counts)
    
    # Calculate risk score
    state.risk_score = calculate_killchain_risk(state, use_phase_floor=use_phase_floor)
    
    state.last_update = now
    
    return state


def phase_floor(phase_depth: int) -> float:
    """
    Phase-based minimum risk floor (RC10b: Low & Slow Fix).
    
    Ensures that advanced kill-chain phases cannot be "damped down" by low
    volumetrische signals (branching, tempo, diversity). This addresses the
    HARD_FN weakness where Low & Slow attacks (Phase 4-5) were not detected
    because volumetrische features were too low.
    
    Args:
        phase_depth: Current kill-chain phase (0-5)
        
    Returns:
        Minimum risk score floor [0.0, 0.65]
    """
    if phase_depth <= 1:
        return 0.0
    elif phase_depth == 2:  # Exploit Development
        return 0.30
    elif phase_depth == 3:  # Lateral Movement
        return 0.40
    elif phase_depth == 4:  # Data Collection
        return 0.55
    else:  # Documentation (5) or beyond
        return 0.65


def calculate_killchain_risk(
    state: KillChainState,
    use_phase_floor: bool = True,
) -> float:
    """
    Calculate risk score from kill-chain state (RC10b: with Phase Floor).
    
    Risk factors:
    - Phase depth (higher phase = higher risk)
    - Branching factor (more parallel targets = higher risk)
    - Tempo (faster execution = higher risk)
    - Tool diversity (more tools = higher risk)
    
    RC10b Enhancement:
    - Phase-based minimum floor ensures Low & Slow attacks (Phase 4-5) are
      detected even with low volumetrische signals.
    
    Returns:
        Risk score [0.0, 1.0]
    """
    # Phase depth component (0.0 - 0.4)
    phase_score = (state.current_phase.value / len(KillChainPhase)) * 0.4
    
    # Branching factor component (0.0 - 0.2)
    # Normalize: 1 target = 0.0, 10+ targets = 0.2
    branch_score = min(state.branching_factor / 10.0, 1.0) * 0.2
    
    # Tempo component (0.0 - 0.2)
    # Normalize: 0.1 events/s = 0.0, 10 events/s = 0.2
    tempo_score = min(state.tempo / 10.0, 1.0) * 0.2
    
    # Tool diversity component (0.0 - 0.2)
    # Normalize: 1 tool = 0.0, 10+ tools = 0.2
    diversity_score = min(state.tool_diversity / 10.0, 1.0) * 0.2
    
    # Raw combined score
    total_score = phase_score + branch_score + tempo_score + diversity_score
    
    # RC10b: Apply phase-based minimum floor
    # This ensures Low & Slow attacks (Phase 4-5) are detected even with
    # low volumetrische signals (branching=1, tempo≈0, diversity=2-3)
    if use_phase_floor:
        phase_floor_value = phase_floor(state.current_phase.value)
        total_score = max(total_score, phase_floor_value)
    
    return min(total_score, 1.0)


def detect_killchain_campaign(
    events: List[ToolEvent],
    session_id: str,
    operator_id: Optional[str] = None,
    tool_categories: Dict[str, KillChainPhase] = None,
    risk_threshold: float = 0.5,
    use_phase_floor: bool = True,
) -> Tuple[KillChainState, Dict[str, any]]:
    """
    Detect kill-chain campaign from tool event sequence.
    
    Args:
        events: List of tool events
        session_id: Session identifier
        operator_id: Operator/API key identifier
        tool_categories: Tool-to-phase mapping
        risk_threshold: Risk score threshold for alerting
        
    Returns:
        Tuple of (final state, detection report)
    """
    state = KillChainState(session_id=session_id, operator_id=operator_id)
    
    # Process events in order
    for event in events:
        state = update_killchain_state(
            state,
            event,
            tool_categories,
            use_phase_floor=use_phase_floor,
        )
    
    # Build detection report
    report = {
        "session_id": session_id,
        "operator_id": operator_id,
        "risk_score": state.risk_score,
        "phase_depth": state.current_phase.value,
        "phase_name": state.current_phase.name,
        "phases_reached": [p.name for p in sorted(state.phase_reached)],
        "branching_factor": state.branching_factor,
        "tempo": state.tempo,
        "tool_diversity": state.tool_diversity,
        "target_count": len(state.targets),
        "tool_count": len(state.tool_events),
        "is_campaign": state.risk_score >= risk_threshold,
        "signals": [],
    }
    
    # Add specific signals
    if state.current_phase >= KillChainPhase.EXPLOIT_DEVELOPMENT:
        report["signals"].append("exploit_phase_reached")
    
    if state.branching_factor >= 3:
        report["signals"].append("high_branching_factor")
    
    if state.tempo >= 5.0:
        report["signals"].append("high_tempo")
    
    if state.tool_diversity >= 5:
        report["signals"].append("high_tool_diversity")
    
    if len(state.targets) >= 5:
        report["signals"].append("multi_target_campaign")
    
    return state, report


# Convenience function for integration
def scan_tool_events(
    events: List[ToolEvent],
    session_id: str,
    operator_id: Optional[str] = None,
    use_phase_floor: bool = True,
) -> List[str]:
    """
    Scan tool events and return detection signals.
    
    Compatible with existing detector interface (returns List[str]).
    
    Args:
        events: List of tool events
        session_id: Session identifier
        operator_id: Operator identifier
        
    Returns:
        List of signal strings (e.g., ["killchain_phase_3", "high_tempo"])
    """
    state, report = detect_killchain_campaign(
        events,
        session_id,
        operator_id,
        use_phase_floor=use_phase_floor,
    )
    
    signals = []
    
    # Phase-based signals
    if state.current_phase >= KillChainPhase.RECONNAISSANCE:
        signals.append(f"killchain_recon")
    
    if state.current_phase >= KillChainPhase.EXPLOIT_DEVELOPMENT:
        signals.append(f"killchain_exploit")
    
    if state.current_phase >= KillChainPhase.LATERAL_MOVEMENT:
        signals.append(f"killchain_lateral")
    
    if state.current_phase >= KillChainPhase.DATA_COLLECTION:
        signals.append(f"killchain_exfil")
    
    # Metric-based signals
    if state.branching_factor >= 3:
        signals.append("killchain_multi_target")
    
    if state.tempo >= 5.0:
        signals.append("killchain_high_tempo")
    
    if state.risk_score >= 0.5:
        signals.append("killchain_campaign_detected")
    
    return signals

