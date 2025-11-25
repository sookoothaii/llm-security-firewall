"""
Campaign Graph (RC10: Multi-Target Campaign Detection)
========================================================

DAG-based tracking of multi-target cyber campaigns.

Based on Anthropic Report (2025): Campaigns involve:
- Multiple targets in parallel
- Phase progression per target
- Time-to-phase transitions
- Cross-target relationships

Graph Structure:
- Nodes: Target × Phase (e.g., "corpA.com@recon", "corpA.com@exploit")
- Edges: Phase transitions triggered by tool events
- Features: Target count, phase depth, transition times

Creator: Joerg Bollwahn (with GPT-5.1 analysis)
Date: 2025-11-17
License: MIT
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from llm_firewall.detectors.tool_killchain import KillChainPhase, ToolEvent


@dataclass(frozen=True)
class CampaignNode:
    """Node in campaign graph: Target × Phase."""

    target: str
    phase: KillChainPhase

    def __str__(self) -> str:
        return f"{self.target}@{self.phase.name.lower()}"


@dataclass
class CampaignEdge:
    """Edge in campaign graph: Phase transition."""

    source: CampaignNode
    target: CampaignNode
    timestamp: float
    tool: str
    event_id: Optional[str] = None


@dataclass
class CampaignGraph:
    """
    DAG tracking multi-target campaign progression.

    Nodes represent target-phase combinations.
    Edges represent phase transitions.
    """

    campaign_id: str  # Operator ID or session group ID
    nodes: Set[CampaignNode] = field(default_factory=set)
    edges: List[CampaignEdge] = field(default_factory=list)

    # Target tracking
    targets: Set[str] = field(default_factory=set)
    target_max_phase: Dict[str, KillChainPhase] = field(default_factory=dict)
    target_first_seen: Dict[str, float] = field(default_factory=dict)
    target_phase_times: Dict[Tuple[str, KillChainPhase], float] = field(
        default_factory=dict
    )

    # Metrics
    max_phase_reached: KillChainPhase = KillChainPhase.INITIALIZATION
    targets_at_phase: Dict[KillChainPhase, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    avg_time_to_phase: Dict[KillChainPhase, float] = field(default_factory=dict)

    # Risk features
    risk_score: float = 0.0
    last_update: float = field(default_factory=time.time)


def add_tool_event_to_graph(
    graph: CampaignGraph,
    event: ToolEvent,
    phase: Optional[KillChainPhase] = None,
) -> CampaignGraph:
    """
    Add tool event to campaign graph.

    Args:
        graph: Current campaign graph
        event: Tool event
        phase: Kill-chain phase (if None, will be inferred)

    Returns:
        Updated graph
    """
    if not event.target:
        # No target, skip
        return graph

    target = event.target
    now = event.timestamp

    # Track target
    graph.targets.add(target)

    if target not in graph.target_first_seen:
        graph.target_first_seen[target] = now

    # Determine phase (if not provided)
    if phase is None:
        # Simple heuristic: try to infer from tool name/category
        tool_lower = event.tool.lower()
        if any(x in tool_lower for x in ["scan", "nmap", "recon"]):
            phase = KillChainPhase.RECONNAISSANCE
        elif any(x in tool_lower for x in ["exploit", "vuln", "cve"]):
            phase = KillChainPhase.EXPLOIT_DEVELOPMENT
        elif any(x in tool_lower for x in ["credential", "ssh", "lateral"]):
            phase = KillChainPhase.LATERAL_MOVEMENT
        elif any(x in tool_lower for x in ["export", "read", "exfil"]):
            phase = KillChainPhase.DATA_COLLECTION
        else:
            phase = KillChainPhase.INITIALIZATION

    # Get current phase for target
    current_phase = graph.target_max_phase.get(target, KillChainPhase.INITIALIZATION)

    # Check if phase advanced
    if phase > current_phase:
        # Create nodes
        source_node = CampaignNode(target=target, phase=current_phase)
        target_node = CampaignNode(target=target, phase=phase)

        graph.nodes.add(source_node)
        graph.nodes.add(target_node)

        # Create edge
        edge = CampaignEdge(
            source=source_node,
            target=target_node,
            timestamp=now,
            tool=event.tool,
        )
        graph.edges.append(edge)

        # Update target phase
        graph.target_max_phase[target] = phase

        # Track phase transition time
        if (target, current_phase) in graph.target_phase_times:
            transition_time = now - graph.target_phase_times[(target, current_phase)]
            # Update average
            if phase not in graph.avg_time_to_phase:
                graph.avg_time_to_phase[phase] = transition_time
            else:
                # Simple moving average
                graph.avg_time_to_phase[phase] = (
                    graph.avg_time_to_phase[phase] * 0.7 + transition_time * 0.3
                )

        graph.target_phase_times[(target, phase)] = now

        # Update max phase
        if phase > graph.max_phase_reached:
            graph.max_phase_reached = phase

    # Update phase counts
    graph.targets_at_phase[phase] = sum(
        1 for t, p in graph.target_max_phase.items() if p >= phase
    )

    # Calculate risk score
    graph.risk_score = calculate_campaign_risk(graph)

    graph.last_update = now

    return graph


def calculate_campaign_risk(graph: CampaignGraph) -> float:
    """
    Calculate risk score from campaign graph features.

    Risk factors:
    - Number of targets reaching high phases
    - Maximum phase reached
    - Average time to phase (faster = higher risk)
    - Number of targets overall

    Returns:
        Risk score [0.0, 1.0]
    """
    # Phase depth component (0.0 - 0.3)
    phase_score = (graph.max_phase_reached.value / len(KillChainPhase)) * 0.3

    # Multi-target component (0.0 - 0.3)
    # Normalize: 1 target = 0.0, 10+ targets = 0.3
    target_score = min(len(graph.targets) / 10.0, 1.0) * 0.3

    # Targets at high phases (0.0 - 0.2)
    # Count targets at phase >= EXPLOIT_DEVELOPMENT
    high_phase_targets = graph.targets_at_phase.get(
        KillChainPhase.EXPLOIT_DEVELOPMENT, 0
    )
    high_phase_score = min(high_phase_targets / 5.0, 1.0) * 0.2

    # Transition speed component (0.0 - 0.2)
    # Faster transitions = higher risk
    speed_score = 0.0
    if graph.avg_time_to_phase:
        # Average time to reach EXPLOIT_DEVELOPMENT
        avg_time = graph.avg_time_to_phase.get(
            KillChainPhase.EXPLOIT_DEVELOPMENT, float("inf")
        )
        # Normalize: < 1 hour = 0.2, > 24 hours = 0.0
        if avg_time < 3600:  # 1 hour
            speed_score = 0.2
        elif avg_time < 86400:  # 24 hours
            speed_score = 0.2 * (1.0 - (avg_time - 3600) / 82800)

    total_score = phase_score + target_score + high_phase_score + speed_score

    return min(total_score, 1.0)


def get_campaign_features(graph: CampaignGraph) -> Dict[str, any]:
    """
    Extract features from campaign graph for ML/GuardNet integration.

    Returns:
        Dictionary of feature values
    """
    return {
        "target_count": len(graph.targets),
        "max_phase": graph.max_phase_reached.value,
        "targets_at_recon": graph.targets_at_phase.get(
            KillChainPhase.RECONNAISSANCE, 0
        ),
        "targets_at_exploit": graph.targets_at_phase.get(
            KillChainPhase.EXPLOIT_DEVELOPMENT, 0
        ),
        "targets_at_lateral": graph.targets_at_phase.get(
            KillChainPhase.LATERAL_MOVEMENT, 0
        ),
        "targets_at_exfil": graph.targets_at_phase.get(
            KillChainPhase.DATA_COLLECTION, 0
        ),
        "avg_time_to_exploit": graph.avg_time_to_phase.get(
            KillChainPhase.EXPLOIT_DEVELOPMENT, 0.0
        ),
        "avg_time_to_lateral": graph.avg_time_to_phase.get(
            KillChainPhase.LATERAL_MOVEMENT, 0.0
        ),
        "edge_count": len(graph.edges),
        "node_count": len(graph.nodes),
        "risk_score": graph.risk_score,
    }


def detect_multi_target_campaign(
    events: List[ToolEvent],
    campaign_id: str,
    phase_mapping: Optional[Dict[str, KillChainPhase]] = None,
) -> Tuple[CampaignGraph, Dict[str, any]]:
    """
    Build campaign graph from tool events.

    Args:
        events: List of tool events
        campaign_id: Campaign identifier (operator ID or session group)
        phase_mapping: Optional tool-to-phase mapping

    Returns:
        Tuple of (campaign graph, detection report)
    """
    graph = CampaignGraph(campaign_id=campaign_id)

    # Process events in order
    for event in events:
        # Determine phase
        phase = None
        if phase_mapping:
            phase = phase_mapping.get(event.tool) or phase_mapping.get(event.category)

        graph = add_tool_event_to_graph(graph, event, phase)

    # Build detection report
    features = get_campaign_features(graph)

    report = {
        "campaign_id": campaign_id,
        "risk_score": graph.risk_score,
        "target_count": len(graph.targets),
        "max_phase": graph.max_phase_reached.name,
        "features": features,
        "is_campaign": graph.risk_score >= 0.5,
        "signals": [],
    }

    # Add specific signals
    if len(graph.targets) >= 3:
        report["signals"].append("multi_target_campaign")

    if graph.max_phase_reached >= KillChainPhase.EXPLOIT_DEVELOPMENT:
        report["signals"].append("campaign_exploit_phase")

    if graph.targets_at_phase.get(KillChainPhase.EXPLOIT_DEVELOPMENT, 0) >= 2:
        report["signals"].append("campaign_multi_exploit")

    if graph.risk_score >= 0.7:
        report["signals"].append("campaign_high_risk")

    return graph, report
