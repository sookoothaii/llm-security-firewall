"""
Autonomy Heuristics (RC10: Agent-Mode Detection)
=================================================

Detects autonomous agent behavior patterns.

Based on Anthropic Report (2025): Claude ran in agent mode with:
- Many tools, few explanatory texts
- High request rate
- Long campaigns
- Minimal human intervention

Metrics:
- Requests per minute/hour
- Token ratio (input/output)
- Tool-call ratio
- Latency patterns

Creator: Joerg Bollwahn (with GPT-5.1 analysis)
Date: 2025-11-17
License: MIT
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional


@dataclass
class RequestMetrics:
    """Metrics for a single request."""
    
    timestamp: float
    tokens_in: int
    tokens_out: int
    tool_calls: int
    has_human_question: bool = False  # User asked clarifying question
    latency_ms: float = 0.0


@dataclass
class AutonomyState:
    """State tracking for autonomy detection."""
    
    session_id: str
    operator_id: Optional[str] = None
    
    # Request history (rolling window)
    requests: Deque[RequestMetrics] = field(default_factory=lambda: deque(maxlen=100))
    
    # Aggregated metrics
    requests_per_minute: float = 0.0
    requests_per_hour: float = 0.0
    avg_token_ratio: float = 0.0  # tokens_in / tokens_out
    tool_call_ratio: float = 0.0  # requests_with_tools / total_requests
    human_intervention_ratio: float = 0.0  # requests_with_questions / total_requests
    avg_latency_ms: float = 0.0
    
    # Autonomy score
    autonomy_score: float = 0.0
    
    # Time tracking
    window_start: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)


def update_autonomy_state(
    state: AutonomyState,
    metrics: RequestMetrics,
    window_minutes: int = 60,
) -> AutonomyState:
    """
    Update autonomy state with new request metrics.
    
    Args:
        state: Current autonomy state
        metrics: New request metrics
        window_minutes: Rolling window size in minutes
        
    Returns:
        Updated state
    """
    now = metrics.timestamp
    
    # Add request to history
    state.requests.append(metrics)
    
    # Remove old requests outside window
    window_start = now - (window_minutes * 60)
    while state.requests and state.requests[0].timestamp < window_start:
        state.requests.popleft()
    
    # Calculate metrics
    if len(state.requests) > 0:
        # Requests per minute (last minute)
        minute_ago = now - 60
        recent_requests = [r for r in state.requests if r.timestamp >= minute_ago]
        state.requests_per_minute = len(recent_requests)
        
        # Requests per hour (last hour)
        hour_ago = now - 3600
        recent_requests_hour = [r for r in state.requests if r.timestamp >= hour_ago]
        state.requests_per_hour = len(recent_requests_hour)
        
        # Average token ratio
        if sum(r.tokens_out for r in state.requests) > 0:
            total_in = sum(r.tokens_in for r in state.requests)
            total_out = sum(r.tokens_out for r in state.requests)
            state.avg_token_ratio = total_in / total_out
        else:
            state.avg_token_ratio = float("inf") if state.requests else 0.0
        
        # Tool call ratio
        requests_with_tools = sum(1 for r in state.requests if r.tool_calls > 0)
        state.tool_call_ratio = requests_with_tools / len(state.requests)
        
        # Human intervention ratio
        requests_with_questions = sum(1 for r in state.requests if r.has_human_question)
        state.human_intervention_ratio = requests_with_questions / len(state.requests)
        
        # Average latency
        state.avg_latency_ms = sum(r.latency_ms for r in state.requests) / len(state.requests)
    
    # Calculate autonomy score
    state.autonomy_score = calculate_autonomy_score(state)
    
    state.last_update = now
    
    return state


def calculate_autonomy_score(state: AutonomyState) -> float:
    """
    Calculate autonomy score from state metrics.
    
    Higher score = more autonomous/agent-like behavior.
    
    Returns:
        Autonomy score [0.0, 1.0]
    """
    # Request rate component (0.0 - 0.3)
    # Normalize: 1 req/min = 0.0, 10+ req/min = 0.3
    rate_score = min(state.requests_per_minute / 10.0, 1.0) * 0.3
    
    # Token ratio component (0.0 - 0.2)
    # High input, low output = agent mode
    # Normalize: ratio > 5.0 = 0.2, ratio < 1.0 = 0.0
    if state.avg_token_ratio > 5.0:
        token_score = 0.2
    elif state.avg_token_ratio > 1.0:
        token_score = (state.avg_token_ratio - 1.0) / 4.0 * 0.2
    else:
        token_score = 0.0
    
    # Tool call ratio component (0.0 - 0.2)
    # High tool usage = agent mode
    # Normalize: > 0.8 = 0.2, < 0.2 = 0.0
    if state.tool_call_ratio > 0.8:
        tool_score = 0.2
    elif state.tool_call_ratio > 0.2:
        tool_score = (state.tool_call_ratio - 0.2) / 0.6 * 0.2
    else:
        tool_score = 0.0
    
    # Human intervention component (0.0 - 0.15)
    # Low human intervention = agent mode
    # Normalize: < 0.1 = 0.15, > 0.5 = 0.0
    if state.human_intervention_ratio < 0.1:
        intervention_score = 0.15
    elif state.human_intervention_ratio < 0.5:
        intervention_score = 0.15 * (1.0 - (state.human_intervention_ratio - 0.1) / 0.4)
    else:
        intervention_score = 0.0
    
    # Latency pattern component (0.0 - 0.15)
    # Very short, consistent latency = automation
    # Normalize: < 100ms avg = 0.15, > 1000ms = 0.0
    if state.avg_latency_ms < 100:
        latency_score = 0.15
    elif state.avg_latency_ms < 1000:
        latency_score = 0.15 * (1.0 - (state.avg_latency_ms - 100) / 900)
    else:
        latency_score = 0.0
    
    total_score = rate_score + token_score + tool_score + intervention_score + latency_score
    
    return min(total_score, 1.0)


def detect_autonomous_agent(
    requests: List[RequestMetrics],
    session_id: str,
    operator_id: Optional[str] = None,
) -> Tuple[AutonomyState, Dict[str, any]]:
    """
    Detect autonomous agent behavior from request history.
    
    Args:
        requests: List of request metrics
        session_id: Session identifier
        operator_id: Operator identifier
        
    Returns:
        Tuple of (autonomy state, detection report)
    """
    state = AutonomyState(session_id=session_id, operator_id=operator_id)
    
    # Process requests in order
    for metrics in requests:
        state = update_autonomy_state(state, metrics)
    
    # Build detection report
    report = {
        "session_id": session_id,
        "operator_id": operator_id,
        "autonomy_score": state.autonomy_score,
        "requests_per_minute": state.requests_per_minute,
        "requests_per_hour": state.requests_per_hour,
        "avg_token_ratio": state.avg_token_ratio,
        "tool_call_ratio": state.tool_call_ratio,
        "human_intervention_ratio": state.human_intervention_ratio,
        "avg_latency_ms": state.avg_latency_ms,
        "is_autonomous": state.autonomy_score >= 0.8,
        "signals": [],
    }
    
    # Add specific signals
    if state.requests_per_minute >= 5:
        report["signals"].append("high_request_rate")
    
    if state.avg_token_ratio >= 5.0:
        report["signals"].append("high_input_output_ratio")
    
    if state.tool_call_ratio >= 0.8:
        report["signals"].append("high_tool_usage")
    
    if state.human_intervention_ratio < 0.1:
        report["signals"].append("low_human_intervention")
    
    if state.autonomy_score >= 0.8:
        report["signals"].append("autonomous_agent_detected")
    
    return state, report

