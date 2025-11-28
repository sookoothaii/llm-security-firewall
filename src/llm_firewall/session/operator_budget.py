"""
Operator Risk Budget (RC10: Operator-Level Campaign Detection)
================================================================

Tracks risk budget per operator/API-key across sessions to detect
autonomous cyber campaigns.

Based on Anthropic Report (2025): Operators show patterns like:
- High volume (thousands of requests)
- High tempo (multiple ops/second)
- Parallel target operations
- Minimal human involvement

Mathematical Foundation:
- EWMA/CUSUM tracking per operator
- Budget limits for tool categories (net_scan, exploit, etc.)
- Auto-strict guard when budget exceeded
- Integration with Kill-Chain Monitor

Creator: Joerg Bollwahn (with GPT-5.1 analysis)
Date: 2025-11-17
License: MIT
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from llm_firewall.detectors.tool_killchain import ToolEvent


@dataclass
class OperatorBudget:
    """
    Risk budget for a single operator/API-key.

    Tracks tool usage across sessions with time-windowed limits.
    """

    operator_id: str

    # Budget limits (per 24h window)
    max_net_scan: int = 100
    max_exploit: int = 10
    max_lateral: int = 20
    max_exfil: int = 5
    max_parallel_targets: int = 5

    # Current usage (rolling 24h window)
    net_scan_count: int = 0
    exploit_count: int = 0
    lateral_count: int = 0
    exfil_count: int = 0
    parallel_targets: Set[str] = field(default_factory=set)

    # Time tracking
    window_start: float = field(default_factory=time.time)
    window_duration: float = 86400.0  # 24 hours

    # EWMA tracking
    ewma_tempo: float = 0.0  # Exponential weighted moving average of events/sec
    ewma_alpha: float = 0.1  # Smoothing factor

    # Alert state
    budget_exceeded: bool = False
    auto_strict_active: bool = False
    auto_strict_until: float = 0.0
    auto_strict_duration: float = 300.0  # 5 minutes

    # Session tracking
    active_sessions: Set[str] = field(default_factory=set)
    total_sessions: int = 0

    last_update: float = field(default_factory=time.time)


# Tool category to budget counter mapping
TOOL_CATEGORY_TO_BUDGET = {
    "net_scan": "net_scan_count",
    "port_scan": "net_scan_count",
    "service_scan": "net_scan_count",
    "recon": "net_scan_count",
    "exploit": "exploit_count",
    "vuln_scan": "exploit_count",
    "exploit_framework": "exploit_count",
    "lateral": "lateral_count",
    "credential_test": "lateral_count",
    "privilege_escalation": "lateral_count",
    "exfil": "exfil_count",
    "data_export": "exfil_count",
    "file_read": "exfil_count",
}


def update_operator_budget(
    budget: OperatorBudget,
    event: ToolEvent,
    session_id: str,
) -> OperatorBudget:
    """
    Update operator budget with new tool event.

    Args:
        budget: Current operator budget
        event: New tool event
        session_id: Current session identifier

    Returns:
        Updated budget
    """
    now = event.timestamp

    # Reset window if expired
    if now - budget.window_start >= budget.window_duration:
        budget.net_scan_count = 0
        budget.exploit_count = 0
        budget.lateral_count = 0
        budget.exfil_count = 0
        budget.parallel_targets.clear()
        budget.window_start = now
        budget.budget_exceeded = False

    # Track session
    budget.active_sessions.add(session_id)
    if session_id not in budget.active_sessions:
        budget.total_sessions += 1

    # Map tool category to budget counter
    category = event.category.lower()
    counter_name = None

    for cat_key, counter in TOOL_CATEGORY_TO_BUDGET.items():
        if cat_key in category:
            counter_name = counter
            break

    # Update counters
    if counter_name == "net_scan_count":
        budget.net_scan_count += 1
    elif counter_name == "exploit_count":
        budget.exploit_count += 1
    elif counter_name == "lateral_count":
        budget.lateral_count += 1
    elif counter_name == "exfil_count":
        budget.exfil_count += 1

    # Track parallel targets
    if event.target:
        budget.parallel_targets.add(event.target)

    # Update EWMA tempo
    if len(budget.active_sessions) > 0:
        # Estimate events per second from recent activity
        # Simple heuristic: assume 1 event per active session per second
        current_tempo = len(budget.active_sessions)
        if budget.ewma_tempo == 0.0:
            budget.ewma_tempo = current_tempo
        else:
            budget.ewma_tempo = (budget.ewma_alpha * current_tempo) + (
                (1 - budget.ewma_alpha) * budget.ewma_tempo
            )

    # Check budget limits
    budget.budget_exceeded = (
        budget.net_scan_count > budget.max_net_scan
        or budget.exploit_count > budget.max_exploit
        or budget.lateral_count > budget.max_lateral
        or budget.exfil_count > budget.max_exfil
        or len(budget.parallel_targets) > budget.max_parallel_targets
    )

    # Activate auto-strict if budget exceeded
    if budget.budget_exceeded and not budget.auto_strict_active:
        budget.auto_strict_active = True
        budget.auto_strict_until = now + budget.auto_strict_duration

    # Deactivate auto-strict if duration expired
    if budget.auto_strict_active and now >= budget.auto_strict_until:
        budget.auto_strict_active = False

    budget.last_update = now

    return budget


def check_operator_budget(
    operator_id: str,
    event: ToolEvent,
    session_id: str,
    budgets: Dict[str, OperatorBudget],
    default_limits: Optional[Dict[str, int]] = None,
) -> Tuple[OperatorBudget, Dict[str, Any]]:
    """
    Check and update operator budget, return status.

    Args:
        operator_id: Operator identifier
        event: Tool event
        session_id: Session identifier
        budgets: Dictionary of operator budgets
        default_limits: Optional custom budget limits

    Returns:
        Tuple of (updated budget, status report)
    """
    # Get or create budget
    if operator_id not in budgets:
        budget = OperatorBudget(operator_id=operator_id)
        if default_limits:
            budget.max_net_scan = default_limits.get("max_net_scan", 100)
            budget.max_exploit = default_limits.get("max_exploit", 10)
            budget.max_lateral = default_limits.get("max_lateral", 20)
            budget.max_exfil = default_limits.get("max_exfil", 5)
            budget.max_parallel_targets = default_limits.get("max_parallel_targets", 5)
        budgets[operator_id] = budget
    else:
        budget = budgets[operator_id]

    # Update budget
    budget = update_operator_budget(budget, event, session_id)
    budgets[operator_id] = budget

    # Build status report
    report = {
        "operator_id": operator_id,
        "budget_exceeded": budget.budget_exceeded,
        "auto_strict_active": budget.auto_strict_active,
        "counters": {
            "net_scan": budget.net_scan_count,
            "exploit": budget.exploit_count,
            "lateral": budget.lateral_count,
            "exfil": budget.exfil_count,
            "parallel_targets": len(budget.parallel_targets),
        },
        "limits": {
            "max_net_scan": budget.max_net_scan,
            "max_exploit": budget.max_exploit,
            "max_lateral": budget.max_lateral,
            "max_exfil": budget.max_exfil,
            "max_parallel_targets": budget.max_parallel_targets,
        },
        "ewma_tempo": budget.ewma_tempo,
        "active_sessions": len(budget.active_sessions),
        "total_sessions": budget.total_sessions,
        "signals": [],
    }
    signals: List[str] = []

    # Add signals
    if budget.budget_exceeded:
        signals.append("operator_budget_exceeded")

    if budget.auto_strict_active:
        signals.append("operator_auto_strict_active")

    if budget.net_scan_count > budget.max_net_scan * 0.8:
        signals.append("operator_net_scan_warning")

    if budget.exploit_count > budget.max_exploit * 0.8:
        signals.append("operator_exploit_warning")

    if budget.ewma_tempo > 5.0:
        signals.append("operator_high_tempo")

    if len(budget.active_sessions) > 10:
        signals.append("operator_high_session_count")

    report["signals"] = signals  # type: ignore[assignment]

    return budget, report


def get_operator_risk_score(budget: OperatorBudget) -> float:
    """
    Calculate overall risk score for operator.

    Returns:
        Risk score [0.0, 1.0]
    """
    # Budget utilization component (0.0 - 0.4)
    net_scan_util = min(budget.net_scan_count / budget.max_net_scan, 1.0)
    exploit_util = min(budget.exploit_count / budget.max_exploit, 1.0)
    lateral_util = min(budget.lateral_count / budget.max_lateral, 1.0)
    exfil_util = min(budget.exfil_count / budget.max_exfil, 1.0)
    parallel_util = min(len(budget.parallel_targets) / budget.max_parallel_targets, 1.0)

    max_util = max(net_scan_util, exploit_util, lateral_util, exfil_util, parallel_util)
    budget_score = max_util * 0.4

    # Tempo component (0.0 - 0.3)
    # Normalize: 0.1 ops/s = 0.0, 10 ops/s = 0.3
    tempo_score = min(budget.ewma_tempo / 10.0, 1.0) * 0.3

    # Session count component (0.0 - 0.3)
    # Normalize: 1 session = 0.0, 20+ sessions = 0.3
    session_score = min(len(budget.active_sessions) / 20.0, 1.0) * 0.3

    total_score = budget_score + tempo_score + session_score

    return min(total_score, 1.0)
