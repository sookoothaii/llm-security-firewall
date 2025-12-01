"""
Test data factories for generating test objects.
"""

from typing import Dict, Any, Optional, List
from llm_firewall.core.firewall_engine_v2 import FirewallDecision


def create_firewall_decision(
    allowed: bool = True,
    reason: str = "Test decision",
    risk_score: float = 0.0,
    detected_threats: Optional[List[str]] = None,
    sanitized_text: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> FirewallDecision:
    """
    Create a FirewallDecision for testing.

    Args:
        allowed: Whether request is allowed
        reason: Human-readable reason
        risk_score: Risk score [0.0, 1.0]
        detected_threats: List of threat types
        sanitized_text: Sanitized version of text
        metadata: Additional metadata

    Returns:
        FirewallDecision instance.
    """
    return FirewallDecision(
        allowed=allowed,
        reason=reason,
        risk_score=risk_score,
        detected_threats=detected_threats or [],
        sanitized_text=sanitized_text,
        metadata=metadata or {},
    )


def create_allowed_decision(reason: str = "Legitimate request") -> FirewallDecision:
    """Create an ALLOW decision."""
    return create_firewall_decision(allowed=True, reason=reason, risk_score=0.0)


def create_blocked_decision(
    reason: str = "Security policy violation",
    risk_score: float = 0.8,
    detected_threats: Optional[List[str]] = None,
) -> FirewallDecision:
    """Create a BLOCK decision."""
    return create_firewall_decision(
        allowed=False,
        reason=reason,
        risk_score=risk_score,
        detected_threats=detected_threats or ["pattern_match"],
    )


def create_cached_decision_dict(
    allowed: bool = True,
    reason: str = "Cached decision",
    risk_score: float = 0.0,
) -> Dict[str, Any]:
    """
    Create a cached decision dictionary (as stored in Redis/LangCache).

    Args:
        allowed: Whether request is allowed
        reason: Human-readable reason
        risk_score: Risk score [0.0, 1.0]

    Returns:
        Dictionary representation of decision.
    """
    return {
        "allowed": allowed,
        "reason": reason,
        "risk_score": risk_score,
        "detected_threats": [],
        "metadata": {},
    }


def create_tool_call(
    name: str,
    arguments: Dict[str, Any],
    tool_call_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a tool call dictionary for Protocol HEPHAESTUS testing.

    Args:
        name: Tool name
        arguments: Tool arguments
        tool_call_id: Optional tool call ID

    Returns:
        Tool call dictionary.
    """
    import json

    return {
        "type": "function",
        "function": {
            "name": name,
            "arguments": json.dumps(arguments),
        },
        "id": tool_call_id or f"call_{name}_{hash(str(arguments))}",
    }


def create_malicious_tool_call() -> Dict[str, Any]:
    """Create a malicious tool call (e.g., write to /etc/passwd)."""
    return create_tool_call(
        name="write_file",
        arguments={
            "path": "/etc/passwd",
            "content": "malicious content",
        },
    )


def create_legitimate_tool_call() -> Dict[str, Any]:
    """Create a legitimate tool call (e.g., read file)."""
    return create_tool_call(
        name="read_file",
        arguments={
            "path": "test.txt",
        },
    )
