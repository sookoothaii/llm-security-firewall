"""
Tool Guard Types
================

Type definitions for tool call context tracking (scaffolding for future tool-abuse evaluation).

This module defines data structures for logging tool calls and their context,
which can later be integrated into decision logs for analysis.

Author: Joerg Bollwahn
Date: 2025-12-03
License: MIT
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class ToolCallContext:
    """
    Context information for a single tool call.

    This is a scaffolding structure for future tool-abuse evaluation.
    Currently, this is not integrated into the firewall engine.
    """

    tool_name: str
    arguments: Dict[str, Any]
    timestamp: Optional[float] = None
    dangerous_pattern_flags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "timestamp": self.timestamp,
            "dangerous_pattern_flags": self.dangerous_pattern_flags,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolCallContext":
        """Create from dictionary."""
        return cls(
            tool_name=data.get("tool_name", ""),
            arguments=data.get("arguments", {}),
            timestamp=data.get("timestamp"),
            dangerous_pattern_flags=data.get("dangerous_pattern_flags", []),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ToolCallSession:
    """
    Collection of tool calls within a session/request.

    This represents all tool calls made during a single user request.
    """

    session_id: str
    tool_calls: List[ToolCallContext] = field(default_factory=list)
    total_calls: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_tool_call(self, context: ToolCallContext) -> None:
        """Add a tool call to the session."""
        self.tool_calls.append(context)
        self.total_calls += 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "session_id": self.session_id,
            "tool_calls": [tc.to_dict() for tc in self.tool_calls],
            "total_calls": self.total_calls,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolCallSession":
        """Create from dictionary."""
        session = cls(
            session_id=data.get("session_id", ""),
            total_calls=0,  # Will be set correctly by add_tool_call
            metadata=data.get("metadata", {}),
        )
        for tc_data in data.get("tool_calls", []):
            session.add_tool_call(ToolCallContext.from_dict(tc_data))
        return session
