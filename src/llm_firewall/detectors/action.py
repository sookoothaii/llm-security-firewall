"""
Action Enum for Campaign Detection (RC10b)
==========================================

Defines the action hierarchy for campaign decisions.
Used to ensure unambiguous final decisions per campaign.

Creator: Joerg Bollwahn
Date: 2025-11-17
License: MIT
"""

from enum import IntEnum


class Action(IntEnum):
    """
    Action hierarchy for campaign decisions.
    
    Higher values = more severe actions.
    Used for unambiguous aggregation over events.
    """
    ALLOW = 0
    WARN = 1
    REQUIRE_APPROVAL = 2
    BLOCK = 3
    
    def __str__(self) -> str:
        return self.name
    
    @classmethod
    def from_string(cls, s: str) -> "Action":
        """Convert string to Action enum."""
        s_upper = s.upper()
        if s_upper == "PASS":
            return cls.ALLOW
        elif s_upper == "WARN":
            return cls.WARN
        elif s_upper == "REQUIRE_APPROVAL":
            return cls.REQUIRE_APPROVAL
        elif s_upper == "BLOCK":
            return cls.BLOCK
        else:
            raise ValueError(f"Unknown action string: {s}")
    
    def to_string(self) -> str:
        """Convert Action enum to string (for compatibility)."""
        if self == Action.ALLOW:
            return "PASS"
        return self.name

