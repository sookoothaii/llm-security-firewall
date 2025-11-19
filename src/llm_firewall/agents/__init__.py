"""
Agent Behavioral Firewall (RC10b)
==================================

Behavioral detection layer for agentic LLM systems.

Detects multi-turn attack campaigns by analyzing tool invocation patterns
over time, preventing Low-&-Slow attacks (GTG-1002) through High-Watermark logic.

Creator: Joerg Bollwahn
Date: 2025-11-18
License: MIT
"""

from .config import RC10bConfig
from .detector import AgenticCampaignDetector, CampaignResult
from .state import CampaignStateStore, InMemoryStateStore

__all__ = [
    "RC10bConfig",
    "AgenticCampaignDetector",
    "CampaignResult",
    "CampaignStateStore",
    "InMemoryStateStore",
]

