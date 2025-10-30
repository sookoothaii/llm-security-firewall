"""
Base Judge Protocols
====================

Interface definitions for multi-agent judges.

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

from typing import Protocol

from llm_firewall.core.types import JudgeReport, ModelContext


class Judge(Protocol):
    """
    Base protocol for all judges.
    
    Each judge provides independent risk assessment.
    Must be deterministic for same seed/input.
    """
    name: str
    version: str

    def score(self, ctx: ModelContext, prompt: str, draft: str) -> JudgeReport:
        """
        Score prompt/draft for risk.
        
        Args:
            ctx: Request context (session, user, model, etc.)
            prompt: User input
            draft: LLM response draft
            
        Returns:
            JudgeReport with calibrated risk
        """
        ...


