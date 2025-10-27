"""
Personality Plugin for LLM Security Firewall
Version: 1.0.0
Creator: Joerg Bollwahn

This plugin provides personality-aware security adaptations.

PRIVACY-FIRST DESIGN:
- NO personal data included
- Users must provide their own database
- Framework only, not trained models

Usage:
    from llm_firewall.plugins.personality import PersonalityModule
    
    personality = PersonalityModule(db_connection=your_db)
    profile = personality.get_personality_profile(user_id)
"""

from .personality_module import PersonalityModule
from .personality_port import PersonalityPort
from .personality_adapter import PostgreSQLPersonalityAdapter

__all__ = ['PersonalityModule', 'PersonalityPort', 'PostgreSQLPersonalityAdapter']
__version__ = '1.0.0'

