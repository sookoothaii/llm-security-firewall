"""
CARE (Cognitive And Research Effectiveness) Plugin
Version: 1.0.0
Creator: Joerg Bollwahn

Cognitive readiness assessment for optimal research sessions.

PRIVACY-FIRST DESIGN:
- NO personal cognitive data included
- Users must provide their own database
- Framework only, not trained models

Usage:
    from llm_firewall.plugins.care import CAREModule

    care = CAREModule(db_connection=your_db)
    readiness = care.get_readiness(user_id)
"""

from .care_adapter import PostgreSQLCAREAdapter
from .care_module import CAREModule
from .care_port import CAREPort, ReadinessScore

__all__ = ["CAREModule", "CAREPort", "ReadinessScore", "PostgreSQLCAREAdapter"]
__version__ = "1.0.0"
