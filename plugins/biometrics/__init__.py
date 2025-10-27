"""
Cultural Biometrics Plugin for LLM Security Firewall
Version: 1.0.0
Creator: Joerg Bollwahn

27-Dimensional behavioral authentication for LLM interfaces.

WORLD-FIRST: Behavioral authentication specifically designed for
Human/LLM interaction patterns.

PRIVACY-FIRST DESIGN:
- NO personal behavioral data included
- Users must provide their own database
- Framework only, not trained baselines

Usage:
    from llm_firewall.plugins.biometrics import BiometricsModule
    
    biometrics = BiometricsModule(db_connection=your_db)
    auth_result = biometrics.authenticate(user_id, message)
"""

from .biometrics_module import BiometricsModule
from .biometrics_port import BiometricsPort, BiometricProfile
from .biometrics_adapter import PostgreSQLBiometricsAdapter

__all__ = ['BiometricsModule', 'BiometricsPort', 'BiometricProfile', 'PostgreSQLBiometricsAdapter']
__version__ = '1.0.0'

