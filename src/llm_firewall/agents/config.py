"""
RC10b Configuration
===================

Configuration for the RC10b Agent Behavioral Firewall.

Includes High-Watermark logic to prevent Low-&-Slow attacks (GTG-1002).
"""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class RC10bConfig:
    """
    Configuration for the RC10b Agent Behavioral Firewall.

    RC10b Enhancements:
    - High-Watermark: Prevents dilution by noise events (GTG-1002 Fix)
    - Aggressive Phase-Floors: Phase 4 (Exfiltration/Impact) → 0.85
    - Configurable Category-Mappings

    Args:
        use_policy_layer: Enable policy-based action decisions
        use_scope_mismatch: Enable scope mismatch detection
        use_high_watermark: Enable High-Watermark logic (CRITICAL: Prevents dilution)
        use_phase_floor: Enable phase-based risk floors
        threshold_warn: Risk threshold for WARN action
        threshold_block: Risk threshold for BLOCK action
        phase_floors: Mapping of kill-chain phase to minimum risk score
        category_map: Mapping of tool category to kill-chain phase
    """

    # Feature Flags
    use_policy_layer: bool = True
    use_scope_mismatch: bool = True
    use_high_watermark: bool = True  # CRITICAL: Prevents dilution
    use_phase_floor: bool = True

    # Thresholds
    threshold_warn: float = 0.35
    threshold_block: float = 0.55

    # Kill-Chain Floors: Phase -> Min Score
    # Phase 3 (Collection) -> Warn, Phase 4 (Exfil) -> Block
    phase_floors: Dict[int, float] = field(
        default_factory=lambda: {
            3: 0.50,  # Collection, Credential Access, Privilege Escalation
            4: 0.85,  # Exfiltration, Impact, Defense Evasion (Sofort BLOCK)
        }
    )

    # Mapping: Tool Category -> Kill Chain Phase (1-4)
    category_map: Dict[str, int] = field(
        default_factory=lambda: {
            "recon": 1,
            "discovery": 1,
            "read": 1,
            "initial_access": 2,
            "execution": 2,
            "persistence": 2,
            "weaponization": 2,
            "write": 2,
            "credential_access": 3,
            "collection": 3,
            "privilege_escalation": 3,
            "lateral_movement": 3,
            "exfiltration": 4,
            "impact": 4,
            "defense_evasion": 4,
            "command_and_control": 4,
            "delete": 4,
        }
    )
