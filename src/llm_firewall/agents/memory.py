"""
Hierarchical Session Memory (Kimi k2 Architecture)
===================================================

Intelligent memory system with two layers:
- Layer 1 (Tactical): Short-term buffer for pattern recognition (RC10b)
- Layer 2 (Strategic): Long-term profile with latent risk multiplier

Inspired by Kimi k2's hierarchical memory architecture.
"""

import time
from collections import deque, defaultdict
from typing import List, Dict, Any, TYPE_CHECKING
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from llm_firewall.detectors.tool_killchain import ToolEvent
else:
    # Lazy import to avoid circular dependencies
    ToolEvent = None


@dataclass
class HierarchicalMemory:
    """
    Hierarchical memory for a single session.
    
    Combines:
    - Tactical buffer (last 50 events) for RC10b pattern detection
    - Strategic profile (latent risk, max phase) for long-term threat assessment
    """
    
    session_id: str
    
    # Layer 1: Tactical (Kurzzeitgedächtnis)
    # Behält die letzten 50 Events für RC10b Muster-Erkennung
    tactical_buffer: deque = field(default_factory=lambda: deque(maxlen=50))
    
    # Layer 2: Strategic (Langzeitprofil)
    max_phase_ever: int = 0
    latent_risk_multiplier: float = 1.0
    tool_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    start_time: float = field(default_factory=time.time)
    
    def add_event(self, event):
        """
        Add a new event to memory.
        
        Updates both tactical buffer and strategic profile.
        """
        # 1. Update Tactical Buffer
        self.tactical_buffer.append(event)
        
        # 2. Determine phase from event category
        # We need to get phase from the event or calculate it
        phase = self._get_phase_from_event(event)
        
        # 3. Update Strategic Stats
        self.tool_counts[event.tool] += 1
        if phase > self.max_phase_ever:
            self.max_phase_ever = phase
            
        # 4. Update Latent Risk (The "Grudge" Logic)
        self._update_latent_risk(phase)
    
    def _get_phase_from_event(self, event) -> int:
        """
        Determine kill-chain phase from event category.
        
        This should match the logic in AgenticCampaignDetector.
        """
        category_map = {
            "recon": 1, "discovery": 1, "read": 1,
            "initial_access": 2, "execution": 2, "persistence": 2, "write": 2,
            "credential_access": 3, "collection": 3, "privilege_escalation": 3,
            "exfiltration": 4, "impact": 4, "defense_evasion": 4, "delete": 4,
            "user_input": 1  # Default for chat events
        }
        
        cat = (event.category or "").lower().strip()
        return category_map.get(cat, 1)
    
    def _update_latent_risk(self, current_phase: int):
        """
        Update latent risk multiplier based on event phase.
        
        UPGRADE: P0 Fix - Enhanced Latent Risk Logic (Kimi's Formula - The Grudge)
        
        Logic inspired by Kimi k2:
        - Boost: Critical phases (3 or 4) increase suspicion immediately
        - Decay: Harmless phases slowly reduce suspicion (forgetting)
        - Floor: Suspicion never falls below a threshold based on worst phase ever seen
        - "Einmal Dieb, immer Dieb" - Once a thief, always a thief
        """
        # UPDATE LATENT RISK (Kimi's Logic)
        if current_phase >= 3:
            # Sofortiger Anstieg bei Gefahr
            self.latent_risk_multiplier = min(3.0, self.latent_risk_multiplier + 0.5)
        else:
            # Langsames Vergessen (Decay)
            self.latent_risk_multiplier *= 0.99
        
        # Floor Enforcement (Das Elefanten-Gedächtnis)
        # Einmal Dieb, immer Dieb
        floor = 1.0
        if self.max_phase_ever == 4:
            floor = 2.0  # Einmal Dieb, immer Dieb
        elif self.max_phase_ever == 3:
            floor = 1.5
        
        self.latent_risk_multiplier = max(floor, self.latent_risk_multiplier)
    
    def get_adjusted_risk(self, base_risk: float) -> float:
        """
        Berechnet das finale Risiko: Basis-Score * Latenter Multiplikator.
        
        Args:
            base_risk: Base risk score from RC10b detector (0.0 - 1.0)
            
        Returns:
            Adjusted risk score (capped at 1.0)
        """
        return min(1.0, base_risk * self.latent_risk_multiplier)
    
    def get_history(self) -> List:
        """
        Get tactical buffer history.
        
        Returns:
            List of recent events (max 50)
        """
        return list(self.tactical_buffer)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get memory statistics for debugging/monitoring.
        
        Returns:
            Dictionary with memory stats
        """
        return {
            "session_id": self.session_id,
            "tactical_buffer_size": len(self.tactical_buffer),
            "max_phase_ever": self.max_phase_ever,
            "latent_risk_multiplier": round(self.latent_risk_multiplier, 3),
            "total_events": sum(self.tool_counts.values()),
            "unique_tools": len(self.tool_counts),
            "session_age_seconds": round(time.time() - self.start_time, 2)
        }

