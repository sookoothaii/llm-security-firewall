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
from typing import List, Dict, Any, TYPE_CHECKING, Optional
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from llm_firewall.detectors.tool_killchain import ToolEvent
else:
    # Lazy import to avoid circular dependencies
    ToolEvent = None


class MarkovChain:
    """
    Simple Markov Chain for phase transition anomaly detection.
    
    Tracks transition probabilities between kill-chain phases.
    Used to detect anomalous transitions (e.g., Phase 1 → Phase 4 directly).
    """
    
    def __init__(self):
        """Initialize empty transition matrix."""
        # transition_counts[from_phase][to_phase] = count
        self.transition_counts: Dict[int, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        self.total_transitions = 0
    
    def add(self, from_phase: int, to_phase: int):
        """Record a phase transition."""
        self.transition_counts[from_phase][to_phase] += 1
        self.total_transitions += 1
    
    def probability(self, from_phase: int, to_phase: int) -> float:
        """
        Calculate transition probability P(to_phase | from_phase).
        
        Returns:
            Probability (0.0 to 1.0), or 0.01 if transition never observed (default)
        """
        if from_phase not in self.transition_counts:
            return 0.01  # Default: rare transition
        
        from_counts = self.transition_counts[from_phase]
        total_from = sum(from_counts.values())
        
        if total_from == 0:
            return 0.01
        
        count = from_counts.get(to_phase, 0)
        prob = float(count) / total_from
        
        # If never observed, return small default probability
        if prob == 0.0:
            return 0.01
        
        return prob
    
    def is_anomalous(self, from_phase: int, to_phase: int, threshold: float = 0.01) -> bool:
        """
        Check if a transition is anomalous (probability < threshold).
        
        Args:
            from_phase: Source phase
            to_phase: Target phase
            threshold: Minimum probability to consider normal
            
        Returns:
            True if transition is anomalous
        """
        prob = self.probability(from_phase, to_phase)
        return prob < threshold


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
    
    # FIX: Markov-Chain für Anomalie-Erkennung
    phase_transitions: MarkovChain = field(default_factory=MarkovChain)
    recent_phases: deque = field(default_factory=lambda: deque(maxlen=50))
    
    def add_event(self, event):
        """
        Add a new event to memory.
        
        Updates both tactical buffer and strategic profile.
        """
        # 1. Update Tactical Buffer
        self.tactical_buffer.append(event)
        
        # 2. Determine phase from event category
        phase = self._get_phase_from_event(event)
        
        # 3. FIX: Update Markov-Chain (Anomalie-Erkennung)
        if self.recent_phases:
            prev_phase = self.recent_phases[-1]
            self.phase_transitions.add(prev_phase, phase)
            
            # Prüfe auf anomale Übergänge (z.B. Phase 1 → Phase 4 direkt)
            if self.phase_transitions.is_anomalous(prev_phase, phase, threshold=0.01):
                # Sofortiger Risiko-Schub, weil Übergang verdächtig
                self.latent_risk_multiplier = min(3.0, self.latent_risk_multiplier + 0.5)
        
        # 4. Update Strategic Stats
        self.tool_counts[event.tool] += 1
        if phase > self.max_phase_ever:
            self.max_phase_ever = phase
        
        # 5. Update Latent Risk (The "Grudge" Logic)
        self._update_latent_risk(phase)
        
        # 6. Track recent phases for Markov-Chain
        self.recent_phases.append(phase)
    
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
        # UPDATE LATENT RISK (Kimi's Logic - FIXED)
        # FIX: Floor must be calculated BEFORE decay to prevent multiplier from dropping below floor
        # Calculate floor based on max_phase_ever (worst phase ever seen)
        floor = 1.0
        if self.max_phase_ever == 4:
            floor = 2.0  # Einmal Dieb, immer Dieb
        elif self.max_phase_ever == 3:
            floor = 1.5
        elif self.max_phase_ever == 2:
            floor = 1.2
        
        if current_phase >= 3:
            # Sofortiger Anstieg bei Gefahr
            self.latent_risk_multiplier = min(3.0, self.latent_risk_multiplier + 0.5)
        else:
            # Langsames Vergessen (Decay), aber NIE unter Floor
            # FIX: Apply floor BEFORE decay to prevent mathematical error
            self.latent_risk_multiplier = max(floor, self.latent_risk_multiplier * 0.99)
        
        # Final floor enforcement (safety check)
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

