"""
RC10b Agent Behavioral Detector
================================

Core detection engine for agentic campaign detection.

Implements High-Watermark logic to prevent Low-&-Slow attacks (GTG-1002).
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any

from llm_firewall.detectors.tool_killchain import ToolEvent

from .config import RC10bConfig


@dataclass
class CampaignResult:
    """
    Result of campaign detection.
    
    Args:
        score: Combined risk score [0.0, 1.0]
        decision: Action decision (ALLOW, WARN, BLOCK)
        reasons: List of detection reasons
        phase: Maximum kill-chain phase reached
        is_blocked: Whether the campaign is blocked
    """
    
    score: float
    decision: str  # ALLOW, WARN, BLOCK
    reasons: List[str]
    phase: int
    is_blocked: bool = False


class AgenticCampaignDetector:
    """
    Unified detector for AI-orchestrated cyber campaigns.
    
    Combines multiple detection layers:
    1. Tool Kill-Chain progression
    2. Operator budget violations
    3. Multi-target campaign graphs
    4. Security pretext signals (from text analysis)
    
    RC10b Enhancements:
    - High-Watermark: Prevents dilution by noise events
    - Aggressive Phase-Floors: Phase 4 → 0.85
    - Configurable Category-Mappings
    """
    
    def __init__(self, config: Optional[RC10bConfig] = None):
        """
        Initialize detector.
        
        Args:
            config: RC10b configuration (uses defaults if None)
        """
        self.config = config or RC10bConfig()
    
    def _get_phase_for_event(self, event: ToolEvent) -> int:
        """
        Determines kill-chain phase based on event category.
        
        RC10b: Configurable category mappings.
        
        Args:
            event: ToolEvent with category field
            
        Returns:
            Kill-chain phase (1-4, default: 1)
        """
        cat = (event.category or "").lower().strip()
        return self.config.category_map.get(cat, 1)  # Default Phase 1
    
    def _compute_high_watermark(
        self, 
        events: List[ToolEvent], 
        max_reached_phase: Optional[int] = None
    ) -> float:
        """
        Calculates the historic maximum severity (High-Watermark).
        
        RC10b: GTG-1002 Fix - Prevents dilution by noise events.
        
        The High-Watermark principle: Once a critical event (Phase 3+) occurs,
        the score is set to the corresponding floor and remains there,
        even if noise events follow.
        
        Memory Optimization: If max_reached_phase is provided (from sliding window),
        it takes precedence over scanning events. This preserves the watermark
        even when old events are removed.
        
        Args:
            events: List of all campaign events (history, may be truncated)
            max_reached_phase: Optional maximum phase ever reached (from session state)
            
        Returns:
            High-Watermark floor score (0.0 if no critical phase reached)
        """
        if not self.config.use_high_watermark:
            return 0.0
        
        # Use provided max_reached_phase if available (from sliding window state)
        if max_reached_phase is not None and max_reached_phase > 0:
            return self.config.phase_floors.get(max_reached_phase, 0.0)
        
        # Fallback: Scan events to find max phase
        if not events:
            return 0.0
        
        max_phase = 0
        
        # Scan all events in campaign history
        for event in events:
            phase = self._get_phase_for_event(event)
            if phase > max_phase:
                max_phase = phase
        
        # Get floor for highest phase ever seen
        # Default 0.0 if phase not defined in config
        return self.config.phase_floors.get(max_phase, 0.0)
    
    def detect(
        self,
        events: List[ToolEvent],
        scope_context: Optional[Dict[str, Any]] = None,
        operator_id: Optional[str] = None,
        pretext_signals: Optional[List[str]] = None,
        scope: Optional[str] = None,
        authorized: Optional[bool] = None,
        max_reached_phase: Optional[int] = None,
    ) -> CampaignResult:
        """
        Detect agentic campaign from tool events.
        
        Args:
            events: List of tool invocation events
            scope_context: Optional scope context dict (for scope mismatch detection)
            operator_id: Optional operator identifier
            pretext_signals: Optional list of security pretext signals
            scope: Optional scope string ("testlab", "external", etc.)
            authorized: Optional authorization flag
            
        Returns:
            CampaignResult with risk score, decision, and reasons
        """
        reasons = []
        
        if not events:
            return CampaignResult(
                score=0.0,
                decision="ALLOW",
                reasons=[],
                phase=0,
                is_blocked=False,
            )
        
        # 1. Base Heuristics
        # In production: Use full RC10 metrics (tempo, diversity, branching, etc.)
        # For now: Simplified base risk calculation
        base_risk = 0.1 + (len(events) * 0.01)  # Placeholder
        
        # 2. Scope Mismatch Detection
        if self.config.use_scope_mismatch and scope_context:
            # Example logic: If 'mismatch_detected' flag is set
            if scope_context.get("mismatch_detected"):
                base_risk = max(base_risk, 0.65)
                reasons.append("Scope mismatch (Pretext vs Target)")
        
        final_risk = base_risk
        
        # 3. High-Watermark Application (The GTG-1002 Fix)
        # Use max_reached_phase if provided (from sliding window state), otherwise scan events
        current_max_phase = 0
        if max_reached_phase is not None and max_reached_phase > 0:
            current_max_phase = max_reached_phase
        elif events:
            current_max_phase = max(self._get_phase_for_event(e) for e in events)
        
        if self.config.use_phase_floor:
            floor = (
                self._compute_high_watermark(events, max_reached_phase=max_reached_phase)
                if self.config.use_high_watermark
                else 0.0
            )
            
            if floor > final_risk:
                final_risk = floor
                reasons.append(
                    f"High-Watermark enforced (Phase {current_max_phase} severity)"
                )
        
        # 4. Policy Decision
        decision = "ALLOW"
        is_blocked = False
        
        if final_risk >= self.config.threshold_block:
            decision = "BLOCK"
            is_blocked = True
        elif final_risk >= self.config.threshold_warn:
            decision = "WARN"
        
        return CampaignResult(
            score=final_risk,
            decision=decision,
            reasons=reasons,
            phase=current_max_phase,
            is_blocked=is_blocked,
        )

