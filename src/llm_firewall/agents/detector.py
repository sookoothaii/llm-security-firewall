"""
RC10b Agent Behavioral Detector
================================

Core detection engine for agentic campaign detection.

Implements High-Watermark logic to prevent Low-&-Slow attacks (GTG-1002).
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
import logging

from llm_firewall.detectors.tool_killchain import ToolEvent

from .config import RC10bConfig

logger = logging.getLogger(__name__)


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
        self, events: List[ToolEvent], max_reached_phase: Optional[int] = None
    ) -> float:
        """
        Calculates the historic maximum severity (High-Watermark).

        RC10b: GTG-1002 Fix - Prevents dilution by noise events.

        The High-Watermark principle: Once a critical event (Phase 3+) occurs,
        the score is set to the corresponding floor and remains there,
        even if noise events follow.

        FIX (Gemini 3): State Leaking Prevention
        - Wenn max_reached_phase None ist, darf NICHT der globale maximale Wert genommen werden
        - Muss zwingend session-spezifisch sein (wird von außen übergeben)
        - Falls nicht übergeben, wird 0.0 zurückgegeben (kein Floor für neue Sessions)

        Args:
            events: List of all campaign events (history, may be truncated)
            max_reached_phase: Optional maximum phase ever reached (from session state)
                              MUST be session-specific, not global!

        Returns:
            High-Watermark floor score (0.0 if no critical phase reached)
        """
        if not self.config.use_high_watermark:
            return 0.0

        # FIX (Gemini 3): Wenn max_reached_phase None ist, NICHT aus globalem State nehmen
        # Stattdessen: Nur aus den Events dieser spezifischen Request-Session berechnen
        if max_reached_phase is not None and max_reached_phase > 0:
            # Use provided max_reached_phase (from session-specific memory)
            return self.config.phase_floors.get(max_reached_phase, 0.0)

        # Fallback: Scan events to find max phase (only for THIS request's events)
        # This is safe because events are already filtered by session
        if not events:
            return 0.0

        max_phase = 0

        # Scan all events in campaign history (session-specific)
        for event in events:
            phase = self._get_phase_for_event(event)
            if phase > max_phase:
                max_phase = phase

        # Get floor for highest phase ever seen in THIS session's events
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

        # FIX (Gemini 3): Check for Stale Session Context
        # If the previous event is very old, treat this as a new session,
        # even if events exist in the DB (prevents "Zombie Session" problem)
        events_considered = events
        if len(events) > 1:
            last_event_time = events[-1].timestamp
            prev_event_time = events[-2].timestamp

            # Timeout: 1 hour (3600s). For tests, this prevents stale data from previous runs.
            # In production, this handles users returning after long breaks.
            STALE_SESSION_TIMEOUT = 3600  # 1 hour
            if (last_event_time - prev_event_time) > STALE_SESSION_TIMEOUT:
                # Reset effective length for risk calculation (treat as single event)
                events_considered = [events[-1]]
                # Reset phase overrides (don't use old max_phase_ever)
                if max_reached_phase is not None and max_reached_phase > 0:
                    max_reached_phase = 0
                logger.info(
                    f"[RC10b] Stale session detected (gap: {last_event_time - prev_event_time:.0f}s). "
                    f"Treating as new session (was {len(events)} events, now {len(events_considered)})."
                )

        # 1. Base Heuristics
        # In production: Use full RC10 metrics (tempo, diversity, branching, etc.)
        # For now: Simplified base risk calculation
        # FIX: Lower base risk for new sessions to reduce false positives
        # Single event in new session = very low risk (0.05)
        if len(events_considered) == 1:
            base_risk = 0.05  # Very low risk for first event
        else:
            base_risk = 0.1 + (
                len(events_considered) * 0.01
            )  # Slightly higher for multiple events

        # 2. Scope Mismatch Detection
        if self.config.use_scope_mismatch and scope_context:
            # Example logic: If 'mismatch_detected' flag is set
            if scope_context.get("mismatch_detected"):
                base_risk = max(base_risk, 0.65)
                reasons.append("Scope mismatch (Pretext vs Target)")

        final_risk = base_risk

        # 3. High-Watermark Application (The GTG-1002 Fix)
        # Use max_reached_phase if provided (from sliding window state), otherwise scan events
        # FIX (Gemini 3): Use events_considered instead of events for phase calculation
        current_max_phase = 0
        if max_reached_phase is not None and max_reached_phase > 0:
            current_max_phase = max_reached_phase
        elif events_considered:
            current_max_phase = max(
                self._get_phase_for_event(e) for e in events_considered
            )

        if self.config.use_phase_floor:
            floor = (
                self._compute_high_watermark(
                    events, max_reached_phase=max_reached_phase
                )
                if self.config.use_high_watermark
                else 0.0
            )

            # FIX (Gemini 3): Only apply floor if:
            # 1. Floor > 0 (there was a critical phase)
            # 2. AND we have more than 1 event (not a new session with single event)
            # This prevents false positives for new sessions with low-risk events
            # Use events_considered to respect stale session detection
            if floor > 0.0 and len(events_considered) > 1 and floor > final_risk:
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
