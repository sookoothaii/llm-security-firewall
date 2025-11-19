"""
Agentic Campaign Detector (RC10: Unified Campaign Detection)
============================================================

Unified detector combining:
- Tool Kill-Chain Monitor
- Operator Risk Budget
- Campaign Graph
- Security Pretext Signals

Integration point for agentic LLM attack detection.

Creator: Joerg Bollwahn (with GPT-5.1 analysis)
Date: 2025-11-17
License: MIT
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from llm_firewall.detectors.action import Action
from llm_firewall.detectors.tool_killchain import (
    KillChainState,
    ToolEvent,
    detect_killchain_campaign,
    phase_floor,
    scan_tool_events,
)
from llm_firewall.session.campaign_graph import (
    CampaignGraph,
    detect_multi_target_campaign,
)
from llm_firewall.session.operator_budget import (
    OperatorBudget,
    check_operator_budget,
    get_operator_risk_score,
)


def is_testlab_authorized(scope: Optional[str], authorized) -> bool:
    """
    Unified check for testlab + authorized condition.
    
    Used in both detector and validator to ensure consistent logic.
    
    Args:
        scope: Scope string (e.g., "testlab", "internal", "external")
        authorized: Authorization flag (bool, str, or None)
        
    Returns:
        True if scope is testlab/internal and authorized is truthy
    """
    if scope is None:
        return False
    
    s = str(scope).strip().lower()
    # Accept both "testlab" and "internal" as testlab scope
    scope_ok = s in {"testlab", "internal_testlab", "internal"}
    
    if not scope_ok:
        return False
    
    # Normalize authorized to bool
    if authorized is None:
        return False
    
    if isinstance(authorized, bool):
        return authorized
    
    if isinstance(authorized, str):
        auth_str = str(authorized).strip().lower()
        return auth_str in {"true", "1", "yes", "y"}
    
    # For other types (int, etc.), use truthiness
    return bool(authorized)


@dataclass
class CampaignDetectorConfig:
    """
    Feature flags und Konfiguration für RC10b Campaign Detector.
    
    RC10b Enhancements:
    - High-Watermark: Verhindert Dilution durch Noise-Events
    - Aggressive Phase-Floors: Phase 4 (Exfiltration/Impact) → 0.85
    - Konfigurierbare Category-Mappings
    """

    use_phase_floor: bool = True
    use_scope_mismatch: bool = True
    use_policy_layer: bool = True
    
    # RC10b: High-Watermark gegen Dilution (GTG-1002 Fix)
    use_high_watermark: bool = True
    
    # RC10b: Dynamische Phase-Floors (Phase -> Min Score)
    # Phase 3 (Collection/Persist): Warnung
    # Phase 4 (Exfil/Impact): Block
    phase_floors: Dict[int, float] = field(
        default_factory=lambda: {
            3: 0.50,  # Collection, Credential Access, Privilege Escalation
            4: 0.85,  # Exfiltration, Impact, Defense Evasion (Sofort BLOCK)
        }
    )
    
    # Mapping von Event-Kategorien auf Kill-Chain-Phasen (konfigurierbar)
    category_to_phase: Dict[str, int] = field(
        default_factory=lambda: {
            "recon": 1,
            "discovery": 1,
            "initial_access": 2,
            "execution": 2,
            "persistence": 2,
            "weaponization": 2,
            "credential_access": 3,
            "collection": 3,
            "privilege_escalation": 3,
            "lateral_movement": 3,
            "exfiltration": 4,
            "impact": 4,
            "defense_evasion": 4,
            "command_and_control": 4,
        }
    )


class AgenticCampaignDetector:
    """
    Unified detector for AI-orchestrated cyber campaigns.
    
    Combines multiple detection layers:
    1. Tool Kill-Chain progression
    2. Operator budget violations
    3. Multi-target campaign graphs
    4. Security pretext signals (from text analysis)
    """
    
    def __init__(
        self,
        operator_budgets: Optional[Dict[str, OperatorBudget]] = None,
        tool_categories: Optional[Dict[str, any]] = None,
        security_pretext_lexicon: Optional[Path] = None,
        config: Optional[CampaignDetectorConfig] = None,
    ):
        """
        Initialize detector.
        
        Args:
            operator_budgets: Dictionary of operator budgets (persisted across sessions)
            tool_categories: Tool-to-phase mapping
            security_pretext_lexicon: Path to security_pretext.json lexicon
        """
        self.operator_budgets = operator_budgets or {}
        self.tool_categories = tool_categories
        self.config = config or CampaignDetectorConfig()
        
        # Load security pretext lexicon
        self.security_pretext_signals = {}
        if security_pretext_lexicon is None:
            security_pretext_lexicon = (
                Path(__file__).parent.parent / "lexicons" / "security_pretext.json"
            )
        
        if security_pretext_lexicon.exists():
            with open(security_pretext_lexicon) as f:
                data = json.load(f)
                self.security_pretext_signals = {
                    intent["intent"]: intent.get("risk_weights", {}).get(intent["intent"], 1.0)
                    for intent in data.get("intents", [])
                }
    
    def _get_phase_for_event(self, event: ToolEvent) -> int:
        """
        Ermittelt die Phase basierend auf der Event-Kategorie.
        
        RC10b: Konfigurierbare Category-Mappings.
        
        Args:
            event: ToolEvent mit category-Feld
            
        Returns:
            Kill-Chain-Phase (1-4, default: 1)
        """
        cat = (event.category or "").lower().strip()
        return self.config.category_to_phase.get(cat, 1)  # Default Phase 1
    
    def _compute_high_watermark(self, tool_events: List[ToolEvent]) -> float:
        """
        Berechnet den höchsten erzwungenen Score basierend auf der 
        historisch maximal erreichten Phase (High-Watermark).
        
        RC10b: GTG-1002 Fix - Verhindert Dilution durch Noise-Events.
        
        Das High-Watermark-Prinzip: Sobald ein Critical Event (Phase 3+) auftritt,
        wird der Score auf den entsprechenden Floor gesetzt und bleibt dort,
        auch wenn danach Noise-Events kommen.
        
        Args:
            tool_events: Liste aller Events der Kampagne (Historie)
            
        Returns:
            High-Watermark Floor Score (0.0 wenn keine Critical Phase erreicht)
        """
        if not tool_events or not self.config.use_high_watermark:
            return 0.0
        
        max_phase = 0
        
        # Scanne alle Events der Kampagne (Historie)
        for event in tool_events:
            phase = self._get_phase_for_event(event)
            if phase > max_phase:
                max_phase = phase
        
        # Hole den Floor für die höchste jemals gesehene Phase
        # Default 0.0, wenn Phase nicht in Config definiert
        return self.config.phase_floors.get(max_phase, 0.0)
    
    def compute_scope_mismatch(
        self,
        pretext_signals: Optional[List[str]],
        tool_events: List[ToolEvent],
    ) -> Tuple[float, bool]:
        """
        Compute scope mismatch score (RC10b: SHIFT Fix).
        
        Detects when pretext claims testlab/internal scope but targets are external.
        This addresses the HARD_SHIFT weakness where Pretext/Scope-Abuse was not
        strongly penalized.
        
        Args:
            pretext_signals: List of security pretext signals (e.g., ["red_team_authorised", "testlab"])
            tool_events: List of tool events with target information
            
        Returns:
            Tuple of (scope_mismatch_score [0.0, 1.0], has_mismatch: bool)
        """
        if not pretext_signals or not tool_events:
            return 0.0, False
        
        # Check if pretext claims testlab/internal
        pretext_text = " ".join(pretext_signals).lower()
        pretext_testlab = any(
            keyword in pretext_text
            for keyword in ["testlab", "internal", "red_team", "authorised", "authorized", "sandbox"]
        )
        
        if not pretext_testlab:
            return 0.0, False
        
        # Extract targets from events (check metadata for scope)
        external_targets = []
        for event in tool_events:
            if event.target:
                # Check metadata for scope information
                scope = event.metadata.get("scope", "").lower()
                target_str = str(event.target).lower()
                
                # Heuristic: external targets often have domain patterns
                # or explicit scope="external" in metadata
                is_external = (
                    scope == "external"
                    or "external" in target_str
                    or "." in target_str  # Domain-like patterns
                    or event.metadata.get("is_external", False)
                )
                
                if is_external:
                    external_targets.append(event.target)
        
        # If pretext says testlab but we have external targets → mismatch
        has_mismatch = len(external_targets) > 0
        mismatch_score = 1.0 if has_mismatch else 0.0
        
        return mismatch_score, has_mismatch
    
    def apply_policy_layer(
        self,
        combined_risk: float,
        phase_depth: int,
        scope: Optional[str] = None,
        authorized: Optional[bool] = None,
        scope_mismatch: bool = False,
        tool_events: Optional[List[ToolEvent]] = None,
        debug: bool = False,
    ) -> Tuple[Action, float, Optional[Dict[str, any]]]:
        """
        Apply policy layer to convert risk score to action (RC10b: HC1/HC3 Fix).
        
        Separates risk assessment from action decision:
        - High risk in testlab + authorized → REQUIRE_APPROVAL (not BLOCK)
        - Phase <= 1 + no exploit/exfil → max REQUIRE_APPROVAL (HC3: Bulk Recon)
        - Scope mismatch + Phase >= 3 → BLOCK or REQUIRE_APPROVAL
        - Phase >= 4 + external → BLOCK (hard rule)
        
        Args:
            combined_risk: Combined risk score [0.0, 1.0]
            phase_depth: Current kill-chain phase depth (0-5)
            scope: Scope context ("testlab", "external", etc.)
            authorized: Whether operation is authorized
            scope_mismatch: Whether scope mismatch detected
            tool_events: Optional tool events for HC3 detection (exploit/exfil tools)
            debug: If True, return debug info dict
            
        Returns:
            Tuple of (action: Action, final_risk: float, debug_info: Optional[Dict])
            Actions: Action.BLOCK, Action.REQUIRE_APPROVAL, Action.WARN, Action.ALLOW
        """
        final_risk = combined_risk
        debug_info = {} if debug else None
        
        if debug:
            debug_info["pre_policy"] = {
                "combined_risk": combined_risk,
                "phase_depth": phase_depth,
                "scope": scope,
                "authorized": authorized,
                "scope_mismatch": scope_mismatch,
            }
        
        # Policy Rule 1: Testlab + authorized → NEVER BLOCK
        # MUST be checked FIRST, before any hard rules or standard thresholds
        # This is the HC1 invariant: testlab + authorized → {ALLOW, WARN, REQUIRE_APPROVAL}
        # BLOCK is explicitly forbidden for HC1 scenarios
        # Use unified function for consistent logic
        if is_testlab_authorized(scope, authorized):
            if debug:
                debug_info["policy_rule"] = "testlab_authorized"
                debug_info["reason"] = "HC1: testlab + authorized → NEVER BLOCK (invariant enforced)"
            # HC1 Policy: testlab + authorized → ALWAYS softer action, NEVER BLOCK
            # Risk score remains high for logging/metrics, but action is always softer
            if final_risk >= 0.35:
                return (Action.REQUIRE_APPROVAL, final_risk, debug_info)
            else:
                return (Action.WARN, final_risk, debug_info)
        
        # RC10b Fix: HC3 Policy - Phase <= 1 + no exploit/exfil → max REQUIRE_APPROVAL
        # Bulk Recon (HC3) ist per se verdächtig, aber nicht automatisch blockwürdig
        # wenn keine Exploit-/Exfil-Tools verwendet werden
        if phase_depth <= 1 and tool_events:
            # Check if exploit or exfil tools are used
            exploit_tools = {"exploit", "metasploit", "payload", "shell", "backdoor"}
            exfil_tools = {"exfil", "download", "upload", "transfer", "copy", "scp", "ftp"}
            
            uses_exploit = any(
                tool in str(event.tool).lower() or tool in str(event.category).lower()
                for event in tool_events
                for tool in exploit_tools
            )
            uses_exfil = any(
                tool in str(event.tool).lower() or tool in str(event.category).lower()
                for event in tool_events
                for tool in exfil_tools
            )
            
            if not uses_exploit and not uses_exfil:
                # Bulk Recon ohne Exploit/Exfil → max REQUIRE_APPROVAL, kein Hard-BLOCK
                if debug:
                    debug_info["policy_rule"] = "hc3_bulk_recon"
                    debug_info["reason"] = "HC3: Phase<=1 + no exploit/exfil → max REQUIRE_APPROVAL"
                if final_risk >= 0.35:
                    return (Action.REQUIRE_APPROVAL, final_risk, debug_info)
                else:
                    return (Action.WARN, final_risk, debug_info)
        
        # Policy Rule 2: Hard rules for external/unknown (only if not HC1)
        # Hard rule: Phase >= 4 + external + not authorized → BLOCK
        # Note: is_testlab_authorized already checked above, so this only applies if not HC1
        if phase_depth >= 4 and scope in ("external", "unknown") and not is_testlab_authorized(scope, authorized):
            if debug:
                debug_info["policy_rule"] = "hard_rule_phase4_external"
                debug_info["reason"] = "Phase>=4 + external/unknown + !authorized → BLOCK"
            return (Action.BLOCK, max(final_risk, 0.55), debug_info)
        
        # Hard rule: Scope mismatch + Phase >= 3 → BLOCK
        if scope_mismatch and phase_depth >= 3:
            if debug:
                debug_info["policy_rule"] = "hard_rule_scope_mismatch"
                debug_info["reason"] = "Scope mismatch + Phase>=3 → BLOCK"
            return (Action.BLOCK, max(final_risk, 0.50), debug_info)
        
        # Policy Rule 3: Standard threshold-based decisions
        if final_risk >= 0.55:
            if debug:
                debug_info["policy_rule"] = "standard_threshold"
                debug_info["reason"] = f"Risk {final_risk:.3f} >= 0.55 → BLOCK"
            return (Action.BLOCK, final_risk, debug_info)
        elif final_risk >= 0.45:
            if debug:
                debug_info["policy_rule"] = "standard_threshold"
                debug_info["reason"] = f"Risk {final_risk:.3f} >= 0.45 → REQUIRE_APPROVAL"
            return (Action.REQUIRE_APPROVAL, final_risk, debug_info)
        elif final_risk >= 0.35:
            if debug:
                debug_info["policy_rule"] = "standard_threshold"
                debug_info["reason"] = f"Risk {final_risk:.3f} >= 0.35 → WARN"
            return (Action.WARN, final_risk, debug_info)
        else:
            if debug:
                debug_info["policy_rule"] = "standard_threshold"
                debug_info["reason"] = f"Risk {final_risk:.3f} < 0.35 → ALLOW"
            return (Action.ALLOW, final_risk, debug_info)
    
    def detect_campaign(
        self,
        tool_events: List[ToolEvent],
        session_id: str,
        operator_id: Optional[str] = None,
        pretext_signals: Optional[List[str]] = None,
        scope: Optional[str] = None,
        authorized: Optional[bool] = None,
    ) -> Dict[str, any]:
        """
        Detect agentic campaign from tool events and context (RC10b: Enhanced).
        
        Args:
            tool_events: List of tool invocation events
            session_id: Session identifier
            operator_id: Operator/API key identifier
            pretext_signals: List of security pretext signals from text analysis
            scope: Scope context ("testlab", "external", etc.)
            authorized: Whether operation is authorized
            
        Returns:
            Detection report with risk score, action, and signals
        """
        # 1. Kill-Chain Analysis
        killchain_state, killchain_report = detect_killchain_campaign(
            tool_events,
            session_id,
            operator_id,
            self.tool_categories,
            use_phase_floor=self.config.use_phase_floor,
        )
        
        # 2. Operator Budget Check
        operator_report = {}
        operator_risk = 0.0
        if operator_id and tool_events:
            # Check budget for latest event
            latest_event = tool_events[-1]
            budget, operator_report = check_operator_budget(
                operator_id,
                latest_event,
                session_id,
                self.operator_budgets,
            )
            # Calculate operator risk from budget
            operator_risk = get_operator_risk_score(budget)
        
        # 3. Campaign Graph Analysis
        campaign_graph, campaign_report = detect_multi_target_campaign(
            tool_events,
            operator_id or session_id,
            self.tool_categories,
        )
        
        # 4. RC10b: Scope Mismatch Detection
        if self.config.use_scope_mismatch:
            scope_mismatch_score, has_scope_mismatch = self.compute_scope_mismatch(
                pretext_signals, tool_events
            )
        else:
            scope_mismatch_score, has_scope_mismatch = (0.0, False)
        
        # 5. Combine Risk Scores
        risk_scores = {
            "killchain": killchain_report.get("risk_score", 0.0),
            "operator": operator_risk,
            "campaign": campaign_report.get("risk_score", 0.0),
        }
        
        # Pretext signal boost
        pretext_boost = 0.0
        if pretext_signals:
            # Count unique pretext intents
            unique_intents = set(pretext_signals)
            pretext_boost = min(len(unique_intents) * 0.1, 0.3)  # Max 0.3 boost
        
        # RC10b: Add scope mismatch penalty
        scope_mismatch_penalty = (
            scope_mismatch_score * 0.2 if self.config.use_scope_mismatch else 0.0
        )  # Max 0.2 boost
        
        # Weighted combination with adaptive weighting
        # If kill-chain or campaign scores are high, reduce operator weight
        # (new operators may not have high operator scores yet, but activity is suspicious)
        killchain_high = risk_scores["killchain"] >= 0.5
        campaign_high = risk_scores["campaign"] >= 0.5
        
        if killchain_high or campaign_high:
            # Reduce operator weight, increase kill-chain/campaign weights
            combined_risk = (
                risk_scores["killchain"] * 0.5
                + risk_scores["operator"] * 0.1
                + risk_scores["campaign"] * 0.4
                + pretext_boost
                + scope_mismatch_penalty
            )
        else:
            # Standard weighting
            combined_risk = (
                risk_scores["killchain"] * 0.4
                + risk_scores["operator"] * 0.3
                + risk_scores["campaign"] * 0.3
                + pretext_boost
                + scope_mismatch_penalty
            )
        combined_risk = min(combined_risk, 1.0)
        
        phase_depth = killchain_report.get("phase_depth", 0)
        
        # RC10b: High-Watermark & Aggressive Phase-Floors (GTG-1002 Fix)
        if self.config.use_phase_floor and self.config.use_high_watermark:
            high_watermark_floor = self._compute_high_watermark(tool_events)
            if high_watermark_floor > combined_risk:
                combined_risk = high_watermark_floor
        
        # RC10b Fix: Phase-Floor nur für external/unknown + !authorized anwenden
        # Phase-Floor wurde bereits im Kill-Chain Risk angewendet (in calculate_killchain_risk)
        # Für testlab+authorized: Cap den Risk für Policy-Entscheidung (Risk bleibt hoch für Logs)
        
        # Für HC1 (testlab+authorized): Cap Risk für Policy-Entscheidung
        # Risk bleibt hoch für Logs/Metriken, aber Policy entscheidet weicher
        if self.config.use_policy_layer and is_testlab_authorized(scope, authorized):
            # Phase-Floor wurde bereits angewendet, aber für HC1 wollen wir nicht den vollen Effekt
            # Cap combined_risk auf 0.50 für Policy-Entscheidung (wird in Policy-Schicht weiter reduziert)
            # Das stellt sicher, dass HC1 nicht durch Phase-Floor über T_hard (0.55) geht
            combined_risk = min(combined_risk, 0.50)
        
        # 6. RC10b: Apply Policy Layer
        # Enable debug for HC1 scenarios to track policy decisions
        if self.config.use_policy_layer:
            enable_debug = is_testlab_authorized(scope, authorized)
            policy_result = self.apply_policy_layer(
                combined_risk,
                phase_depth,
                scope=scope,
                authorized=authorized,
                scope_mismatch=has_scope_mismatch,
                tool_events=tool_events,
                debug=enable_debug,  # Enable debug for HC1 scenarios
            )
        else:
            enable_debug = False
            policy_result = self.apply_threshold_decision(combined_risk)
        action, final_risk, debug_info = policy_result
        
        # Debug logging for HC1 issues (should never happen after fix)
        if self.config.use_policy_layer and is_testlab_authorized(scope, authorized):
            import logging
            logger = logging.getLogger(__name__)
            if action == Action.BLOCK:
                logger.error(
                    f"[RC10b Debug] HC1 INVARIANT VIOLATION: Got BLOCK despite testlab+authorized! "
                    f"risk={final_risk:.3f}, scope={scope}, authorized={authorized}, "
                    f"is_testlab_authorized={is_testlab_authorized(scope, authorized)}, "
                    f"policy_rule={debug_info.get('policy_rule', 'unknown') if debug_info else 'no_debug'}, "
                    f"reason={debug_info.get('reason', 'unknown') if debug_info else 'no_debug'}, "
                    f"combined_risk={combined_risk:.3f}, phase_depth={phase_depth}"
                )
            elif enable_debug and debug_info:
                logger.info(
                    f"[RC10b Debug] HC1 Policy Decision: "
                    f"action={action.name}, risk={final_risk:.3f}, "
                    f"policy_rule={debug_info.get('policy_rule', 'unknown')}, "
                    f"reason={debug_info.get('reason', 'unknown')}"
                )
        
        # Collect all signals
        all_signals = []
        all_signals.extend(killchain_report.get("signals", []))
        all_signals.extend(operator_report.get("signals", []))
        all_signals.extend(campaign_report.get("signals", []))
        
        if pretext_signals:
            all_signals.extend([f"pretext_{s}" for s in pretext_signals])
        
        if has_scope_mismatch:
            all_signals.append("scope_mismatch")
        
        # Build unified report
        report = {
            "session_id": session_id,
            "operator_id": operator_id,
            "combined_risk_score": final_risk,
            "risk_components": risk_scores,
            "pretext_boost": pretext_boost,
            "scope_mismatch_score": scope_mismatch_score,
            "scope_mismatch": has_scope_mismatch,
            "action": action.to_string() if isinstance(action, Action) else str(action),  # RC10b: Policy decision
            "is_campaign": final_risk >= 0.45,  # Detection threshold
            "is_blocked": (action == Action.BLOCK) if isinstance(action, Action) else (action == "BLOCK"),  # RC10b: Block decision
            "signals": list(set(all_signals)),  # Deduplicate
            "killchain": {
                "phase_depth": killchain_report.get("phase_depth", 0),
                "phase_name": killchain_report.get("phase_name", "INITIALIZATION"),
                "tempo": killchain_report.get("tempo", 0.0),
                "branching_factor": killchain_report.get("branching_factor", 0.0),
            },
            "operator": {
                "budget_exceeded": operator_report.get("budget_exceeded", False),
                "auto_strict_active": operator_report.get("auto_strict_active", False),
                "ewma_tempo": operator_report.get("ewma_tempo", 0.0),
            },
            "campaign": {
                "target_count": campaign_report.get("target_count", 0),
                "max_phase": campaign_report.get("max_phase", "INITIALIZATION"),
            },
        }
        
        return report

    def apply_threshold_decision(
        self,
        combined_risk: float,
    ) -> Tuple[Action, float, Optional[Dict[str, any]]]:
        """
        Fallback-Entscheidung ohne Policy-Layer (reine Schwellenwerte).
        """
        if combined_risk >= 0.55:
            return Action.BLOCK, combined_risk, None
        if combined_risk >= 0.45:
            return Action.REQUIRE_APPROVAL, combined_risk, None
        if combined_risk >= 0.35:
            return Action.WARN, combined_risk, None
        return Action.ALLOW, combined_risk, None
    
    def scan_tool_events_for_signals(
        self,
        tool_events: List[ToolEvent],
        session_id: str,
        operator_id: Optional[str] = None,
    ) -> List[str]:
        """
        Scan tool events and return detection signals.
        
        Compatible with existing detector interface.
        
        Args:
            tool_events: List of tool events
            session_id: Session identifier
            operator_id: Operator identifier
            
        Returns:
            List of signal strings
        """
        report = self.detect_campaign(tool_events, session_id, operator_id)
        return report.get("signals", [])


# Convenience function for integration
def detect_agentic_campaign(
    tool_events: List[ToolEvent],
    session_id: str,
    operator_id: Optional[str] = None,
    pretext_signals: Optional[List[str]] = None,
    scope: Optional[str] = None,
    authorized: Optional[bool] = None,
) -> Dict[str, any]:
    """
    Convenience function for campaign detection (RC10b: Enhanced).
    
    Args:
        tool_events: List of tool events
        session_id: Session identifier
        operator_id: Operator identifier
        pretext_signals: Security pretext signals from text
        scope: Scope context ("testlab", "external", etc.)
        authorized: Whether operation is authorized
        
    Returns:
        Detection report with risk score and action
    """
    detector = AgenticCampaignDetector()
    return detector.detect_campaign(
        tool_events, session_id, operator_id, pretext_signals, scope, authorized
    )

