"""
Multi-Turn Jailbreak Detection
==============================

Erkennt Angriffe, die über mehrere Turns hinweg versuchen, das System zu umgehen.
Beispiel: Erst harmlose Fragen, dann schrittweise Steuerung zum schädlichen Ziel.

Creator: HAK_GAL Security Team
Date: 2025-12-10
"""

import re
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import deque

import logging
logger = logging.getLogger(__name__)


@dataclass
class TurnContext:
    """Kontext für einen einzelnen Turn."""
    turn_number: int
    text: str
    risk_score: float
    timestamp: float
    detector_method: str
    matched_patterns: List[str] = field(default_factory=list)


@dataclass
class SessionContext:
    """Session-Kontext für Multi-Turn-Analyse."""
    session_id: str
    user_id: Optional[str] = None
    turns: List[TurnContext] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    
    # Risk-Akkumulation
    cumulative_risk: float = 0.0
    risk_history: deque = field(default_factory=lambda: deque(maxlen=10))  # Letzte 10 Turns
    
    # Steuerungs-Erkennung
    steering_indicators: List[str] = field(default_factory=list)
    topic_shifts: int = 0
    
    def add_turn(self, turn: TurnContext):
        """Füge Turn hinzu und aktualisiere Kontext."""
        self.turns.append(turn)
        self.last_activity = time.time()
        self.risk_history.append(turn.risk_score)
        
        # Berechne kumulativen Risk mit zeitlicher Abnahme
        self._update_cumulative_risk()
        
        # Prüfe auf Steuerungs-Indikatoren
        self._detect_steering(turn)
    
    def _update_cumulative_risk(self):
        """Aktualisiere kumulativen Risk-Score mit zeitlicher Abnahme."""
        if not self.risk_history:
            self.cumulative_risk = 0.0
            return
        
        current_time = time.time()
        cumulative = 0.0
        
        # Zeitliche Abnahme: neuere Turns haben mehr Gewicht
        for i, risk in enumerate(reversed(self.risk_history)):
            age_factor = 1.0 / (i + 1)  # Exponentielle Abnahme
            cumulative += risk * age_factor
        
        # Normalisiere (max 1.0)
        self.cumulative_risk = min(1.0, cumulative)
    
    def _detect_steering(self, turn: TurnContext):
        """Erkenne Steuerungs-Indikatoren im Turn."""
        text_lower = turn.text.lower()
        
        # Prüfe auf Steuerungs-Keywords
        steering_patterns = [
            r'\b(now|next|then|after|finally|lastly|in conclusion)\b.*\b(explain|describe|tell|show|give|provide)\b',
            r'\b(remember|recall|you mentioned|earlier you said)\b',
            r'\b(building on|expanding|going further|taking it further)\b',
            r'\b(now that|since|given that)\b.*\b(you understand|we established|we discussed)\b',
            r'\b(gradually|step by step|slowly|carefully)\b.*\b(move|progress|advance)\b',
        ]
        
        for pattern in steering_patterns:
            if re.search(pattern, text_lower):
                self.steering_indicators.append(f"steering_pattern_{len(self.steering_indicators)}")
                break
        
        # Prüfe auf Topic-Shifts (wenn Risk steigt)
        if len(self.turns) >= 2:
            prev_risk = self.turns[-2].risk_score
            if turn.risk_score > prev_risk + 0.2:  # Signifikanter Risk-Anstieg
                self.topic_shifts += 1


class MultiTurnDetector:
    """Detector für Multi-Turn Jailbreak-Angriffe."""
    
    def __init__(self, max_session_age: int = 3600):  # 1 Stunde
        self.sessions: Dict[str, SessionContext] = {}
        self.max_session_age = max_session_age
        self._cleanup_interval = 300  # Cleanup alle 5 Minuten
        self._last_cleanup = time.time()
    
    def analyze_turn(
        self,
        session_id: str,
        text: str,
        current_risk_score: float,
        detector_method: str,
        matched_patterns: List[str],
        user_id: Optional[str] = None
    ) -> Tuple[float, Dict]:
        """
        Analysiere einen Turn im Kontext der Session.
        
        Args:
            session_id: Eindeutige Session-ID
            text: Text des aktuellen Turns
            current_risk_score: Risk-Score vom Single-Turn-Detector
            detector_method: Methode die den Score generiert hat
            matched_patterns: Gefundene Patterns
            user_id: Optional User-ID
            
        Returns:
            (adjusted_risk_score, metadata)
        """
        # Cleanup alte Sessions
        self._cleanup_old_sessions()
        
        # Hole oder erstelle Session
        session = self._get_or_create_session(session_id, user_id)
        
        # Erstelle Turn-Kontext
        turn = TurnContext(
            turn_number=len(session.turns) + 1,
            text=text,
            risk_score=current_risk_score,
            timestamp=time.time(),
            detector_method=detector_method,
            matched_patterns=matched_patterns
        )
        
        # Füge Turn hinzu
        session.add_turn(turn)
        
        # Analysiere Multi-Turn-Patterns
        multi_turn_risk, metadata = self._analyze_multi_turn_patterns(session, turn)
        
        # Kombiniere Single-Turn und Multi-Turn Risk
        # Multi-Turn Risk erhöht den Score, wenn Steuerung erkannt wird
        adjusted_risk = max(current_risk_score, multi_turn_risk)
        
        # Wenn kumulativer Risk hoch ist, erhöhe Score
        if session.cumulative_risk > 0.5:
            adjusted_risk = max(adjusted_risk, session.cumulative_risk * 0.8)
        
        metadata.update({
            "session_id": session_id,
            "turn_number": turn.turn_number,
            "cumulative_risk": session.cumulative_risk,
            "steering_indicators": len(session.steering_indicators),
            "topic_shifts": session.topic_shifts,
            "total_turns": len(session.turns)
        })
        
        return adjusted_risk, metadata
    
    def _get_or_create_session(self, session_id: str, user_id: Optional[str]) -> SessionContext:
        """Hole oder erstelle Session-Kontext."""
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionContext(
                session_id=session_id,
                user_id=user_id
            )
        return self.sessions[session_id]
    
    def _analyze_multi_turn_patterns(self, session: SessionContext, current_turn: TurnContext) -> Tuple[float, Dict]:
        """
        Analysiere Multi-Turn-Patterns.
        
        Returns:
            (multi_turn_risk_score, metadata)
        """
        if len(session.turns) < 2:
            # Braucht mindestens 2 Turns für Multi-Turn-Analyse
            return 0.0, {"multi_turn_detected": False}
        
        risk_score = 0.0
        metadata = {"multi_turn_detected": True}
        
        # Pattern 1: Gradual Risk Escalation
        # Harmlose Turns am Anfang, dann steigender Risk
        if len(session.turns) >= 3:
            early_risks = [t.risk_score for t in session.turns[:3]]
            recent_risks = [t.risk_score for t in session.turns[-3:]]
            
            if max(early_risks) < 0.3 and max(recent_risks) > 0.5:
                risk_score = max(risk_score, 0.6)
                metadata["pattern"] = "gradual_risk_escalation"
                logger.warning(f"Multi-turn pattern detected: Gradual risk escalation in session {session.session_id}")
        
        # Pattern 2: Topic Steering
        # Steuerung von harmlosem zu schädlichem Topic
        if session.topic_shifts >= 2 and session.cumulative_risk > 0.4:
            risk_score = max(risk_score, 0.7)
            metadata["pattern"] = "topic_steering"
            logger.warning(f"Multi-turn pattern detected: Topic steering in session {session.session_id}")
        
        # Pattern 3: Context Building
        # Aufbau von Kontext in frühen Turns, dann schädliche Anfrage
        if len(session.turns) >= 4:
            early_texts = " ".join([t.text.lower() for t in session.turns[:2]])
            recent_texts = " ".join([t.text.lower() for t in session.turns[-2:]])
            
            # Prüfe ob frühe Turns harmlos sind, aber spätere schädlich
            harmless_keywords = ["help", "explain", "understand", "learn", "curious", "question"]
            harmful_keywords = ["hack", "exploit", "bypass", "ignore", "remove", "delete", "drop", "system", "admin"]
            
            early_harmless = any(kw in early_texts for kw in harmless_keywords)
            recent_harmful = any(kw in recent_texts for kw in harmful_keywords)
            
            if early_harmless and recent_harmful and current_turn.risk_score > 0.4:
                risk_score = max(risk_score, 0.65)
                metadata["pattern"] = "context_building"
                logger.warning(f"Multi-turn pattern detected: Context building attack in session {session.session_id}")
        
        # Pattern 4: Cumulative Risk Threshold
        # Wenn kumulativer Risk sehr hoch ist, auch bei niedrigem Einzel-Turn-Risk
        if session.cumulative_risk > 0.7:
            risk_score = max(risk_score, 0.75)
            metadata["pattern"] = "cumulative_risk_threshold"
        
        return risk_score, metadata
    
    def _cleanup_old_sessions(self):
        """Entferne alte Sessions."""
        current_time = time.time()
        
        # Cleanup nur alle N Sekunden
        if current_time - self._last_cleanup < self._cleanup_interval:
            return
        
        self._last_cleanup = current_time
        
        sessions_to_remove = []
        for session_id, session in self.sessions.items():
            age = current_time - session.last_activity
            if age > self.max_session_age:
                sessions_to_remove.append(session_id)
        
        for session_id in sessions_to_remove:
            del self.sessions[session_id]
            logger.debug(f"Cleaned up old session: {session_id}")
    
    def get_session_stats(self, session_id: str) -> Optional[Dict]:
        """Hole Statistiken für eine Session."""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        return {
            "session_id": session_id,
            "total_turns": len(session.turns),
            "cumulative_risk": session.cumulative_risk,
            "steering_indicators": len(session.steering_indicators),
            "topic_shifts": session.topic_shifts,
            "created_at": session.created_at,
            "last_activity": session.last_activity
        }


# Global instance
_multi_turn_detector: Optional[MultiTurnDetector] = None


def get_multi_turn_detector() -> MultiTurnDetector:
    """Hole globale Multi-Turn-Detector-Instanz."""
    global _multi_turn_detector
    if _multi_turn_detector is None:
        _multi_turn_detector = MultiTurnDetector()
    return _multi_turn_detector

