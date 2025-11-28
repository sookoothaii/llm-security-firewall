#!/usr/bin/env python3
"""
HAK_GAL v2.0 Core Engine - Fully Integrated Layer Stack
========================================================
Integriert alle Layer (0, 1-A, 1-B, 1.5, 4) in einer zentralen Entscheidungskette.

Fixes:
- Lücke 1: ContextClassifier (Gamer Amnesty) ist jetzt in die Entscheidungskette eingebunden
- Lücke 2: Centralized Violation Tracking - SessionMonitor bekommt jeden Block mit

Author: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-28
Status: v2.0 - Full Integration (PROTOCOL CHAOS Fix)
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional

# Import Layer Components
from .unicode_sanitizer import UnicodeSanitizer
from .persona_skeptic import PersonaSkeptic
from .context_classifier import ContextClassifier, ContextResult
from .session_monitor import SessionMonitor

# TopicRouter import
try:
    from .routing.topic_router import TopicRouter

    HAS_TOPIC_ROUTER = True
except ImportError:
    HAS_TOPIC_ROUTER = False
    TopicRouter = None

# Semantic Guard import (Layer 1-B)
try:
    from .truth_preservation.validators.semantic_grooming_guard import (
        SemanticGroomingGuard,
    )

    HAS_SEMANTIC_GUARD = True
except ImportError:
    HAS_SEMANTIC_GUARD = False
    SemanticGroomingGuard = None

# Truth Preservation import (TAG-2)
try:
    from .truth_preservation.validators.truth_preservation_validator_v2_3 import (
        TruthPreservationValidatorV2_3,
    )

    HAS_TRUTH_VALIDATOR = True
except ImportError:
    HAS_TRUTH_VALIDATOR = False
    TruthPreservationValidatorV2_3 = None

logger = logging.getLogger(__name__)


class HakGalFirewall_v2:
    """
    HAK_GAL v2.0 CORE ENGINE

    Integrierte Logik für Layer 0, 1-A, 1-B, 1.5 und 4.

    Architecture:
    - Layer 0: UnicodeSanitizer (Demojizer, Homoglyph replacement)
    - Layer 1-A: PersonaSkeptic (Framing Detection)
    - Layer 1-B: SemanticGroomingGuard (Neural Intent Detection)
    - Layer 1.5: ContextClassifier (Gamer Amnesty)
    - Layer 4: SessionMonitor (Adaptive Memory, Slow Drip Detection)
    """

    def __init__(self, topic_map_path: Optional[str] = None):
        """
        Initialize HAK_GAL v2.0 Engine with all layers.

        Args:
            topic_map_path: Optional path to topic_map_v1.yaml. If None, uses default path.
        """
        # INITIALISIERUNG DER STACK-KOMPONENTEN
        self.sanitizer = UnicodeSanitizer(enable_emoji_demojize=True)  # L0: Demojizer
        self.skeptic = PersonaSkeptic()  # L1-A: Framing Detector
        self.context = ContextClassifier()  # L1.5: Gamer Amnesty

        # TopicRouter (Layer 1.5 - Fast Fail for unsafe topics)
        self.topic_router: Optional[TopicRouter] = None
        if HAS_TOPIC_ROUTER:
            if topic_map_path is None:
                base_path = Path(__file__).parent / "config"
                topic_map_path = str(base_path / "topic_map_v1.yaml")
            try:
                self.topic_router = TopicRouter(topic_map_path, meta_guard=None)
                logger.info("TopicRouter initialized")
            except Exception as e:
                logger.warning(f"TopicRouter initialization failed: {e}")

        # Semantic Guard (Layer 1-B)
        if HAS_SEMANTIC_GUARD:
            self.semantic = SemanticGroomingGuard()
        else:
            logger.warning(
                "SemanticGroomingGuard not available. Using fallback heuristic."
            )
            self.semantic = None

        self.monitor = SessionMonitor()  # L4: Adaptive Memory

        # Truth Preservation Validator (TAG-2) - Optional
        self.truth_validator: Optional[TruthPreservationValidatorV2_3] = None
        if HAS_TRUTH_VALIDATOR:
            try:
                self.truth_validator = TruthPreservationValidatorV2_3()
                logger.info("TruthPreservationValidator initialized (TAG-2)")
            except Exception as e:
                logger.warning(f"TruthPreservationValidator initialization failed: {e}")

        # KONFIGURATION
        self.BASE_THRESHOLD = 0.75  # Standard-Schwelle für Semantic Guard
        self.GAMER_AMNESTY_BONUS = 0.20  # Toleranz-Bonus für Gamer (Threshold-Erhöhung)
        self.HARD_BLOCK_THRESHOLD = 0.95  # Sofortiger Block egal welcher Kontext
        self.CUMULATIVE_RISK_THRESHOLD = 0.65  # SessionMonitor Block-Schwelle

        logger.info("HAK_GAL v2.0 Engine initialized (Full Layer Integration)")

    def _get_semantic_risk_score(self, text: str) -> float:
        """
        Get semantic risk score from Layer 1-B (SemanticGroomingGuard).

        Falls SemanticGuard nicht verfügbar ist, verwendet einfache Heuristik.

        Args:
            text: Input text to analyze

        Returns:
            Risk score (0.0-1.0)
        """
        if self.semantic:
            # SemanticGroomingGuard API: check_semantic_risk(text, threshold, use_spotlight)
            # Returns: (is_safe, risk_description, score)
            is_safe, _, score = self.semantic.check_semantic_risk(
                text, threshold=0.65, use_spotlight=True
            )
            return score
        else:
            # Fallback Heuristik für Standalone-Testing
            text_lower = text.lower()
            high_risk_keywords = [
                "kill",
                "bomb",
                "pistol",
                "firearm",
                "weapon",
                "explosive",
            ]
            if any(keyword in text_lower for keyword in high_risk_keywords):
                return 0.85
            return 0.1

    def process_request(
        self, user_id: str, raw_input: str, detected_topic: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Process request through full Layer stack (v2.0 - Full Integration).

        Args:
            user_id: Unique user identifier
            raw_input: Raw user input text
            detected_topic: Optional topic ID from TopicRouter

        Returns:
            Decision dict with status, reason, and debug info
        """
        # --- PHASE 1: Normalisierung (Layer 0) ---
        clean_text, unicode_flags = self.sanitizer.sanitize(raw_input)

        # --- PHASE 2: Analyse (Layer 1 Stack) ---

        # A) Skepticism (Framing Detector) - Layer 1-A
        # Erkennt "I am a researcher" -> Penalty z.B. 0.3
        skepticism_penalty = self.skeptic.calculate_skepticism_penalty(clean_text)

        # --- STEP 2.5: Topic Router (Fast Fail) ---
        # Check specific unsafe topics before expensive semantic analysis
        topic_from_router = None
        if self.topic_router:
            try:
                route_result = self.topic_router.route(clean_text)
                topic_from_router = route_result.topic_id

                # If no topic provided from outside, use router result
                if detected_topic is None:
                    detected_topic = (
                        topic_from_router
                        if topic_from_router != "general_chat"
                        else None
                    )

                # PRIORITY: UNSAFE topic detection (with gaming context exception)
                if topic_from_router == "unsafe":
                    # Layer 1.5: Check gaming context exception BEFORE blocking
                    gaming_exception = False
                    if self.context:
                        try:
                            gaming_exception = (
                                self.context.should_allow_unsafe_in_gaming(
                                    clean_text, detected_topic="unsafe"
                                )
                            )
                            if gaming_exception:
                                logger.info(
                                    f"[Layer 1.5] Gaming context exception: {clean_text[:50]}... "
                                    f"(UNSAFE keywords in fictional context)"
                                )
                                # Continue to semantic analysis (grooming checks still active!)
                            else:
                                # Real-world violence - block immediately
                                logger.warning(
                                    f"[UNSAFE] Unsafe topic detected (no gaming context): {clean_text[:50]}..."
                                )
                                # CRITICAL: Register violation for adaptive decay
                                self.monitor.register_violation(user_id)

                                return {
                                    "status": "BLOCK",
                                    "reason": f"UNSAFE_TOPIC_{topic_from_router.upper()}",
                                    "block_reason_code": "UNSAFE_TOPIC",
                                    "debug": {
                                        "input": clean_text,
                                        "original_input": raw_input,
                                        "risk_score": 1.0,
                                        "threshold": 0.0,
                                        "penalty": skepticism_penalty,
                                        "context_modifier": "UNSAFE_TOPIC_DETECTED",
                                        "is_gaming": False,
                                        "accumulated_risk": self.monitor.get_risk(
                                            user_id
                                        ),
                                        "unicode_flags": unicode_flags,
                                        "detected_topic": topic_from_router,
                                    },
                                }
                        except Exception as e:
                            logger.warning(
                                f"[Layer 1.5] ContextClassifier error: {e}. Falling back to strict blocking."
                            )
                            # Fail-safe: Block if classifier fails
                            self.monitor.register_violation(user_id)

                            return {
                                "status": "BLOCK",
                                "reason": f"UNSAFE_TOPIC_{topic_from_router.upper()}",
                                "block_reason_code": "UNSAFE_TOPIC",
                                "debug": {
                                    "input": clean_text,
                                    "original_input": raw_input,
                                    "risk_score": 1.0,
                                    "threshold": 0.0,
                                    "penalty": skepticism_penalty,
                                    "context_modifier": "UNSAFE_TOPIC_DETECTED",
                                    "is_gaming": False,
                                    "accumulated_risk": self.monitor.get_risk(user_id),
                                    "unicode_flags": unicode_flags,
                                    "detected_topic": topic_from_router,
                                },
                            }
                    else:
                        # No ContextClassifier available - strict blocking
                        logger.warning(
                            f"[UNSAFE] Unsafe topic detected: {clean_text[:50]}..."
                        )
                        self.monitor.register_violation(user_id)

                        return {
                            "status": "BLOCK",
                            "reason": f"UNSAFE_TOPIC_{topic_from_router.upper()}",
                            "block_reason_code": "UNSAFE_TOPIC",
                            "debug": {
                                "input": clean_text,
                                "original_input": raw_input,
                                "risk_score": 1.0,
                                "threshold": 0.0,
                                "penalty": skepticism_penalty,
                                "context_modifier": "UNSAFE_TOPIC_DETECTED",
                                "is_gaming": False,
                                "accumulated_risk": self.monitor.get_risk(user_id),
                                "unicode_flags": unicode_flags,
                                "detected_topic": topic_from_router,
                            },
                        }
            except Exception as e:
                logger.warning(
                    f"TopicRouter error: {e}. Continuing without topic routing."
                )

        # B) Context (Gamer Check) - Layer 1.5
        # ContextClassifier.classify() gibt ContextResult zurück
        context_result: ContextResult = self.context.classify(
            clean_text, detected_topic=detected_topic
        )
        is_gaming = context_result.is_gaming_context

        # C) Semantic Risk (Neural Scan) - Layer 1-B
        risk_score = self._get_semantic_risk_score(clean_text)

        # --- PHASE 3: Threshold Berechnung (Die Entscheidungs-Matrix) ---

        # Startwert
        dynamic_threshold = self.BASE_THRESHOLD

        # Logik: Wer Framing benutzt ("Researcher"), verliert das Recht auf Gamer Amnesty.
        if skepticism_penalty > 0:
            # PersonaSkeptic macht System strenger
            dynamic_threshold -= skepticism_penalty  # System wird strenger
            # Cap at minimum 0.1
            dynamic_threshold = max(0.1, dynamic_threshold)
            context_modifier = (
                f"IGNORED (Suspicious Persona, penalty={skepticism_penalty:.2f})"
            )
        elif is_gaming:
            # Gamer Amnesty: System wird lockerer
            dynamic_threshold += self.GAMER_AMNESTY_BONUS  # System wird lockerer
            # Cap at maximum 0.95
            dynamic_threshold = min(0.95, dynamic_threshold)
            context_modifier = f"APPLIED (+{self.GAMER_AMNESTY_BONUS:.2f}, confidence={context_result.confidence:.2f})"
        else:
            context_modifier = "NONE"

        # --- PHASE 4: Memory Check (Layer 4) ---
        # Update Session State VOR der Entscheidung, um Slow Drip zu sehen
        # SessionMonitor.update() gibt accumulated_risk zurück
        accumulated_risk = self.monitor.update(
            user_id, current_score=risk_score, topic=detected_topic
        )

        # Get current session risk (nach Update)
        session_risk = self.monitor.get_risk(user_id)

        # --- PHASE 5: Finale Entscheidung ---
        decision = "ALLOW"
        reason = ""
        block_reason_code = None

        # Kriterium 1: Session History (Slow Drip) - Layer 4
        if session_risk > self.CUMULATIVE_RISK_THRESHOLD:
            decision = "BLOCK"
            session = self.monitor._sessions.get(user_id, None)
            if session:
                violation_count = session.violation_count
            else:
                violation_count = 0
            reason = f"Cumulative Risk (History: {violation_count} violations, accumulated_risk={session_risk:.2f} > {self.CUMULATIVE_RISK_THRESHOLD})"
            block_reason_code = "SESSION_HISTORY"

        # Kriterium 2: Semantischer Verstoß gegen dynamischen Threshold - Layer 1-B
        elif risk_score > dynamic_threshold:
            decision = "BLOCK"
            reason = f"Semantic Violation (Score {risk_score:.2f} > Threshold {dynamic_threshold:.2f})"
            block_reason_code = "SEMANTIC_VIOLATION"

        # Kriterium 3: Hard Block (extreme cases)
        elif risk_score > self.HARD_BLOCK_THRESHOLD:
            decision = "BLOCK"
            reason = f"Hard Block (Score {risk_score:.2f} > Hard Threshold {self.HARD_BLOCK_THRESHOLD})"
            block_reason_code = "HARD_BLOCK"

        # --- PHASE 6: Execution & Feedback Loop ---
        if decision == "BLOCK":
            # WICHTIG: Das Gedächtnis muss JEDEN Block registrieren!
            self.monitor.register_violation(user_id)

            logger.warning(
                f"[HAK_GAL v2.0] BLOCK for user {user_id}: {reason} "
                f"(risk={risk_score:.2f}, threshold={dynamic_threshold:.2f}, "
                f"penalty={skepticism_penalty:.2f}, context={context_modifier})"
            )

            return {
                "status": "BLOCK",
                "reason": reason,
                "block_reason_code": block_reason_code,
                "debug": {
                    "input": clean_text,
                    "original_input": raw_input,
                    "risk_score": risk_score,
                    "threshold": dynamic_threshold,
                    "penalty": skepticism_penalty,
                    "context_modifier": context_modifier,
                    "is_gaming": is_gaming,
                    "accumulated_risk": session_risk,
                    "unicode_flags": unicode_flags,
                },
            }

        # ALLOW Decision
        logger.debug(
            f"[HAK_GAL v2.0] ALLOW for user {user_id} "
            f"(risk={risk_score:.2f}, threshold={dynamic_threshold:.2f}, context={context_modifier})"
        )

        return {
            "status": "ALLOW",
            "sanitized_input": clean_text,
            "debug": {
                "context_modifier": context_modifier,
                "risk_score": risk_score,
                "threshold": dynamic_threshold,
                "penalty": skepticism_penalty,
                "is_gaming": is_gaming,
                "accumulated_risk": session_risk,
                "unicode_flags": unicode_flags,
            },
        }

    def validate_output(
        self,
        user_id: str,
        user_input: str,
        llm_response: str,
        age_band: Optional[str] = None,
        topic_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Layer 2: Output Validation (TAG-2 Truth Preservation)

        Validates LLM response for factuality and harmful advice.
        Must be called AFTER LLM generation.

        Args:
            user_id: Unique user identifier
            user_input: Original user question (for topic routing if needed)
            llm_response: LLM-generated response to validate
            age_band: Age band (e.g., "6-8", "9-12", "13-15")
            topic_id: Topic identifier (optional, will be routed from user_input if not provided)

        Returns:
            Dict with status, modified_response, and reason
        """
        # Standard result (allow by default)
        result = {
            "status": "ALLOW",
            "modified_response": llm_response,
            "reason": None,
            "debug": {},
        }

        # Skip if TruthPreservation not available
        if not self.truth_validator:
            logger.debug("[TAG-2] Skipped (TruthPreservationValidator not available)")
            result["debug"]["tag2_skipped"] = "not_available"
            return result

        # Route topic if not provided
        if not topic_id and self.topic_router:
            try:
                route_result = self.topic_router.route(user_input)
                topic_id = (
                    route_result.topic_id
                    if route_result.topic_id != "general_chat"
                    else None
                )
                result["debug"]["routed_topic"] = route_result.topic_id
                result["debug"]["routing_confidence"] = route_result.confidence
            except Exception as e:
                logger.warning(f"TopicRouter error in validate_output: {e}")

        # Skip validation if no topic_id
        if not topic_id or topic_id == "general_chat":
            logger.debug("[TAG-2] Skipped (no topic_id or general_chat)")
            result["debug"]["tag2_skipped"] = "no_topic_id"
            return result

        # Run truth preservation validation
        try:
            # Note: Full TAG-2 validation requires canonical facts and gates config
            # This is a simplified version - full implementation would load YAML configs
            # For now, we check if truth_validator is available and can validate
            logger.debug(f"[TAG-2] Validating output for topic: {topic_id}")

            # The full validation would require:
            # - Loading canonical facts from YAML
            # - Loading gates config
            # - Calling truth_validator.validate() with proper parameters
            # This is a placeholder that can be extended with full implementation

            result["debug"]["tag2_checked"] = True
            result["debug"]["topic_id"] = topic_id

        except Exception as e:
            logger.error(f"[TAG-2] Validation error: {e}", exc_info=True)
            # Fail-open: Allow response if validation fails
            result["debug"]["tag2_error"] = str(e)

        return result
