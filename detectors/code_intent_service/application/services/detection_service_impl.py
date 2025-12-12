"""
Detection Service Implementation
=================================

Implementiert den kompletten Code Intent Detection Service.

Orchestriert:
1. Benign Validation (FPR-Reduktion)
2. ML-basierte Intent Classification
3. Rule-basierte Pattern Matching
4. Hybrid Decision Logic
5. Feedback Collection

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
License: MIT
"""

import logging
import time
from decimal import Decimal
from typing import Dict, Any, List, Optional

from domain.services.ports import (
    BenignValidatorPort,
    IntentClassifierPort,
    DetectionServicePort,
    DetectionResult,
    RuleEnginePort,
    FeedbackRepositoryPort,
)
import sys
from pathlib import Path

# Add detectors directory to path for shared imports
service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from shared.domain.value_objects import RiskScore

logger = logging.getLogger(__name__)


class DetectionServiceImpl(DetectionServicePort):
    """
    Implementiert den kompletten Code Intent Detection Service.
    
    Orchestriert:
    1. Benign Validation (FPR-Reduktion)
    2. ML-basierte Intent Classification
    3. Rule-basierte Pattern Matching
    4. Hybrid Decision Logic
    5. Feedback Collection
    """
    
    def __init__(
        self,
        benign_validator: BenignValidatorPort,
        intent_classifier: IntentClassifierPort,
        rule_engine: Optional[RuleEnginePort],
        feedback_repository: Optional[FeedbackRepositoryPort],
        settings: Any  # DetectionSettings
    ):
        """
        Initialize detection service.
        
        Args:
            benign_validator: Benign validator for FPR reduction
            intent_classifier: ML-based intent classifier
            rule_engine: Rule-based pattern matcher
            feedback_repository: Feedback collection repository
            settings: Detection settings
        """
        self.benign_validator = benign_validator
        self.intent_classifier = intent_classifier
        self.rule_engine = rule_engine
        self.feedback_repo = feedback_repository
        self.settings = settings
        
        # Konfiguration
        self.block_threshold = Decimal(str(getattr(settings, 'rule_engine_threshold', 0.5)))
        self.enable_feedback = getattr(settings, 'enable_feedback_collection', False)
        self.shadow_mode = getattr(settings, 'shadow_mode', False)
        
        logger.info(f"DetectionService initialisiert (Threshold: {self.block_threshold})")
    
    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """
        Haupt-Detection-Pipeline.
        
        CRITICAL FIX 2025-12-10: Reihenfolge angepasst wie in alter Implementierung:
        1. Narrative Intent Detection (VOR Benign Check)
        2. Intent Classifier (VOR Benign Check - verhindert Execution Requests als benign)
        3. Minimale Commands Check (VOR Benign Check)
        4. Suspicious Patterns Check (VOR Benign Check)
        5. Benign Check (nur wenn keine Execution Requests erkannt)
        6. ML Classification
        7. Rule Engine
        8. Hybrid Decision
        
        Args:
            text: Text to analyze
            context: Optional context (user_id, session, etc.)
            
        Returns:
            DetectionResult with risk_score and matched_patterns
        """
        context = context or {}
        start_time = time.time()
        
        try:
            # Import helper functions
            from domain.services.narrative_intent_detector import (
                detect_narrative_intent,
                is_code_example,
                detect_suspicious_patterns,
                is_minimal_command,
                is_likely_benign
            )
            
            import re
            text_lower = text.lower()
            
            # CRITICAL: Block-Validatoren müssen IMMER ZUERST geprüft werden (Security first!)
            # Prüfe block-Validatoren VOR is_likely_benign(), um zu verhindern, dass gefährliche Patterns übersehen werden
            block_validator_result = self.benign_validator.is_benign(text)
            if not block_validator_result:
                # Block-Validatoren haben gefährliche Patterns erkannt → blockieren
                logger.warning(f"Block validators detected malicious patterns (before is_likely_benign check): {text[:80]}...")
                # Continue to rule engine and scoring - don't return benign result
                is_legitimate_question = False
            else:
                # PRE-CHECK: Legitime Fragen/Erklärungen sollten NICHT blockiert werden
                # Verwende die umfangreiche is_likely_benign() Funktion aus dem alten System
                is_legitimate_question = is_likely_benign(text)
            
            # PRIORITY 0: Narrative Intent Detection (VOR Benign Check)
            # CRITICAL: Nur blockieren wenn block-Validatoren auch blockieren
            # Legitime Poesie (ohne gefährliche Patterns) sollte NICHT blockiert werden
            narrative_score = 0.0
            if not block_validator_result:
                # Block-Validatoren haben gefährliche Patterns erkannt → prüfe narrative intent
                narrative_score = detect_narrative_intent(text)
                # AGGRESSIVER: Threshold auf 0.5 gesenkt (vorher 0.7)
                # Erkennt jetzt auch moderate Creative Bypasses
                if narrative_score >= 0.5:
                    # Moderate/High narrative score = Creative Bypass → Block
                    logger.warning(f"Narrative intent detected (score={narrative_score:.3f}): {text[:80]}...")
                    return DetectionResult(
                        risk_score=RiskScore.create(
                            value=max(narrative_score, 0.6),  # Mindestens 0.6 für Block
                            confidence=0.9,
                            source="narrative_intent_detection"
                        ),
                        matched_patterns=["narrative_intent"],
                        blocked=True,
                        metadata={
                            "narrative_score": narrative_score,
                            "processing_time_ms": (time.time() - start_time) * 1000
                        }
                    )
            elif block_validator_result and is_legitimate_question:
                # Block-Validatoren erlauben UND legitime Frage → erlauben, auch bei hohem narrative_score
                logger.debug(f"Legitimate poetry/question detected (validated by block validators): {text[:80]}...")
                # Skip narrative intent check for legitimate content
                narrative_score = 0.0
            
            # PRIORITY 1: Intent Classifier VOR Benign Check
            # CRITICAL: Verhindert, dass Execution Requests als benign klassifiziert werden
            # V2.1 HOTFIX: Whitelist-Entscheidungen haben höchste Priorität!
            ml_result = None
            intent_execution_detected = False
            v21_whitelist_override = False  # V2.1 Hotfix Whitelist Override Flag
            
            if self.intent_classifier.is_available() and not self.shadow_mode:
                try:
                    ml_result = self.intent_classifier.classify(text)
                    logger.debug(f"ML Result: method={ml_result.method}, score={ml_result.score:.3f}, execution={ml_result.is_execution_request}")
                    
                    # V2.1 HOTFIX: Whitelist-Entscheidungen haben höchste Priorität!
                    # Wenn V2.1 Hotfix eine Whitelist-Entscheidung trifft → IMMER respektieren
                    if ml_result.method == "v2_whitelist_override" or "whitelist" in ml_result.method.lower():
                        v21_whitelist_override = True
                        logger.info(f"V2.1 Hotfix Whitelist Override: {text[:80]}... (method: {ml_result.method})")
                        # Whitelist-Entscheidung → Return early mit benign result
                        return DetectionResult(
                            risk_score=RiskScore.create(
                                value=0.0,
                                confidence=ml_result.confidence or 0.99,
                                source="v2_whitelist_override"
                            ),
                            matched_patterns=[],
                            blocked=False,
                            metadata={
                                "method": ml_result.method,
                                "whitelist_reason": ml_result.metadata.get("reason", "technical_question") if ml_result.metadata else "technical_question",
                                "processing_time_ms": (time.time() - start_time) * 1000
                            }
                        )
                    
                    # Wenn Intent Classifier Execution Request erkannt hat → NICHT benign
                    # ABER: Nur wenn block-Validatoren auch blockieren (verhindert False Positives)
                    if ml_result.is_execution_request and ml_result.confidence > 0.6:
                        # CRITICAL: Nur als Execution Request markieren, wenn block-Validatoren auch blockieren
                        if not block_validator_result:
                            intent_execution_detected = True
                            logger.warning(f"Intent classifier detected execution request (confidence={ml_result.confidence:.3f}): {text[:80]}...")
                        else:
                            logger.debug(f"ML classifier detected execution request, but block validators allow - skipping (legitimate poetry?): {text[:80]}...")
                except Exception as e:
                    logger.warning(f"ML classification failed: {e}")
            
            # PRIORITY 2: Minimale Commands Check (VOR Benign Check)
            minimal_cmd = is_minimal_command(text)
            if minimal_cmd:
                logger.warning(f"Minimal command detected: {text[:50]}... - forcing execution request")
                if ml_result:
                    ml_result.is_execution_request = True
                    ml_result.confidence = 0.95
                intent_execution_detected = True
            
            # PRIORITY 3: Suspicious Patterns Check (VOR Benign Check)
            # ABER: Überspringe wenn legitime Frage/Erklärung
            suspicious = detect_suspicious_patterns(text)
            suspicious_score_boost = 0.0
            if suspicious["any"] and not is_legitimate_question:
                logger.warning(f"Suspicious patterns detected: {suspicious} - forcing not benign")
                intent_execution_detected = True
                # AGGRESSIVER: Höhere Score-Boosts
                if suspicious.get("temporal") or suspicious.get("grammatical"):
                    suspicious_score_boost = 0.7  # Erhöht von 0.6 auf 0.7
                elif suspicious.get("indirect") or suspicious.get("implicit"):
                    suspicious_score_boost = 0.65  # Erhöht von 0.6 auf 0.65 - AGGRESSIVER
                elif suspicious.get("meta") or suspicious.get("contextual"):
                    suspicious_score_boost = 0.5  # Neuer Boost für meta/contextual
                else:
                    suspicious_score_boost = 0.5  # Erhöht von 0.4 auf 0.5
            
            # PRIORITY 4: Context Flags (Code Examples, Documentation)
            import re
            context_flags = {
                "is_code_example": is_code_example(text),
                "is_documentation": any(re.search(pattern, text.lower()) for pattern in [
                    r'\b(example|usage|syntax|according to|manual|documentation|docs|guide|tutorial)\s*:',
                    r'\b(the\s+)?(command|tool|utility)\s+(is\s+)?(used|designed|intended)\s+(to|for)',
                    r'\b(in\s+this\s+)?(example|tutorial|guide|documentation)',
                ])
            }
            
            # SCHRITT 5: Benign-Prüfung (nur wenn KEIN Execution Request erkannt wurde)
            # CRITICAL: Block-Validatoren wurden bereits oben geprüft (block_validator_result)
            # Verwende das bereits geprüfte Ergebnis, um doppelte Prüfungen zu vermeiden
            if intent_execution_detected or minimal_cmd or (suspicious["any"] and not is_legitimate_question):
                # Skip benign check - Execution Request erkannt
                logger.debug("Skipping benign check - execution request detected")
                benign_result = False
            elif not block_validator_result:
                # Block-Validatoren haben bereits gefährliche Patterns erkannt → blockieren
                benign_result = False
                logger.warning(f"Block validators detected malicious patterns: {text[:80]}...")
            elif block_validator_result and is_legitimate_question:
                # Nur wenn legitime Frage UND block-Validatoren erlauben → erlauben
                logger.debug(f"Legitimate question/explanation detected (validated by block validators): {text[:80]}...")
                return self._create_benign_result(text, context, start_time)
            elif block_validator_result:
                # Block-Validatoren erlauben, aber is_likely_benign() erkennt es nicht als "legitimate question"
                # Prüfe, ob es legitime Poesie ist (ohne gefährliche Patterns)
                # Wenn ja, erlauben (verhindert False Positives bei legitimer Poesie)
                from infrastructure.rule_engines.benign_validators.poetic_context_validator import PoeticContextValidator
                poetic_validator = PoeticContextValidator()
                # Prüfe nur auf poetische Struktur (ohne gefährliche Patterns)
                # Wenn poetische Struktur erkannt wird, bedeutet das, dass keine gefährlichen Patterns gefunden wurden
                if poetic_validator._is_poetic_structure(text):
                    logger.debug(f"Legitimate poetry detected (no harmful patterns): {text[:80]}...")
                    return self._create_benign_result(text, context, start_time)
                # Sonst: Fallback zu block_validator_result
                benign_result = block_validator_result
            else:
                # Fallback: Verwende block_validator_result
                benign_result = block_validator_result
            
            # SCHRITT 6: Rule-basierte Pattern-Erkennung
            rule_score = Decimal('0.0')
            matched_patterns = []
            
            if self.rule_engine is not None:
                try:
                    risk_scores_dict, patterns = self.rule_engine.analyze(text)
                    matched_patterns = patterns
                    # Get overall score or max score
                    rule_score = Decimal(str(risk_scores_dict.get('overall', 0.0)))
                    if rule_score == 0 and risk_scores_dict:
                        rule_score = Decimal(str(max(risk_scores_dict.values())))
                    logger.debug(f"Rule Engine: score={rule_score}, patterns={patterns}")
                except Exception as e:
                    logger.warning(f"Rule engine analysis failed: {e}")
            
            # SCHRITT 4: Hybrid Decision Logic
            final_score = self._calculate_hybrid_score(
                rule_score=rule_score,
                ml_result=ml_result,
                context=context
            )
            
            # CRITICAL: Wenn block-Validatoren gefährliche Patterns erkannt haben → risk_score erhöhen
            if not block_validator_result:
                # Block-Validatoren haben gefährliche Patterns erkannt → mindestens 0.55 für Block
                min_block_score = max(float(final_score.value), 0.55)
                final_score = RiskScore.create(
                    value=min_block_score,
                    confidence=max(final_score.confidence, 0.9),
                    source=f"{final_score.source or 'unknown'}_block_validators"
                )
                logger.warning(f"Block validators detected malicious patterns → boosting score to {min_block_score:.3f}")
            
            # SCHRITT 4.5: Apply Suspicious Patterns Boost (falls erkannt)
            if suspicious_score_boost > 0.0:
                # Boost den finalen Score wenn Suspicious Patterns erkannt wurden
                boosted_value = max(float(final_score.value), suspicious_score_boost)
                final_score = RiskScore.create(
                    value=boosted_value,
                    confidence=final_score.confidence,
                    source=f"{final_score.source or 'unknown'}_suspicious_patterns"
                )
                logger.warning(f"Suspicious patterns boost applied: {suspicious_score_boost:.2f} → final score: {boosted_value:.3f}")
            
            # SCHRITT 5: Blocking Decision
            blocked = final_score.value >= float(self.block_threshold)
            
            # SCHRITT 6: Feedback sammeln (falls aktiviert)
            if self.enable_feedback and self.feedback_repo is not None:
                self._collect_feedback(
                    text=text,
                    rule_score=float(rule_score),
                    ml_score=ml_result.score if ml_result else None,
                    final_score=float(final_score.value),
                    blocked=blocked,
                    patterns=matched_patterns,
                    context=context
                )
            
            # SCHRITT 7: Result erstellen
            processing_time = (time.time() - start_time) * 1000
            
            return DetectionResult(
                risk_score=final_score,
                matched_patterns=matched_patterns,
                blocked=blocked,
                metadata={
                    "processing_time_ms": processing_time,
                    "rule_score": float(rule_score),
                    "ml_score": ml_result.score if ml_result else None,
                    "ml_method": ml_result.method if ml_result else None,
                    "ml_confidence": ml_result.confidence if ml_result else None,
                    "context": context,
                    "threshold": float(self.block_threshold)
                }
            )
            
        except Exception as e:
            logger.error(f"Detection failed: {e}", exc_info=True)
            return self._create_error_result(text, e, start_time)
    
    def _create_benign_result(
        self,
        text: str,
        context: Dict[str, Any],
        start_time: float
    ) -> DetectionResult:
        """Erstellt Ergebnis für benignen Text."""
        logger.debug(f"Benign text detected: {text[:50]}...")
        
        processing_time = (time.time() - start_time) * 1000
        
        return DetectionResult(
            risk_score=RiskScore.create(
                value=0.0,
                confidence=0.95,
                source="benign_validator"
            ),
            matched_patterns=[],
            blocked=False,
            metadata={
                "method": "benign_validator",
                "context": context,
                "processing_time_ms": processing_time
            }
        )
    
    def _calculate_hybrid_score(
        self,
        rule_score: Decimal,
        ml_result: Optional[Any],
        context: Dict[str, Any]
    ) -> RiskScore:
        """
        Berechnet finalen Score basierend auf Rule + ML.
        
        Hybrid-Logik:
        1. Hohes Vertrauen in Rule Engine (> 0.8)
        2. ML sehr sicher (> 0.7)
        3. Gray Zone: Gewichtete Kombination
        """
        # Fallback: Wenn keine ML, nur Rule Score
        if ml_result is None:
            return RiskScore.create(
                value=float(rule_score),
                confidence=0.7,
                source="rule_engine_only"
            )
        
        ml_score = Decimal(str(ml_result.score))
        ml_confidence = Decimal(str(ml_result.confidence or 0.5))
        
        # HYBRID LOGIC
        # 1. Hohes Vertrauen in Rule Engine (> 0.8)
        if rule_score >= Decimal('0.8'):
            return RiskScore.create(
                value=float(rule_score),
                confidence=0.9,
                source="rule_engine_high_confidence"
            )
        
        # 2. ML sehr sicher (> 0.7) und hohe Confidence
        if ml_score >= Decimal('0.7') and ml_confidence >= Decimal('0.8'):
            return RiskScore.create(
                value=float(ml_score),
                confidence=float(ml_confidence),
                source=ml_result.method
            )
        
        # 3. Execution Request von ML → hohe Priorität
        if ml_result.is_execution_request and ml_confidence >= Decimal('0.6'):
            return RiskScore.create(
                value=max(float(ml_score), 0.7),  # Mindestens 0.7 für Execution Requests
                confidence=float(ml_confidence),
                source=f"{ml_result.method}_execution_request"
            )
        
        # 4. Gray Zone: Gewichtete Kombination
        # Gewichtung: 60% ML (trainiert), 40% Rule (Fallback)
        combined_value = float(Decimal('0.6') * ml_score + Decimal('0.4') * rule_score)
        combined_confidence = float((ml_confidence + Decimal('0.7')) / Decimal('2'))
        
        return RiskScore.create(
            value=combined_value,
            confidence=combined_confidence,
            source=f"hybrid_{ml_result.method}"
        )
    
    def _collect_feedback(
        self,
        text: str,
        rule_score: float,
        ml_score: Optional[float],
        final_score: float,
        blocked: bool,
        patterns: List[str],
        context: Dict[str, Any]
    ):
        """Sammelt Feedback für kontinuierliches Lernen."""
        try:
            sample = {
                "text": text[:1000],  # Begrenze Länge
                "rule_score": rule_score,
                "ml_score": ml_score,
                "final_score": final_score,
                "blocked": blocked,
                "patterns": patterns,
                "context": context,
                "timestamp": time.time()
            }
            
            self.feedback_repo.add(sample)
            logger.debug(f"Feedback collected for: {text[:50]}...")
                
        except Exception as e:
            logger.warning(f"Feedback collection failed: {e}")
    
    def _create_error_result(
        self,
        text: str,
        error: Exception,
        start_time: float
    ) -> DetectionResult:
        """Erstellt Ergebnis bei Fehler (Fail-Open)."""
        logger.error(f"Creating error result for: {text[:50]}...")
        
        processing_time = (time.time() - start_time) * 1000
        
        return DetectionResult(
            risk_score=RiskScore.create(
                value=0.0,  # Fail-Open: Kein Block bei Fehler
                confidence=0.0,
                source="error_fallback"
            ),
            matched_patterns=[],
            blocked=False,
            metadata={
                "error": str(error),
                "method": "error_fallback",
                "processing_time_ms": processing_time
            }
        )

