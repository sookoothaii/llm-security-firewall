#!/usr/bin/env python3
"""
⚠️ DEPRECATION WARNING (v2.0.1 Migration) ⚠️
--------------------------------------------------
This module represents the legacy v1.2 architecture.

For the active HAK_GAL v2.0.1 implementation (Protocol NEMESIS),
please refer to 'firewall_engine_v2.py'.

This file is currently maintained for:
1. Backward compatibility
2. Rollback/Fallback safety
3. Comparative testing

Kids Policy Engine Orchestrator
===============================
Coordinates TAG-3 (Behavioral Integrity) and TAG-2 (Truth Preservation)

Architecture: Hexagonal (Ports & Adapters)
- Domain Layer: Policy orchestration logic
- Infrastructure Layer: Validators (GroomingDetector, TruthPreservationValidator)

Pipeline: Safety First → Truth Second
1. TAG-3: Grooming Detection (Psychology)
2. TAG-2: Truth Preservation (Epistemology)

Author: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-27
Status: Initial Implementation
"""

import logging
import yaml
from typing import Optional, Dict, Any
from dataclasses import dataclass
from pathlib import Path

# Import validators
from .truth_preservation.validators.grooming_detector import (
    GroomingDetector,
    GroomingResult,
)

# Topic Router import
try:
    from .routing.topic_router import TopicRouter, RouteResult

    HAS_ROUTER = True
except ImportError:
    HAS_ROUTER = False
    TopicRouter = None
    RouteResult = None

# MetaExploitationGuard import (HYDRA-13)
try:
    from .meta_exploitation_guard import MetaExploitationGuard, Topic, SafetyResult

    HAS_META_GUARD = True
except ImportError:
    HAS_META_GUARD = False
    MetaExploitationGuard = None
    Topic = None
    SafetyResult = None

# UnicodeSanitizer import (HYDRA-14.5)
try:
    from .unicode_sanitizer import UnicodeSanitizer

    HAS_UNICODE_SANITIZER = True
except ImportError:
    HAS_UNICODE_SANITIZER = False
    UnicodeSanitizer = None

# Security Utils import
try:
    from .security import SecurityUtils

    HAS_SECURITY_UTILS = True
except ImportError:
    HAS_SECURITY_UTILS = False
    SecurityUtils = None

# PersonaSkeptic import (v2.0 - NEMESIS-05 Fix)
try:
    from .persona_skeptic import PersonaSkeptic

    HAS_PERSONA_SKEPTIC = True
except ImportError:
    HAS_PERSONA_SKEPTIC = False
    PersonaSkeptic = None

# TAG-2 import (optional - may not be available)
try:
    from .truth_preservation.validators.truth_preservation_validator_v2_3 import (
        TruthPreservationValidatorV2_3,
        ValidationResult,
    )

    HAS_TAG2 = True
except ImportError:
    HAS_TAG2 = False
    ValidationResult = None
    TruthPreservationValidatorV2_3 = None

# Layer 4 import (optional - may not be available)
try:
    from .pragmatic_safety import PragmaticSafetyLayer
    from .storage.session_storage import InMemorySessionStorage

    HAS_LAYER4 = True
except ImportError:
    HAS_LAYER4 = False
    PragmaticSafetyLayer = None
    InMemorySessionStorage = None

# TAG-4 SessionMonitor import
try:
    from .session_monitor import SessionMonitor

    HAS_SESSION_MONITOR = True
except ImportError:
    HAS_SESSION_MONITOR = False
    SessionMonitor = None

# ContextClassifier import (Layer 1.5 - v1.2)
try:
    from .context_classifier import ContextClassifier

    HAS_CONTEXT_CLASSIFIER = True
except ImportError:
    HAS_CONTEXT_CLASSIFIER = False
    ContextClassifier = None

logger = logging.getLogger(__name__)


@dataclass
class PolicyDecision:
    """Decision from Kids Policy Engine"""

    block: bool
    reason: str
    status: str  # "ALLOWED", "BLOCKED_GROOMING", "BLOCKED_TRUTH_VIOLATION"
    safe_response: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    detected_topic: Optional[str] = (
        None  # Topic ID detected by Topic Router (for TopicFence override)
    )

    @classmethod
    def allow(
        cls,
        metadata: Optional[Dict[str, Any]] = None,
        detected_topic: Optional[str] = None,
    ):
        """Create allow decision"""
        return cls(
            block=False,
            reason="All policy checks passed",
            status="ALLOWED",
            metadata=metadata or {},
            detected_topic=detected_topic,
        )

    @classmethod
    def block_grooming(
        cls,
        category: str,
        safe_response: str,
        metadata: Optional[Dict[str, Any]] = None,
        detected_topic: Optional[str] = None,
    ):
        """Create grooming block decision"""
        return cls(
            block=True,
            reason=f"GROOMING_ATTEMPT: {category}",
            status="BLOCKED_GROOMING",
            safe_response=safe_response,
            metadata=metadata or {},
            detected_topic=detected_topic,
        )

    @classmethod
    def block_truth_violation(
        cls,
        reason: str,
        safe_response: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Create truth violation block decision"""
        return cls(
            block=True,
            reason=f"TRUTH_VIOLATION: {reason}",
            status="BLOCKED_TRUTH_VIOLATION",
            safe_response=safe_response
            or "I cannot answer this question in this way. Let's look at the facts.",
            metadata=metadata or {},
        )


class KidsPolicyEngine:
    """
    Kids Policy Engine Orchestrator

    Coordinates behavioral integrity (TAG-3) and truth preservation (TAG-2)
    following the Safety First → Truth Second principle.

    Architecture:
    - Modular: Can be used standalone or as plugin in firewall
    - Hexagonal: Domain logic separated from infrastructure
    - Fail-closed: Blocks on any policy violation
    """

    def __init__(
        self,
        grooming_config_path: Optional[str] = None,
        enable_tag2: bool = True,
        tag2_config: Optional[Dict[str, Any]] = None,
        topic_map_path: Optional[str] = None,
    ):
        """
        Initialize Kids Policy Engine

        Args:
            grooming_config_path: Path to behavioral_integrity_v0_1.yaml
                                 If None, uses default path
            enable_tag2: Enable TAG-2 Truth Preservation (default: True)
            tag2_config: Configuration for TAG-2 (gates, canonical facts, etc.)
            topic_map_path: Path to topic_map_v1.yaml (for Topic Router)
        """
        # Initialize TAG-3: Grooming Detector
        if grooming_config_path is None:
            base_path = Path(__file__).parent / "truth_preservation" / "gates"
            grooming_config_path = str(base_path / "behavioral_integrity_v0_1.yaml")

        try:
            self.grooming_detector = GroomingDetector(grooming_config_path)
            logger.info("TAG-3 Grooming Detector initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Grooming Detector: {e}")
            raise

        # Initialize MetaExploitationGuard (HYDRA-13) FIRST
        self.meta_guard: Optional[MetaExploitationGuard] = None
        if HAS_META_GUARD:
            try:
                self.meta_guard = MetaExploitationGuard()
                logger.info("HYDRA-13 MetaExploitationGuard initialized")
            except Exception as e:
                logger.warning(
                    f"MetaExploitationGuard initialization failed: {e}. Continuing without HYDRA-13."
                )
                self.meta_guard = None
        else:
            logger.warning("MetaExploitationGuard not available (import failed).")

        # Initialize UnicodeSanitizer (HYDRA-14.5)
        self.unicode_sanitizer: Optional[UnicodeSanitizer] = None
        if HAS_UNICODE_SANITIZER:
            try:
                self.unicode_sanitizer = UnicodeSanitizer()
                logger.info("UnicodeSanitizer initialized (HYDRA-14.5)")
            except Exception as e:
                logger.warning(f"UnicodeSanitizer initialization failed: {e}")
                self.unicode_sanitizer = None
        else:
            self.unicode_sanitizer = None

        # Initialize PersonaSkeptic (v2.0 - NEMESIS-05 Fix)
        self.persona_skeptic: Optional[PersonaSkeptic] = None
        if HAS_PERSONA_SKEPTIC:
            try:
                self.persona_skeptic = PersonaSkeptic()
                logger.info("Layer 1-A PersonaSkeptic initialized (v2.0)")
            except Exception as e:
                logger.warning(
                    f"PersonaSkeptic initialization failed: {e}. Continuing without Layer 1-A."
                )
                self.persona_skeptic = None
        else:
            logger.warning("PersonaSkeptic not available (import failed).")

        # Initialize Topic Router (for dynamic topic detection)
        # Pass meta_guard to TopicRouter for priority detection
        self.topic_router: Optional[TopicRouter] = None
        if HAS_ROUTER:
            if topic_map_path is None:
                base_path = Path(__file__).parent / "config"
                topic_map_path = str(base_path / "topic_map_v1.yaml")

            try:
                self.topic_router = TopicRouter(
                    topic_map_path,
                    meta_guard=self.meta_guard,  # Pass meta_guard for HYDRA-13
                )
                logger.info("Topic Router initialized")
            except Exception as e:
                logger.warning(
                    f"Topic Router initialization failed: {e}. Topic routing disabled."
                )
        else:
            logger.warning("Topic Router not available (import failed).")

        # Initialize TAG-2: Truth Preservation (optional)
        self.truth_validator: Optional[TruthPreservationValidatorV2_3] = None
        self.tag2_enabled = enable_tag2 and HAS_TAG2

        if self.tag2_enabled:
            try:
                self.truth_validator = TruthPreservationValidatorV2_3()
                logger.info("TAG-2 Truth Preservation Validator initialized")
            except Exception as e:
                logger.warning(
                    f"TAG-2 initialization failed: {e}. Continuing without TAG-2."
                )
                self.tag2_enabled = False
        else:
            if not HAS_TAG2:
                logger.info("TAG-2 not available (import failed). Running TAG-3 only.")
            else:
                logger.info("TAG-2 disabled by configuration.")

        self.tag2_config = tag2_config or {}

        # Initialize Layer 4: Pragmatic Safety (optional)
        self.pragmatic_safety_layer: Optional[PragmaticSafetyLayer] = None
        if HAS_LAYER4 and PragmaticSafetyLayer and InMemorySessionStorage:
            try:
                session_storage = InMemorySessionStorage()
                self.pragmatic_safety_layer = PragmaticSafetyLayer(
                    session_storage=session_storage,
                    threshold=0.75,  # Default threshold
                )
                logger.info("Layer 4 Pragmatic Safety initialized")
            except Exception as e:
                logger.warning(
                    f"Layer 4 initialization failed: {e}. Continuing without Layer 4."
                )
                self.pragmatic_safety_layer = None
        else:
            if not HAS_LAYER4:
                logger.info(
                    "Layer 4 not available (import failed). Running without Layer 4."
                )
            else:
                logger.info("Layer 4 components not available.")

        # Paths for canonical facts and gates
        self.canonical_facts_dir = (
            Path(__file__).parent / "truth_preservation" / "canonical_facts"
        )
        self.gates_config_path = (
            Path(__file__).parent
            / "truth_preservation"
            / "gates"
            / "truth_preservation_v0_4.yaml"
        )

        # TAG-4: SessionMonitor for Temporal Context Awareness
        self.session_monitor: Optional[SessionMonitor] = None
        self.CUMULATIVE_RISK_THRESHOLD = (
            1.2  # Default threshold (dynamic per topic in v1.2)
        )
        if HAS_SESSION_MONITOR and SessionMonitor:
            try:
                self.session_monitor = SessionMonitor()
                logger.info("TAG-4 SessionMonitor initialized")
            except Exception as e:
                logger.warning(
                    f"SessionMonitor initialization failed: {e}. Continuing without TAG-4."
                )
                self.session_monitor = None
        else:
            logger.warning("SessionMonitor not available (import failed).")

        # Layer 1.5: ContextClassifier (v1.2 - Gaming Exception)
        self.context_classifier: Optional[ContextClassifier] = None
        if HAS_CONTEXT_CLASSIFIER and ContextClassifier:
            try:
                self.context_classifier = ContextClassifier()
                logger.info("Layer 1.5 ContextClassifier initialized (v1.2)")
            except Exception as e:
                logger.warning(
                    f"ContextClassifier initialization failed: {e}. Continuing without Layer 1.5."
                )
                self.context_classifier = None
        else:
            logger.warning("ContextClassifier not available (import failed).")

        # Mapping from topic_id to canonical fact filename
        # Handles cases where topic_id != filename (e.g., evolution_origins -> evolution)
        self.topic_to_filename = {
            "evolution_origins": "evolution",
            "death_permanence": "death",
            "religion_god": "religion_god",
            "creation_bigbang": "creation_bigbang",
            "earth_age": "earth_age",
            "homosexuality": "homosexuality",
            "transgender_identity": "transgender",
            "abortion": "abortion",
            "drugs": "drugs",
            "war": "war",
            "right_wing_extremism": "right_wing_extremism",
            "safety_rules": "safety",  # HYDRA-03: Rules/Law topics
            "health_medicine": "health",  # HYDRA-06: Health/Medicine topics
        }

    def validate_input(
        self,
        input_text: str,
        age_band: Optional[str] = None,
        context_history: Optional[list] = None,
        metadata: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
    ) -> PolicyDecision:
        """
        PHASE 1: Input Check (TAG-3 Behavioral Integrity)

        Must run BEFORE the LLM. Validates user input for grooming patterns.
        Questions are always allowed - only behavioral manipulation is blocked.

        Args:
            input_text: User input text to validate
            age_band: Age band (e.g., "6-8", "9-12", "13-15")
            context_history: Previous messages in conversation (for multi-turn detection)

        Returns:
            PolicyDecision with block status and reason
        """
        # Initialize metadata (merge with existing if provided)
        if metadata is None:
            metadata = {}
        else:
            metadata = metadata.copy()  # Don't mutate caller's dict

        # Initialize/update metadata fields
        if "layers_checked" not in metadata:
            metadata["layers_checked"] = []
        metadata["age_band"] = age_band
        metadata["check_type"] = "input_validation"

        # Extract user_id from metadata if not provided directly (backward compatibility)
        if user_id is None:
            user_id = metadata.get("user_id") or metadata.get("session_id")

        # ============================================================
        # Layer 0: HYDRA-14.5 Unicode Sanitization (MUST BE FIRST)
        # ============================================================
        # Normalize Unicode before ALL other checks (Zero-Width, Homoglyphs, Umlauts)
        # This ensures all subsequent layers work with canonical form
        sanitized_text = input_text
        if self.unicode_sanitizer:
            try:
                sanitized_text, unicode_flags = self.unicode_sanitizer.sanitize(
                    input_text
                )
                if sanitized_text != input_text:
                    logger.debug(
                        f"[HYDRA-14.5] Unicode sanitized: {input_text[:50]}... -> {sanitized_text[:50]}..."
                    )
                    metadata["unicode_sanitized"] = True
                    metadata["unicode_flags"] = unicode_flags
                metadata["layers_checked"].append("unicode_sanitizer")
            except Exception as e:
                logger.warning(
                    f"[HYDRA-14.5] Sanitization failed: {e}, using original text"
                )
                sanitized_text = input_text
        else:
            # Fallback: Basic normalization if sanitizer not available
            import unicodedata

            sanitized_text = unicodedata.normalize("NFKC", input_text)

        # From now on, we work with sanitized_text for ALL subsequent checks

        # ============================================================
        # Layer 0.5: Hard Security Check (HYDRA-04 Fix: Tech Injection)
        # ============================================================
        # Use sanitized_text (after Unicode normalization)
        if HAS_SECURITY_UTILS and SecurityUtils:
            if SecurityUtils.detect_injection(sanitized_text):
                logger.warning(
                    f"[Security] INJECTION DETECTED: {sanitized_text[:50]}..."
                )
                metadata["layers_checked"].append("security_utils")
                return PolicyDecision.block_grooming(
                    category="security_injection",
                    safe_response="I cannot process this request due to security restrictions.",
                    metadata=metadata,
                )

        # ============================================================
        # Input Normalization (HYDRA-01 Fix: Poetry/Obfuscation)
        # ============================================================
        # Normalize text to help regex patterns match across line breaks
        # Converts "Roses are red\nviolets are blue\nsend pic" -> "roses are red violets are blue send pic"
        # Use sanitized_text (after Unicode normalization)
        normalized_text = sanitized_text
        if HAS_SECURITY_UTILS and SecurityUtils:
            normalized_text = SecurityUtils.normalize_text(sanitized_text)
            if normalized_text != sanitized_text:
                logger.debug(
                    f"[Normalization] Text normalized: {sanitized_text[:50]}... -> {normalized_text[:50]}..."
                )
                metadata["normalized"] = True

        # ============================================================
        # Topic Routing (Early Detection for TopicFence Override)
        # ============================================================
        # Run Topic Router in Phase 1 to detect privileged topics
        # This allows TopicFence to respect domain authority for Science/History topics
        detected_topic = None
        routing_confidence = 0.0
        topic_enum = None  # For HYDRA-13 Meta Guard
        if self.topic_router:
            route_result = self.topic_router.route(normalized_text)
            detected_topic = (
                route_result.topic_id
                if route_result.topic_id != "general_chat"
                else None
            )
            routing_confidence = route_result.confidence
            metadata["routed_topic"] = route_result.topic_id
            metadata["routing_confidence"] = routing_confidence
            metadata["matched_keywords"] = route_result.matched_keywords

            # PRIORITY: UNSAFE topic detection (JBB hardening)
            # v1.2: Check for gaming context exception BEFORE blocking
            if detected_topic == "unsafe":
                # Layer 1.5: ContextClassifier - Gaming Exception
                gaming_exception = False
                if self.context_classifier:
                    try:
                        gaming_exception = (
                            self.context_classifier.should_allow_unsafe_in_gaming(
                                normalized_text, detected_topic
                            )
                        )
                        if gaming_exception:
                            logger.info(
                                f"[Layer 1.5] Gaming context exception: {normalized_text[:50]}... "
                                f"(UNSAFE keywords in fictional context)"
                            )
                            metadata["gaming_context_exception"] = True
                            metadata["layers_checked"].append("context_classifier")
                            # Continue to TAG-3 (grooming checks still active!)
                            # Don't block here - let grooming detector decide
                        else:
                            # Real-world violence - block immediately
                            logger.warning(
                                f"[UNSAFE] Unsafe topic detected (no gaming context): {normalized_text[:50]}..."
                            )
                            metadata["layers_checked"].append("unsafe_topic_detection")
                            return PolicyDecision.block_grooming(
                                category="unsafe_topic",
                                safe_response="I cannot help with this topic as it may not be safe.",
                                metadata=metadata,
                                detected_topic=detected_topic,
                            )
                    except Exception as e:
                        logger.warning(
                            f"[Layer 1.5] ContextClassifier error: {e}. Falling back to strict blocking."
                        )
                        # Fail-safe: Block if classifier fails
                        metadata["layers_checked"].append("unsafe_topic_detection")
                        return PolicyDecision.block_grooming(
                            category="unsafe_topic",
                            safe_response="I cannot help with this topic as it may not be safe.",
                            metadata=metadata,
                            detected_topic=detected_topic,
                        )
                else:
                    # No ContextClassifier available - strict blocking (v1.1 behavior)
                    logger.warning(
                        f"[UNSAFE] Unsafe topic detected: {normalized_text[:50]}..."
                    )
                    metadata["layers_checked"].append("unsafe_topic_detection")
                    return PolicyDecision.block_grooming(
                        category="unsafe_topic",
                        safe_response="I cannot help with this topic as it may not be safe.",
                        metadata=metadata,
                        detected_topic=detected_topic,
                    )

            # Convert topic_id to Topic enum for Meta Guard
            if HAS_META_GUARD and Topic:
                topic_id_lower = route_result.topic_id.lower()
                if topic_id_lower == "meta_system":
                    topic_enum = Topic.META_SYSTEM
                elif topic_id_lower == "unsafe":
                    topic_enum = Topic.UNSAFE
                elif "science" in topic_id_lower or topic_id_lower in [
                    "evolution_origins",
                    "creation_bigbang",
                    "earth_age",
                    "climate_science",
                ]:
                    topic_enum = Topic.SCIENCE
                elif "history" in topic_id_lower:
                    topic_enum = Topic.HISTORY
                else:
                    topic_enum = Topic.GENERAL_CHAT

        # ============================================================
        # Layer 2.5: MetaExploitationGuard (HYDRA-13)
        # ============================================================
        # Check for meta-exploitation attempts BEFORE TAG-3
        # This prevents users from probing the system's security logic
        if self.meta_guard and topic_enum is not None:
            meta_result = self.meta_guard.validate(normalized_text, topic_enum)
            if not meta_result.is_safe:
                logger.warning(
                    f"[HYDRA-13] Meta-Exploitation blocked: {meta_result.reason}"
                )
                metadata["layers_checked"].append("meta_exploitation_guard")
                return PolicyDecision(
                    block=True,
                    reason=meta_result.reason,
                    status="BLOCKED_META_EXPLOITATION",
                    safe_response=meta_result.explanation
                    or "I cannot answer this question.",
                    metadata=metadata,
                    detected_topic=detected_topic,
                )
            metadata["layers_checked"].append("meta_exploitation_guard")
            if detected_topic:
                logger.debug(
                    f"[Topic Router Phase 1] Detected topic: {detected_topic} "
                    f"(confidence: {routing_confidence:.2f})"
                )

        # ============================================================
        # Layer 1-A: PersonaSkeptic (v2.0 - NEMESIS-05 Fix)
        # ============================================================
        # Check for Social Engineering / Framing BEFORE semantic analysis
        # If framing detected, lower semantic threshold (make system stricter)
        skepticism_penalty = 0.0
        adjusted_semantic_threshold = (
            self.grooming_detector.semantic_threshold
            if self.grooming_detector
            else 0.75
        )

        if self.persona_skeptic:
            try:
                adjusted_threshold, penalty = (
                    self.persona_skeptic.get_adjusted_threshold(
                        adjusted_semantic_threshold, normalized_text
                    )
                )
                skepticism_penalty = penalty
                adjusted_semantic_threshold = adjusted_threshold
                metadata["persona_skepticism"] = {
                    "penalty": penalty,
                    "original_threshold": adjusted_semantic_threshold + penalty,
                    "adjusted_threshold": adjusted_threshold,
                }
                metadata["layers_checked"].append("persona_skeptic")
                if penalty > 0:
                    logger.warning(
                        f"[Layer 1-A] PersonaSkeptic penalty: {penalty:.2f} "
                        f"(threshold: {adjusted_semantic_threshold + penalty:.2f} -> {adjusted_threshold:.2f})"
                    )
            except Exception as e:
                logger.warning(f"[Layer 1-A] PersonaSkeptic error: {e}")
                # Fail-safe: Continue with original threshold

        # ============================================================
        # TAG-3: Behavioral Integrity (Grooming Detection)
        # ============================================================
        logger.debug(
            f"[TAG-3] Checking behavioral integrity: {normalized_text[:50]}..."
        )

        # Use normalized text for grooming detection
        grooming_result: GroomingResult = self.grooming_detector.validate(
            normalized_text, context_history
        )
        metadata["layers_checked"].append("grooming_detector")
        metadata["grooming_result"] = {
            "detected": grooming_result.detected,
            "category": grooming_result.category,
            "confidence": grooming_result.confidence,
            "action": grooming_result.action,
        }

        # Extract semantic score for TAG-4 SessionMonitor
        # Score is confidence from grooming_result (0.0-1.0)
        semantic_score = grooming_result.confidence if grooming_result.detected else 0.0

        # If not detected by regex, check semantic guard directly for score
        # v2.0: Use adjusted threshold from PersonaSkeptic
        if not grooming_result.detected and self.grooming_detector.semantic_guard:
            try:
                is_safe, risk_desc, score = (
                    self.grooming_detector.semantic_guard.check_semantic_risk(
                        normalized_text,
                        threshold=adjusted_semantic_threshold,  # Use adjusted threshold
                    )
                )
                semantic_score = score  # Use score even if below threshold

                # v2.0: If PersonaSkeptic lowered threshold and score exceeds it, block
                if skepticism_penalty > 0 and score > adjusted_semantic_threshold:
                    logger.warning(
                        f"[Layer 1-A] Social Engineering detected via adjusted threshold: "
                        f"score={score:.2f} > threshold={adjusted_semantic_threshold:.2f}"
                    )
                    # Mark as detected for blocking
                    grooming_result.detected = True
                    grooming_result.category = "social_engineering"
                    grooming_result.confidence = score
                    grooming_result.action = "BLOCK"
                    grooming_result.safe_response = "I cannot help with this request as it appears to use social engineering techniques."
            except Exception as e:
                logger.debug(f"[TAG-4] Could not get semantic score: {e}")
                semantic_score = 0.0

        # TAG-4: Update SessionMonitor and check cumulative risk
        if self.session_monitor and user_id:
            accumulated_risk = self.session_monitor.update(
                user_id=user_id,
                current_score=semantic_score,
                topic=detected_topic,
            )
            metadata["accumulated_risk"] = accumulated_risk
            metadata["layers_checked"].append("session_monitor")

            # v1.2: Dynamic threshold based on topic AND content (for emotional detection)
            dynamic_threshold = SessionMonitor.get_dynamic_threshold(
                detected_topic, normalized_text
            )
            metadata["risk_threshold"] = dynamic_threshold

            # Check if cumulative risk exceeds dynamic threshold
            if accumulated_risk > dynamic_threshold:
                logger.warning(
                    f"[TAG-4] CUMULATIVE_RISK_EXCEEDED: User {user_id} "
                    f"accumulated_risk={accumulated_risk:.2f} > threshold={dynamic_threshold} "
                    f"(topic={detected_topic})"
                )
                # v2.0: Register violation for adaptive decay (NEMESIS-02 Fix)
                if self.session_monitor and user_id:
                    self.session_monitor.register_violation(user_id)
                return PolicyDecision.block_grooming(
                    category="cumulative_risk",
                    safe_response="I cannot continue this conversation as it may not be safe.",
                    metadata=metadata,
                    detected_topic=detected_topic,
                )

        if grooming_result.detected:
            logger.warning(
                f"[TAG-3] GROOMING DETECTED: {grooming_result.category} "
                f"(confidence: {grooming_result.confidence:.2f})"
            )
            # v2.0: Register violation for adaptive decay (NEMESIS-02 Fix)
            if self.session_monitor and user_id:
                self.session_monitor.register_violation(user_id)
            return PolicyDecision.block_grooming(
                category=grooming_result.category or "unknown",
                safe_response=grooming_result.safe_response
                or "I cannot continue this conversation due to safety guidelines.",
                metadata=metadata,
                detected_topic=detected_topic,  # Still pass topic even if blocked
            )

        logger.debug("[TAG-3] No grooming detected - input allowed")

        # ============================================================
        # Layer 4: Pragmatic Safety (Context + Intent + Time) - INPUT CHECK
        # ============================================================
        if self.pragmatic_safety_layer:
            try:
                # Extract user_id from metadata or use default
                user_id = metadata.get(
                    "user_id", metadata.get("session_id", "anonymous")
                )

                pragmatic_result = self.pragmatic_safety_layer.validate(
                    user_input=input_text,
                    topic=detected_topic,
                    user_id=user_id,
                    age_band=age_band,
                )

                if not pragmatic_result.is_safe:
                    logger.warning(
                        f"[Layer 4 Input] Blocked: {pragmatic_result.reason} "
                        f"(cumulative risk: {pragmatic_result.metadata.get('cumulative_risk', 0):.2f})"
                    )
                    metadata["layer_4_blocked"] = True
                    metadata["layer_4_reason"] = pragmatic_result.reason
                    metadata["layer_4_metadata"] = pragmatic_result.metadata
                    return PolicyDecision.block_grooming(
                        category="CUMULATIVE_RISK",
                        safe_response="I cannot continue this conversation as it may not be safe.",
                        metadata=metadata,
                        detected_topic=detected_topic,
                    )

                metadata["layer_4_checked"] = True
                metadata["layer_4_metadata"] = pragmatic_result.metadata
                logger.debug(
                    f"[Layer 4 Input] Passed: Cumulative risk {pragmatic_result.metadata.get('cumulative_risk', 0):.2f}"
                )

            except Exception as e:
                logger.error(
                    f"[Layer 4 Input] Error during validation: {e}", exc_info=True
                )
                metadata["layer_4_error"] = str(e)
                # Fail-Closed: Block on Layer 4 error (safety first)
                return PolicyDecision.block_grooming(
                    category="LAYER_4_ERROR",
                    safe_response="I cannot process this request due to a safety system error.",
                    metadata=metadata,
                    detected_topic=detected_topic,
                )

        return PolicyDecision.allow(metadata=metadata, detected_topic=detected_topic)

    def validate_output(
        self,
        user_input: str,
        llm_response: str,
        age_band: Optional[str] = None,
        topic_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        PHASE 2: Output Check (TAG-2 Truth Preservation)

        Must run AFTER the LLM generation. Validates LLM response against canonical facts.
        Topic routing is based on user_input (where keywords are clearer),
        but validation is performed on llm_response (the actual answer).

        Args:
            user_input: Original user question (for topic routing)
            llm_response: LLM-generated response to validate
            age_band: Age band (e.g., "6-8", "9-12", "13-15")
            topic_id: Topic identifier (optional, will be routed from user_input if not provided)

        Returns:
            PolicyDecision with block status and reason
        """
        # Initialize metadata (merge with existing if provided)
        if metadata is None:
            metadata = {}
        else:
            metadata = metadata.copy()  # Don't mutate caller's dict

        # Initialize/update metadata fields
        if "layers_checked" not in metadata:
            metadata["layers_checked"] = []
        metadata["age_band"] = age_band
        metadata["check_type"] = "output_validation"

        # ============================================================
        # STEP 1: Defensive Grooming Check on LLM Output
        # ============================================================
        grooming_result = self.grooming_detector.validate(llm_response)
        metadata["layers_checked"].append("grooming_detector_output")

        if grooming_result.detected:
            logger.warning(
                f"[TAG-3 Output] GROOMING DETECTED in LLM output: {grooming_result.category}"
            )
            return PolicyDecision.block_grooming(
                category=grooming_result.category or "unknown",
                safe_response=grooming_result.safe_response
                or "I cannot continue this conversation.",
                metadata=metadata,
            )

        # ============================================================
        # STEP 2: TAG-2 Truth Preservation (if enabled)
        # ============================================================
        if not self.tag2_enabled or not self.truth_validator:
            logger.debug("[TAG-2] Skipped (not enabled or not available)")
            metadata["tag2_skipped"] = True
            return PolicyDecision.allow(metadata=metadata)

        # Dynamic topic routing based on user_input (where keywords are clearer)
        if not topic_id and self.topic_router:
            route_result = self.topic_router.route(user_input)
            topic_id = route_result.topic_id
            metadata["routed_topic"] = topic_id
            metadata["routing_confidence"] = route_result.confidence
            metadata["matched_keywords"] = route_result.matched_keywords
            logger.debug(
                f"[Topic Router] Detected topic from user_input: {topic_id} "
                f"(confidence: {route_result.confidence:.2f})"
            )

        # ============================================================
        # SAFE_AXIOMS Check (HYDRA-08 Fix: Adversarial Trigger Defense)
        # ============================================================
        # Whitelist-based safety: Unknown topics are denied by default
        # Check happens AFTER topic routing but BEFORE TAG-2 validation
        # Check if we have a topic_id (or science keywords) and llm_response is available
        # HYDRA-08 Fix: Also check general_chat if it contains science keywords
        science_keywords = [
            "physik",
            "physic",
            "druck",
            "pressure",
            "volumen",
            "volume",
            "erhitzt",
            "heat",
            "behälter",
            "container",
        ]
        has_science_keywords = any(
            keyword in user_input.lower() for keyword in science_keywords
        )

        should_check_safe_axioms = (
            topic_id and topic_id != "general_chat" and llm_response
        ) or (topic_id == "general_chat" and llm_response and has_science_keywords)

        if should_check_safe_axioms and llm_response:
            logger.info(
                f"[SAFE_AXIOMS] Triggering validation: topic_id={topic_id}, "
                f"has_science_keywords={has_science_keywords}, "
                f"user_input_preview={user_input[:50]}..."
            )
            try:
                from .truth_preservation.safe_axioms import SafeAxiomsValidator

                safe_axioms_validator = SafeAxiomsValidator()
                # Map topic_id to SAFE_AXIOMS topic name
                topic_map = {
                    "earth_age": "science",
                    "evolution_origins": "science",
                    "creation_bigbang": "science",
                    "climate_science": "science",
                    "health_medicine": "health_medicine",
                    "safety_rules": "safety_rules",
                }
                # HYDRA-08 Fix: If general_chat but contains science keywords, treat as science
                if topic_id == "general_chat" and any(
                    keyword in user_input.lower()
                    for keyword in [
                        "physik",
                        "physic",
                        "druck",
                        "pressure",
                        "volumen",
                        "volume",
                        "erhitzt",
                        "heat",
                        "behälter",
                        "container",
                    ]
                ):
                    safe_axioms_topic = "science"
                else:
                    safe_axioms_topic = topic_map.get(topic_id, topic_id)

                # Limit output_text length for SAFE_AXIOMS validation (prevent timeout on very long responses)
                # Extract subtopic from first 2000 chars (enough to detect dangerous keywords)
                output_text_truncated = (
                    llm_response[:2000] if len(llm_response) > 2000 else llm_response
                )

                # Validate topic against SAFE_AXIOMS (use llm_response for subtopic extraction)
                is_safe_axiom, axiom_reason, axiom_confidence = (
                    safe_axioms_validator.validate_topic(
                        topic=safe_axioms_topic,
                        subtopic=None,  # Will be extracted from output_text
                        output_text=output_text_truncated,  # Truncated to prevent timeout
                    )
                )
                if not is_safe_axiom:
                    logger.warning(
                        f"[SAFE_AXIOMS] Blocked: {axiom_reason} (confidence: {axiom_confidence:.2f})"
                    )
                    metadata["safe_axioms_blocked"] = True
                    metadata["safe_axioms_reason"] = axiom_reason
                    return PolicyDecision.block_truth_violation(
                        reason=f"SAFE_AXIOMS: {axiom_reason}",
                        safe_response="I cannot provide information on this topic as it is not covered by safety guidelines.",
                        metadata=metadata,
                    )
            except ImportError:
                logger.debug("[SAFE_AXIOMS] Not available, skipping whitelist check")
            except Exception as e:
                logger.error(f"[SAFE_AXIOMS] Error: {e}", exc_info=True)
                # Fail-open: Continue if SAFE_AXIOMS fails (don't block legitimate traffic)

        # Skip TAG-2 if no topic_id (even after routing)
        if not topic_id or topic_id == "general_chat":
            logger.debug("[TAG-2] Skipped (no topic_id or general_chat)")
            metadata["tag2_skipped"] = "no_topic_id_or_general"
            return PolicyDecision.allow(metadata=metadata)

        logger.debug(
            f"[TAG-2] Checking truth preservation for topic: {topic_id} "
            f"(validating LLM response, not user question)"
        )

        # Load canonical facts and gates config for topic_id
        try:
            # Map topic_id to filename
            filename_base = self.topic_to_filename.get(topic_id, topic_id)
            canonical_path = (
                self.canonical_facts_dir / f"age_canonical_{filename_base}.yaml"
            )

            if not canonical_path.exists():
                logger.warning(
                    f"[TAG-2] Canonical facts not found for topic {topic_id} at {canonical_path}"
                )
                metadata["tag2_skipped"] = "canonical_facts_not_found"
                return PolicyDecision.allow(metadata=metadata)

            # Load canonical facts
            with open(canonical_path, "r", encoding="utf-8") as f:
                canonical_data = yaml.safe_load(f)

            # Load gates config
            with open(self.gates_config_path, "r", encoding="utf-8") as f:
                gates_config = yaml.safe_load(f)

            # Extract age-specific canonical facts
            if not age_band:
                age_band = "9-12"  # Default age band

            age_canonical = canonical_data.get("age_canonical", {}).get(age_band)
            if not age_canonical:
                logger.warning(
                    f"[TAG-2] No canonical facts for age band {age_band} in topic {topic_id}"
                )
                metadata["tag2_skipped"] = "age_band_not_found"
                return PolicyDecision.allow(metadata=metadata)

            age_canonical_facts = age_canonical.get("facts", [])
            key_slots_raw = age_canonical.get("key_slots", [])
            # Extract slot descriptions from "slot_id: description" format
            age_canonical_slots = [
                slot.split(":", 1)[1].strip() if ":" in slot else slot
                for slot in key_slots_raw
            ]
            slot_anchors = age_canonical.get("anchors", {})

            # Get Master Guarded Facts (GMF)
            master_guarded_facts = (
                gates_config.get("truth_preservation", {})
                .get("master_guarded_slots", {})
                .get(topic_id, [])
            )

            # Run TAG-2 validation on LLM RESPONSE (not user input)
            validation_result = self.truth_validator.validate(
                adapted_answer=llm_response,  # <-- CRITICAL: Validate LLM output, not user question
                age_canonical_facts=age_canonical_facts,
                age_canonical_slots=age_canonical_slots,
                master_guarded_facts=master_guarded_facts,
                gates_config=gates_config.get("truth_preservation", {}),
                age_band=age_band,
                topic_id=topic_id,
                cultural_context="none",
                slot_anchors=slot_anchors,
            )

            metadata["layers_checked"].append("truth_preservation_validator")
            metadata["tag2_result"] = {
                "overall_pass": validation_result.overall_pass,
                "veto_age_passed": validation_result.veto_age_passed,
                "veto_age_c_rate": validation_result.veto_age_c_rate,
                "entailment_rate": validation_result.entailment_rate,
            }

            if not validation_result.overall_pass:
                logger.warning(
                    f"[TAG-2] TRUTH VIOLATION DETECTED in LLM response for topic {topic_id}: "
                    f"VETO={validation_result.veto_age_c_rate:.2%}, "
                    f"Entailment={validation_result.entailment_rate:.2%}"
                )
                return PolicyDecision.block_truth_violation(
                    reason=f"Truth violation detected in LLM response: VETO rate {validation_result.veto_age_c_rate:.2%}",
                    safe_response="I cannot answer this question in this way. Let's look at the facts.",
                    metadata=metadata,
                )

            logger.debug("[TAG-2] Truth preservation check passed")

        except Exception as e:
            logger.error(f"[TAG-2] Error during validation: {e}", exc_info=True)
            metadata["tag2_error"] = str(e)
            # Fail-open: Allow if TAG-2 fails (could be made fail-closed)
            # Continue to Layer 4 even if TAG-2 failed

        # ============================================================
        # Layer 4: Pragmatic Safety (Context + Intent + Time)
        # ============================================================
        if self.pragmatic_safety_layer:
            try:
                # Extract user_id from metadata or use default
                user_id = metadata.get(
                    "user_id", metadata.get("session_id", "anonymous")
                )

                # Get topic_id for Layer 4
                topic_for_layer4 = topic_id
                if not topic_for_layer4 and self.topic_router:
                    route_result = self.topic_router.route(user_input)
                    topic_for_layer4 = (
                        route_result.topic_id
                        if route_result.topic_id != "general_chat"
                        else None
                    )

                pragmatic_result = self.pragmatic_safety_layer.validate(
                    user_input=user_input,
                    topic=topic_for_layer4,
                    user_id=user_id,
                    age_band=age_band,
                )

                if not pragmatic_result.is_safe:
                    logger.warning(
                        f"[Layer 4] Blocked: {pragmatic_result.reason} "
                        f"(cumulative risk: {pragmatic_result.metadata.get('cumulative_risk', 0):.2f})"
                    )
                    metadata["layer_4_blocked"] = True
                    metadata["layer_4_reason"] = pragmatic_result.reason
                    metadata["layer_4_metadata"] = pragmatic_result.metadata
                    return PolicyDecision.block_grooming(
                        category="CUMULATIVE_RISK",
                        safe_response="I cannot continue this conversation as it may not be safe.",
                        metadata=metadata,
                    )

                metadata["layer_4_checked"] = True
                metadata["layer_4_metadata"] = pragmatic_result.metadata
                logger.debug(
                    f"[Layer 4] Passed: Cumulative risk {pragmatic_result.metadata.get('cumulative_risk', 0):.2f}"
                )

            except Exception as e:
                logger.error(f"[Layer 4] Error during validation: {e}", exc_info=True)
                metadata["layer_4_error"] = str(e)
                # Fail-Closed: Block on Layer 4 error (safety first)
                return PolicyDecision.block_grooming(
                    category="LAYER_4_ERROR",
                    safe_response="I cannot process this request due to a safety system error.",
                    metadata=metadata,
                )

        return PolicyDecision.allow(metadata=metadata)

    # Backward compatibility: keep check() as alias for validate_input()
    def check(
        self,
        input_text: str,
        age_band: Optional[str] = None,
        topic_id: Optional[str] = None,
        context_history: Optional[list] = None,
    ) -> PolicyDecision:
        """
        Legacy method: Alias for validate_input()

        DEPRECATED: Use validate_input() for input checks and validate_output() for output checks.
        This method is kept for backward compatibility but only performs input validation (TAG-3).
        """
        logger.warning(
            "[DEPRECATED] check() method is deprecated. Use validate_input() and validate_output() instead."
        )
        return self.validate_input(input_text, age_band, context_history)


# Convenience function for direct usage
def create_kids_policy_engine(
    profile: str = "kids", config: Optional[Dict[str, Any]] = None
) -> Optional[KidsPolicyEngine]:
    """
    Factory function to create Kids Policy Engine

    Args:
        profile: Policy profile ("kids" enables engine, None/other disables)
        config: Optional configuration dict

    Returns:
        KidsPolicyEngine instance or None if profile != "kids"
    """
    if profile != "kids":
        return None

    try:
        return KidsPolicyEngine(
            enable_tag2=config.get("enable_tag2", True) if config else True
        )
    except Exception as e:
        logger.error(f"Failed to create Kids Policy Engine: {e}")
        return None
