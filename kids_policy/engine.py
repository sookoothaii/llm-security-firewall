#!/usr/bin/env python3
"""
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

logger = logging.getLogger(__name__)


@dataclass
class PolicyDecision:
    """Decision from Kids Policy Engine"""

    block: bool
    reason: str
    status: str  # "ALLOWED", "BLOCKED_GROOMING", "BLOCKED_TRUTH_VIOLATION"
    safe_response: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    @classmethod
    def allow(cls, metadata: Optional[Dict[str, Any]] = None):
        """Create allow decision"""
        return cls(
            block=False,
            reason="All policy checks passed",
            status="ALLOWED",
            metadata=metadata or {},
        )

    @classmethod
    def block_grooming(
        cls,
        category: str,
        safe_response: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Create grooming block decision"""
        return cls(
            block=True,
            reason=f"GROOMING_ATTEMPT: {category}",
            status="BLOCKED_GROOMING",
            safe_response=safe_response,
            metadata=metadata or {},
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

        # Initialize Topic Router (for dynamic topic detection)
        self.topic_router: Optional[TopicRouter] = None
        if HAS_ROUTER:
            if topic_map_path is None:
                base_path = Path(__file__).parent / "config"
                topic_map_path = str(base_path / "topic_map_v1.yaml")

            try:
                self.topic_router = TopicRouter(topic_map_path)
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
        }

    def validate_input(
        self,
        input_text: str,
        age_band: Optional[str] = None,
        context_history: Optional[list] = None,
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
        metadata: Dict[str, Any] = {
            "layers_checked": [],
            "age_band": age_band,
            "check_type": "input_validation",
        }

        # ============================================================
        # TAG-3: Behavioral Integrity (Grooming Detection)
        # ============================================================
        logger.debug(f"[TAG-3] Checking behavioral integrity: {input_text[:50]}...")

        grooming_result: GroomingResult = self.grooming_detector.validate(
            input_text, context_history
        )
        metadata["layers_checked"].append("grooming_detector")
        metadata["grooming_result"] = {
            "detected": grooming_result.detected,
            "category": grooming_result.category,
            "confidence": grooming_result.confidence,
            "action": grooming_result.action,
        }

        if grooming_result.detected:
            logger.warning(
                f"[TAG-3] GROOMING DETECTED: {grooming_result.category} "
                f"(confidence: {grooming_result.confidence:.2f})"
            )
            return PolicyDecision.block_grooming(
                category=grooming_result.category or "unknown",
                safe_response=grooming_result.safe_response
                or "I cannot continue this conversation due to safety guidelines.",
                metadata=metadata,
            )

        logger.debug("[TAG-3] No grooming detected - input allowed")
        return PolicyDecision.allow(metadata=metadata)

    def validate_output(
        self,
        user_input: str,
        llm_response: str,
        age_band: Optional[str] = None,
        topic_id: Optional[str] = None,
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
        metadata: Dict[str, Any] = {
            "layers_checked": [],
            "age_band": age_band,
            "check_type": "output_validation",
        }

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
            return PolicyDecision.allow(metadata=metadata)

        except Exception as e:
            logger.error(f"[TAG-2] Error during validation: {e}", exc_info=True)
            metadata["tag2_error"] = str(e)
            # Fail-open: Allow if TAG-2 fails (could be made fail-closed)
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
