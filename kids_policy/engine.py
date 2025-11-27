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
from typing import Optional, Dict, Any
from dataclasses import dataclass
from pathlib import Path

# Import validators
from .truth_preservation.validators.grooming_detector import (
    GroomingDetector,
    GroomingResult,
)

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
        cls, reason: str, metadata: Optional[Dict[str, Any]] = None
    ):
        """Create truth violation block decision"""
        return cls(
            block=True,
            reason=f"TRUTH_VIOLATION: {reason}",
            status="BLOCKED_TRUTH_VIOLATION",
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
    ):
        """
        Initialize Kids Policy Engine

        Args:
            grooming_config_path: Path to behavioral_integrity_v0_1.yaml
                                 If None, uses default path
            enable_tag2: Enable TAG-2 Truth Preservation (default: True)
            tag2_config: Configuration for TAG-2 (gates, canonical facts, etc.)
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

    def check(
        self,
        input_text: str,
        age_band: Optional[str] = None,
        topic_id: Optional[str] = None,
        context_history: Optional[list] = None,
    ) -> PolicyDecision:
        """
        Check input against Kids Policy (TAG-3 → TAG-2)

        Pipeline:
        1. TAG-3: Behavioral Integrity (Grooming Detection)
        2. TAG-2: Truth Preservation (if TAG-3 passes)

        Args:
            input_text: Text to validate
            age_band: Age band (e.g., "6-8", "9-12", "13-15")
            topic_id: Topic identifier for TAG-2 (optional)
            context_history: Previous messages in conversation (for multi-turn detection)

        Returns:
            PolicyDecision with block status and reason
        """
        metadata: Dict[str, Any] = {
            "layers_checked": [],
            "age_band": age_band,
            "topic_id": topic_id,
        }

        # ============================================================
        # STEP 1: TAG-3 - Behavioral Integrity (Safety First)
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
                or "I cannot continue this conversation.",
                metadata=metadata,
            )

        logger.debug("[TAG-3] No grooming detected - proceeding to TAG-2")

        # ============================================================
        # STEP 2: TAG-2 - Truth Preservation (Truth Second)
        # ============================================================
        if not self.tag2_enabled or not self.truth_validator:
            logger.debug("[TAG-2] Skipped (not enabled or not available)")
            metadata["tag2_skipped"] = True
            return PolicyDecision.allow(metadata=metadata)

        # TAG-2 requires topic_id and canonical facts
        if not topic_id:
            logger.debug("[TAG-2] Skipped (no topic_id provided)")
            metadata["tag2_skipped"] = "no_topic_id"
            return PolicyDecision.allow(metadata=metadata)

        logger.debug(f"[TAG-2] Checking truth preservation for topic: {topic_id}")

        # TODO: Load canonical facts and gates config for topic_id
        # For now, TAG-2 is a placeholder that requires full configuration
        # This will be implemented when TAG-2 integration is fully specified
        metadata["tag2_skipped"] = "not_fully_configured"
        logger.debug(
            "[TAG-2] Skipped (not fully configured - requires canonical facts)"
        )

        return PolicyDecision.allow(metadata=metadata)

    def check_output(
        self,
        output_text: str,
        age_band: Optional[str] = None,
        topic_id: Optional[str] = None,
    ) -> PolicyDecision:
        """
        Check LLM output against Kids Policy (output validation)

        Currently only checks for grooming patterns in output.
        TAG-2 output validation can be added here.

        Args:
            output_text: LLM-generated text to validate
            age_band: Age band
            topic_id: Topic identifier

        Returns:
            PolicyDecision
        """
        # Check output for grooming patterns (defensive check)
        grooming_result = self.grooming_detector.validate(output_text)

        if grooming_result.detected:
            logger.warning(
                f"[TAG-3 Output] GROOMING DETECTED in LLM output: {grooming_result.category}"
            )
            return PolicyDecision.block_grooming(
                category=grooming_result.category or "unknown",
                safe_response=grooming_result.safe_response
                or "I cannot continue this conversation.",
                metadata={"check_type": "output_validation"},
            )

        return PolicyDecision.allow(metadata={"check_type": "output_validation"})


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
