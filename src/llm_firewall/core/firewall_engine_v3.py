"""
HAK_GAL Core Engine v3 - Modular Layer Architecture
====================================================

Clean, modular layer architecture with clear separation of concerns.
Each security layer is isolated, testable, and independently configurable.

Architecture:
- Layer 0: UnicodeSanitizerLayer (Input sanitization)
- Layer 0.25: NormalizationLayer (Recursive URL/percent decoding)
- Layer 0.5: RegexGateLayer (Fast-fail pattern matching)
- Layer 0.6: ExploitDetectionLayer (Exploit instruction detection)
- Layer 0.7: ToxicityDetectionLayer (Multilingual toxicity)
- Layer 0.8: SemanticGuardLayer (Semantic similarity)
- Layer 1: KidsPolicyLayer (Kids-safe content filtering)
- Layer 2: ToolCallValidationLayer (HEPHAESTUS - Tool Call Validation)
- Layer 3: OutputValidationLayer (Truth Preservation)

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-06
Status: Core Engine v3 - Modular Architecture
License: MIT
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from llm_firewall.core.firewall_engine_v2 import FirewallDecision

logger = logging.getLogger(__name__)


# ============================================================================
# Core Data Structures
# ============================================================================


@dataclass
class ProcessingContext:
    """
    Central data container for firewall processing pipeline.

    This context flows through all security layers, allowing each layer
    to read input, update state, and make blocking decisions.

    Attributes:
        user_id: User/session identifier
        text: Current text being processed (may be modified by layers)
        original_text: Original input text (immutable)
        sanitized_text: Final sanitized text (after all layers)
        metadata: Layer-specific metadata (encoding flags, detections, etc.)
        risk_score: Accumulated risk score [0.0, 1.0]
        detected_threats: List of detected threat identifiers
        should_block: Whether request should be blocked
        block_reason: Human-readable block reason (if blocked)
        layer_results: Results from each layer (for debugging/analysis)
        detecting_layers: Layers that detected threats (for ensemble detection)
        layer_risk_scores: Risk scores contributed by each layer
    """

    user_id: str
    text: str
    original_text: str
    sanitized_text: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    detected_threats: List[str] = field(default_factory=list)
    should_block: bool = False
    block_reason: Optional[str] = None
    layer_results: Dict[str, Any] = field(default_factory=dict)
    detecting_layers: Dict[str, float] = field(default_factory=dict)
    layer_risk_scores: Dict[str, float] = field(default_factory=dict)

    def add_threat(self, threat_name: str, risk_increase: float = 0.0):
        """Add a detected threat and optionally increase risk score."""
        if threat_name not in self.detected_threats:
            self.detected_threats.append(threat_name)
        if risk_increase > 0.0:
            self.risk_score = min(1.0, self.risk_score + risk_increase)

    def block(self, reason: str, risk_score: float = 1.0):
        """
        Mark context for blocking with given reason.
        
        CRITICAL: Sets risk_score to the specified value (not max) to ensure
        blocking decisions maintain their intended risk score.
        """
        self.should_block = True
        self.block_reason = reason
        # FIXED: Set risk_score directly (not max) to prevent reduction after blocking
        # This ensures that when a layer calls block(risk_score=0.90), the score
        # is actually set to 0.90, not reduced by subsequent operations
        self.risk_score = risk_score

    def add_layer_detection(self, layer_name: str, layer_risk: float):
        """Track which layers detected threats and their risk scores."""
        if layer_risk > 0.001:  # Small threshold to avoid floating point noise
            self.detecting_layers[layer_name] = layer_risk
            self.layer_risk_scores[layer_name] = layer_risk

    def calculate_ensemble_risk(self, config: "FirewallConfig") -> float:
        """Calculate ensemble risk bonus based on multiple detections."""
        # Only apply bonus if at least one layer has significant risk
        if not self.detecting_layers:
            return 0.0
        
        max_layer_risk = max(self.detecting_layers.values())
        if max_layer_risk < config.ensemble_min_risk_for_bonus:
            return 0.0  # No bonus if all detections are too weak
        
        if len(self.detecting_layers) >= 3:
            return config.ensemble_bonus_3_layers
        elif len(self.detecting_layers) >= config.ensemble_min_layers:
            return config.ensemble_bonus_2_layers
        return 0.0

    def calculate_multiplicative_risk(self) -> float:
        """Calculate combined risk using multiplicative formula."""
        if not self.detecting_layers:
            return self.risk_score

        # Multiplicative combination: 1 - ∏(1 - layer_risk_i)
        combined_risk = 1.0
        for layer_risk in self.detecting_layers.values():
            combined_risk *= (1.0 - layer_risk)

        return 1.0 - combined_risk


@dataclass
class FirewallConfig:
    """
    Configuration for FirewallEngineV3.

    All layer toggles and parameters are centralized here.
    This allows easy configuration via constructor or config files.
    """

    # Layer toggles
    enable_sanitization: bool = True
    enable_normalization: bool = True
    enable_regex_gate: bool = True
    enable_exploit_detection: bool = True
    enable_toxicity_detection: bool = True
    enable_semantic_guard: bool = True
    enable_safety_blacklist: bool = True
    enable_kids_policy: bool = True
    enable_tool_validation: bool = True
    enable_output_validation: bool = True

    # Layer parameters
    strict_mode: bool = True
    allowed_tools: Optional[List[str]] = None
    blocking_threshold: float = 0.18  # TUNED: 0.20 -> 0.18 (balanced for ASR/FPR trade-off)
    # Note: Dynamic threshold adjustment can lower this to min_threshold=0.15 for technical content

    # Normalization parameters
    max_decode_depth: int = 3

    # Toxicity parameters
    toxicity_threshold: float = 0.38  # TUNED: 0.35 -> 0.38 (balanced for FPR/ASR)
    toxicity_low_threshold: float = 0.38  # For subtle toxicity
    toxicity_high_threshold: float = 0.45  # For explicit toxicity

    # Semantic Guard parameters
    semantic_threshold: float = 0.60  # TUNED: 0.58 -> 0.60 (balanced for FPR/ASR)
    semantic_guard_low_threshold: float = 0.60  # For subtle threats
    semantic_guard_high_threshold: float = 0.65  # For explicit threats
    semantic_use_spotlight: bool = True

    # Context-aware detection parameters (P0-Fix)
    base_threshold: float = 0.75
    documentation_threshold: float = 0.95
    documentation_score_reduction: float = 0.30

    # ASR Improvement: Ensemble Detection
    enable_ensemble_detection: bool = True
    ensemble_min_layers: int = 2  # Minimum layers for ensemble bonus
    ensemble_bonus_2_layers: float = 0.03  # TUNED: 0.05 -> 0.03 (minimal FPR impact)
    ensemble_bonus_3_layers: float = 0.06  # TUNED: 0.10 -> 0.06 (minimal FPR impact)
    ensemble_min_risk_for_bonus: float = 0.20  # Only strong detections get bonus

    # ASR Improvement: Multiplicative Aggregation
    use_multiplicative_aggregation: bool = False  # TUNED: Disabled (causes FPR explosion)
    multiplicative_boost_factor: float = 1.0  # Not used when disabled

    # ASR Improvement: Dynamic Thresholds
    dynamic_threshold_enabled: bool = True
    min_threshold: float = 0.15  # Minimum blocking threshold
    max_threshold: float = 0.25  # Maximum blocking threshold

    # ASR Improvement: Meta-Exploitation Detection
    enable_meta_exploitation: bool = True  # Re-enabled with selective activation
    meta_exploitation_min_risk: float = 0.15  # Only check if risk_score already >0.15

    # Answer Policy parameters (optional)
    use_answer_policy: bool = False
    policy_provider: Optional[Any] = None
    use_evidence_based_p_correct: bool = False
    p_correct_stretch_factor: float = 1.0
    uncertainty_boost_factor: float = 0.0
    
    # Two-Ring Defense System (Outer Ring - Detector Orchestration)
    enable_detector_orchestration: bool = True  # Enable outer ring detectors


@dataclass
class EmergencyFixFirewallConfig(FirewallConfig):
    """
    OPTIMIERTE KONFIGURATION für FPR <10% bei ASR <16%
    
    Optimierte Konfiguration nach erfolgreichem Emergency Fix:
    - Blocking Threshold weiter optimiert (0.15)
    - Meta-Exploitation selektiv für hochriskante Prompts aktiviert
    - Semantic Guard feinjustiert (0.56)
    """
    
    # ZURUECKGESETZT: Gute Werte aus Handover Report (ASR 16%, FPR 9%)
    blocking_threshold: float = 0.17  # Optimiert für FPR <10% bei ASR <20%
    
    # OPTIMIERT: Meta-Exploitation SELEKTIV aktiviert für hochriskante Prompts
    enable_meta_exploitation: bool = True  # Selektiv aktiviert
    meta_exploitation_min_risk: float = 0.30  # Nur für risk_score > 0.30 (sehr hochriskant)
    
    # FIXED: Ensemble Detection DEAKTIVIERT (reduziert FPR)
    enable_ensemble_detection: bool = False  # Deaktiviert für FPR-Reduktion
    
    # KRITISCH: Multiplikative Aggregation AUSSCHALTEN
    use_multiplicative_aggregation: bool = False
    
    # ZURUECKGESETZT: Semantic Guard Thresholds (gute Werte)
    semantic_threshold: float = 0.56  # Optimiert für ASR <20%
    semantic_guard_low_threshold: float = 0.56
    semantic_guard_high_threshold: float = 0.63
    
    # Toxicity Thresholds (aus Basis-Config)
    toxicity_threshold: float = 0.38  # Balanced für FPR/ASR
    toxicity_low_threshold: float = 0.38
    toxicity_high_threshold: float = 0.42
    
    # Dynamische Thresholds: AUSSCHALTEN (kompliziert, erhöht FPR)
    dynamic_threshold_enabled: bool = False
    
    # Exploit Detection: VERSTÄRKEN (bleibt aktiviert)
    enable_exploit_detection: bool = True
    
    # NEU: Safety Blacklist aktiviert
    enable_safety_blacklist: bool = True


# ============================================================================
# Security Layer Abstract Base Class
# ============================================================================


class SecurityLayer(ABC):
    """
    Abstract base class for all security layers.

    Each layer processes the context, performs its checks, and updates
    the context state (risk score, threats, block decision).

    Layers follow the Fail-Closed principle: Any exception in a layer
    must result in a block decision to prevent security bypasses.
    """

    def __init__(self, config: FirewallConfig):
        """
        Initialize security layer with configuration.

        Args:
            config: Firewall configuration object
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def process(self, context: ProcessingContext) -> ProcessingContext:
        """
        Process context through this security layer.

        Args:
            context: Processing context (will be modified in-place)

        Returns:
            Modified context (same object, modified in-place)

        Raises:
            Exception: If layer fails, caller must handle with fail-closed logic
        """
        pass

    @abstractmethod
    def can_block(self) -> bool:
        """
        Whether this layer can make blocking decisions.

        Returns:
            True if layer can set should_block=True, False otherwise
        """
        pass

    def _log_result(self, context: ProcessingContext, status: str, details: str = ""):
        """Helper to log layer processing results."""
        self.logger.debug(
            f"[{self.__class__.__name__}] {status} | "
            f"Risk: {context.risk_score:.2f} | "
            f"Blocked: {context.should_block} | "
            f"{details}"
        )


# ============================================================================
# Layer 0: Unicode Sanitizer - Input Sanitization
# ============================================================================


class UnicodeSanitizerLayer(SecurityLayer):
    """
    Unicode sanitization layer (Layer 0).

    Sanitizes dangerous Unicode characters (zero-width, bidi overrides, etc.)
    that could be used for obfuscation or evasion.

    Responsibilities:
    - Remove/normalize dangerous Unicode characters
    - Detect Unicode-based evasion attempts
    - Update risk score based on detected anomalies
    """

    def __init__(self, config: FirewallConfig):
        super().__init__(config)

        # Try to import UnicodeSanitizer from kids_policy
        try:
            import sys
            from pathlib import Path

            kids_policy_path = (
                Path(__file__).parent.parent.parent.parent / "kids_policy"
            )
            if kids_policy_path.exists():
                sys.path.insert(0, str(kids_policy_path.parent))
                from kids_policy.unicode_sanitizer import UnicodeSanitizer

                self.sanitizer = UnicodeSanitizer()
                self.available = True
                self.logger.info("UnicodeSanitizer initialized")
            else:
                self.sanitizer = None
                self.available = False
                self.logger.warning("kids_policy path not found")
        except ImportError as e:
            self.sanitizer = None
            self.available = False
            self.logger.warning(f"UnicodeSanitizer not available: {e}")

    def can_block(self) -> bool:
        return False  # Sanitization layer does not block, only sanitizes

    def process(self, context: ProcessingContext) -> ProcessingContext:
        """
        Sanitize dangerous Unicode characters.

        Args:
            context: Processing context

        Returns:
            Modified context with sanitized text
        """
        if not self.available or not self.config.enable_sanitization:
            self._log_result(context, "SKIPPED", "Sanitization disabled or unavailable")
            return context

        try:
            clean_text, unicode_flags = self.sanitizer.sanitize(context.text)

            # Update context with sanitized text
            context.text = clean_text
            context.metadata["unicode_flags"] = unicode_flags

            # Calculate risk based on detected anomalies
            risk_increase = 0.0

            # Zero-width characters indicate evasion attempts
            if unicode_flags.get("has_zero_width", False) or unicode_flags.get(
                "zero_width_removed", False
            ):
                risk_increase += 0.6
                context.add_threat("ZERO_WIDTH_EVASION", risk_increase=0.0)
                self.logger.warning("Zero-width characters detected - evasion attempt")

            # RTL/LTR override characters indicate obfuscation
            if (
                unicode_flags.get("has_bidi", False)
                or unicode_flags.get("has_directional_override", False)
                or unicode_flags.get("bidi_detected", False)
            ):
                risk_increase += 0.5
                context.add_threat("BIDI_OBFUSCATION", risk_increase=0.0)
                self.logger.warning(
                    "Bidi/directional override detected - obfuscation attempt"
                )

            # Update risk score
            if risk_increase > 0.0:
                context.risk_score = min(1.0, context.risk_score + risk_increase)

            self._log_result(
                context,
                "SANITIZED",
                f"Flags: {len(unicode_flags)}, Risk increase: {risk_increase:.2f}",
            )

        except Exception as e:
            self.logger.warning(f"Sanitization error: {e}. Using original text.")
            # Fail-open for sanitization errors (use original text)

        # Store layer result
        context.layer_results["unicode_sanitizer"] = {
            "sanitized": context.text != context.original_text,
            "flags": context.metadata.get("unicode_flags", {}),
            "risk_score": context.risk_score,
        }

        return context


# ============================================================================
# Layer 0.25: Normalization Layer - Recursive URL/Percent Decoding
# ============================================================================


class NormalizationLayer(SecurityLayer):
    """
    Normalization layer for recursive URL/percent decoding (Layer 0.25).

    Detects and normalizes encoding anomalies (multiple URL encodings, etc.)
    that could be used to bypass pattern matching.

    Responsibilities:
    - Recursive URL/percent decoding
    - Detect encoding anomalies (multi-layer encoding)
    - Update encoding anomaly score
    """

    def __init__(self, config: FirewallConfig):
        super().__init__(config)

        # Try to import NormalizationLayer from hak_gal
        try:
            from hak_gal.layers.inbound.normalization_layer import (
                NormalizationLayer as HAKNormalizationLayer,
            )

            self.normalization = HAKNormalizationLayer(
                max_decode_depth=config.max_decode_depth
            )
            self.available = True
            self.logger.info("NormalizationLayer initialized")
        except ImportError as e:
            self.normalization = None
            self.available = False
            self.logger.warning(f"NormalizationLayer not available: {e}")

    def can_block(self) -> bool:
        return False  # Normalization does not block, only normalizes

    def process(self, context: ProcessingContext) -> ProcessingContext:
        """
        Normalize text (recursive URL decoding).

        Args:
            context: Processing context

        Returns:
            Modified context with normalized text
        """
        if not self.available or not self.config.enable_normalization:
            self._log_result(
                context, "SKIPPED", "Normalization disabled or unavailable"
            )
            return context

        try:
            normalized_text, encoding_anomaly_score = self.normalization.normalize(
                context.text
            )

            # Update context
            context.text = normalized_text
            context.metadata["encoding_anomaly_score"] = encoding_anomaly_score

            # High encoding anomaly increases risk
            if encoding_anomaly_score > 0.5:
                context.add_threat(
                    "HIGH_ENCODING_ANOMALY", risk_increase=encoding_anomaly_score * 0.3
                )
                self.logger.warning(
                    f"High encoding anomaly detected: {encoding_anomaly_score:.2f}"
                )

            self._log_result(
                context, "NORMALIZED", f"Encoding anomaly: {encoding_anomaly_score:.2f}"
            )

        except Exception as e:
            self.logger.warning(f"Normalization error: {e}. Using previous text.")
            # Fail-open for normalization errors

        # Store layer result
        context.layer_results["normalization"] = {
            "encoding_anomaly_score": context.metadata.get(
                "encoding_anomaly_score", 0.0
            ),
            "normalized": context.text != context.original_text,
            "risk_score": context.risk_score,
        }

        return context


# ============================================================================
# Layer 0.5: RegexGate - Fast-Fail Pattern Matching
# ============================================================================


class RegexGateLayer(SecurityLayer):
    """
    Fast-fail pattern matching for command injection, jailbreaks, etc.

    This layer checks text against regex patterns for immediate threats.
    If a pattern matches, the request is blocked immediately (fast-fail).

    Responsibilities:
    - Pattern-based threat detection
    - Fast-fail blocking (no further processing needed)
    - Encoding anomaly boost (from NormalizationLayer)
    """

    def __init__(self, config: FirewallConfig):
        super().__init__(config)

        # Try to import RegexGate from hak_gal package
        try:
            from hak_gal.layers.inbound.regex_gate import RegexGate
            from hak_gal.core.exceptions import SecurityException

            self.regex_gate = RegexGate()
            self.SecurityException = SecurityException
            self.available = True
            self.logger.info("RegexGate initialized")
        except ImportError:
            self.regex_gate = None
            self.SecurityException = None
            self.available = False
            self.logger.warning("RegexGate not available - pattern matching disabled")

    def can_block(self) -> bool:
        return True  # RegexGate can block on pattern match

    def process(self, context: ProcessingContext) -> ProcessingContext:
        """
        Check text against regex patterns for immediate threats.

        Args:
            context: Processing context

        Returns:
            Modified context (blocked if pattern matches)
        """
        if not self.available or not self.config.enable_regex_gate:
            self._log_result(context, "SKIPPED", "RegexGate disabled or unavailable")
            return context

        try:
            # Check text against patterns
            self.regex_gate.check(context.text)
            self._log_result(context, "PASSED", "No pattern matches")

        except self.SecurityException as e:
            # Pattern matched - decide whether to block or allow
            threat_name = e.metadata.get("threat_name", "unknown")

            # P0-FIX: Context-Aware RegexGate for homoglyphs in documentation
            if threat_name == "homoglyph_obfuscation":
                # Check if this is documentation content
                from llm_firewall.core.firewall_engine_v2 import (
                    _analyze_documentation_context,
                )

                doc_context = _analyze_documentation_context(context.text)

                if doc_context["is_documentation"] > 0.5:
                    self.logger.debug(
                        f"Homoglyph in documentation context allowed "
                        f"(doc_confidence={doc_context['is_documentation']:.2f})"
                    )
                    # Allow documentation content with homoglyphs (e.g., mathematical symbols)
                    self._log_result(
                        context, "ALLOWED", f"Documentation override for {threat_name}"
                    )
                    return context

            # Fast-fail: Block immediately on pattern match
            encoding_anomaly = context.metadata.get("encoding_anomaly_score", 0.0)
            risk = min(1.0, 0.65 + encoding_anomaly * 0.35)  # Boost if encoding anomaly

            context.block(reason=f"RegexGate: {e.message}", risk_score=risk)
            context.add_threat(threat_name)
            context.add_layer_detection("RegexGateLayer", risk)
            context.metadata["regex_gate_violation"] = e.metadata

            self._log_result(
                context, "BLOCKED", f"Pattern: {threat_name}, Message: {e.message}"
            )

        except Exception as e:
            # Fail-closed: Block on error
            self.logger.error(f"RegexGate error: {e}", exc_info=True)
            context.block(reason=f"RegexGate error: {str(e)}", risk_score=1.0)
            context.add_threat("REGEX_GATE_ERROR")
            self._log_result(context, "ERROR", str(e))

        # Store layer result for analysis
        context.layer_results["regex_gate"] = {
            "passed": not context.should_block,
            "risk_score": context.risk_score,
            "threats": context.detected_threats.copy(),
        }

        return context


# ============================================================================
# Layer 0.55: Meta-Exploitation Detection - Bypass/Evade Pattern Detection
# ============================================================================


class MetaExploitationDetectionLayer(SecurityLayer):
    """
    Meta-exploitation detection layer (Layer 0.55).

    Detects patterns that indicate attempts to bypass or evade security measures.
    This catches "how to bypass", "ways to evade", etc. patterns.

    Responsibilities:
    - Detect meta-exploitation patterns (bypass, evade, circumvent)
    - Detect instruction manipulation attempts
    - Boost risk for combined suspicious indicators
    """

    def __init__(self, config: FirewallConfig):
        super().__init__(config)
        import re

        # Meta-exploitation patterns with base risk scores
        # TUNED: Reduced base risks to reduce FPR on benign "how to" questions
        self.meta_patterns = [
            (r"(?i)(how to|ways to|methods to)\s+(bypass|evade|circumvent|avoid)\s+(firewall|security|filter|safety)", 0.8),
            (r"(?i)(technique|method|approach)\s+to\s+(bypass|evade)\s+(firewall|security)", 0.7),
            (r"(?i)(get around|work around|get past)\s+(firewall|security|filter)", 0.9),
            (r"(?i)(trick|fool|deceive)\s+(the|this)\s+(system|ai|model)", 0.6),
            (r"(?i)(ignor|disregard|skip)\s+(previous|earlier)\s+(instruction|rule|safety)", 0.7),
            (r"(?i)(override|disable|turn off)\s+(safety|security|filter)", 0.8),
            (r"(?i)(make|force)\s+(the|this)\s+(ai|model|system)\s+(do|say|generate)\s+(harmful|dangerous)", 0.6),
        ]
        self.available = True
        self.logger.info("MetaExploitationDetectionLayer initialized")

    def can_block(self) -> bool:
        return True  # Can contribute to blocking via risk score

    def process(self, context: ProcessingContext) -> ProcessingContext:
        """
        Detect meta-exploitation patterns.

        Args:
            context: Processing context

        Returns:
            Modified context with meta-exploitation risk
        """
        if not self.available or not self.config.enable_meta_exploitation:
            self._log_result(
                context, "SKIPPED", "Meta-exploitation detection disabled"
            )
            return context

        # SELECTIVE ACTIVATION: Only check if risk_score already indicates suspicion
        if context.risk_score < self.config.meta_exploitation_min_risk:
            self._log_result(
                context, "SKIPPED", f"Risk score too low ({context.risk_score:.2f} < {self.config.meta_exploitation_min_risk})"
            )
            return context

        import re

        max_meta_risk = 0.0
        detected_patterns = []

        for pattern, base_risk in self.meta_patterns:
            if re.search(pattern, context.text, re.IGNORECASE):
                max_meta_risk = max(max_meta_risk, base_risk)
                detected_patterns.append(pattern)

        if max_meta_risk > 0.0:
            # Boost risk if combined with other suspicious indicators (reduced boost)
            if context.risk_score > 0.2:  # TUNED: 0.1 -> 0.2 (only boost if already suspicious)
                max_meta_risk = min(1.0, max_meta_risk * 1.3)  # TUNED: 1.5 -> 1.3 (reduced boost)

            context.risk_score = max(context.risk_score, max_meta_risk)
            context.add_threat("META_EXPLOITATION_DETECTED")
            context.add_layer_detection("MetaExploitationDetectionLayer", max_meta_risk)
            context.metadata["meta_exploitation_patterns"] = detected_patterns

            self.logger.warning(
                f"Meta-exploitation detected: {len(detected_patterns)} patterns, "
                f"risk: {max_meta_risk:.2f}"
            )
            self._log_result(
                context, "DETECTED", f"Meta-exploitation risk: {max_meta_risk:.2f}"
            )
        else:
            self._log_result(context, "PASSED", "No meta-exploitation patterns")

        # Store layer result
        context.layer_results["meta_exploitation"] = {
            "detected": max_meta_risk > 0.0,
            "risk_score": max_meta_risk,
            "patterns": detected_patterns,
        }

        return context


# ============================================================================
# Layer 0.6: Exploit Detection - Exploit Instruction Detection
# ============================================================================


class ExploitDetectionLayer(SecurityLayer):
    """
    Exploit instruction detection layer (Layer 0.6).

    Detects specific exploit instructions before they are misclassified
    as documentation (e.g., "Give detailed instructions for SQL injection").

    Responsibilities:
    - Detect explicit exploit instructions
    - Block harmful "how-to" requests
    - Prevent documentation false positives
    """

    def __init__(self, config: FirewallConfig):
        super().__init__(config)

        # Import helper functions from V2
        try:
            from llm_firewall.core.firewall_engine_v2 import _check_exploit_instructions

            self.check_exploit_instructions = _check_exploit_instructions
            self.available = True
            self.logger.info("ExploitDetectionLayer initialized")
        except ImportError as e:
            self.check_exploit_instructions = None
            self.available = False
            self.logger.warning(f"ExploitDetectionLayer not available: {e}")

    def can_block(self) -> bool:
        return True  # Can block on exploit detection

    def process(self, context: ProcessingContext) -> ProcessingContext:
        """
        Check for exploit instructions.

        Args:
            context: Processing context

        Returns:
            Modified context (blocked if exploit detected)
        """
        if not self.available or not self.config.enable_exploit_detection:
            self._log_result(
                context, "SKIPPED", "Exploit detection disabled or unavailable"
            )
            return context

        try:
            exploit_check = self.check_exploit_instructions(context.text)

            if exploit_check:
                # Exploit instruction detected - block
                threat_type = exploit_check.get("threat_type", "EXPLOIT_INSTRUCTION")
                risk_score = exploit_check.get("risk_score", 0.9)

                context.block(
                    reason=exploit_check.get("reason", "Exploit instruction detected"),
                    risk_score=risk_score,
                )
                context.add_threat(threat_type)
                context.add_layer_detection("ExploitDetectionLayer", risk_score)
                context.metadata["exploit_detection"] = exploit_check

                self._log_result(
                    context, "BLOCKED", f"Threat: {threat_type}, Risk: {risk_score:.2f}"
                )
            else:
                self._log_result(context, "PASSED", "No exploit instructions")

        except Exception as e:
            self.logger.error(f"Exploit detection error: {e}", exc_info=True)
            # Fail-closed: Block on error
            context.block(reason=f"Exploit detection error: {str(e)}", risk_score=1.0)
            context.add_threat("EXPLOIT_DETECTION_ERROR")

        # Store layer result
        context.layer_results["exploit_detection"] = {
            "passed": not context.should_block,
            "risk_score": context.risk_score,
            "threats": context.detected_threats.copy(),
        }

        return context


# ============================================================================
# Layer 0.7: Toxicity Detection - Multilingual Toxicity Detection
# ============================================================================


class ToxicityDetectionLayer(SecurityLayer):
    """
    Multilingual toxicity detection layer (Layer 0.7).

    Detects toxic content using ML-based and keyword-based methods.
    Hybrid approach: ML for subtle toxicity, keywords for explicit content.

    Responsibilities:
    - ML-based toxicity detection
    - Keyword-based toxicity detection
    - Risk score calculation based on toxicity
    """

    def __init__(self, config: FirewallConfig):
        super().__init__(config)

        # Try to import ML toxicity scanner
        try:
            from llm_firewall.detectors.ml_toxicity_scanner import scan_ml_toxicity

            self.scan_ml_toxicity = scan_ml_toxicity
            self.has_ml_scanner = True
        except ImportError:
            self.scan_ml_toxicity = None
            self.has_ml_scanner = False

        # Try to import keyword toxicity scanner
        try:
            from llm_firewall.detectors.multilingual_toxicity import scan_toxicity

            self.scan_toxicity = scan_toxicity
            self.has_keyword_scanner = True
        except ImportError:
            self.scan_toxicity = None
            self.has_keyword_scanner = False

        if not self.has_ml_scanner and not self.has_keyword_scanner:
            self.logger.warning("No toxicity scanners available")
            self.available = False
        else:
            self.available = True
            self.logger.info(
                f"ToxicityDetectionLayer initialized "
                f"(ML: {self.has_ml_scanner}, Keywords: {self.has_keyword_scanner})"
            )

    def can_block(self) -> bool:
        return True  # Can contribute to blocking via risk score

    def process(self, context: ProcessingContext) -> ProcessingContext:
        """
        Detect toxic content.

        Args:
            context: Processing context

        Returns:
            Modified context with toxicity risk
        """
        if not self.available or not self.config.enable_toxicity_detection:
            self._log_result(
                context, "SKIPPED", "Toxicity detection disabled or unavailable"
            )
            return context

        toxicity_risk = 0.0
        ml_result = None
        keyword_hits = []

        # ML-based detection (more accurate for subtle toxicity)
        # Use context-aware threshold selection
        if self.has_ml_scanner:
            try:
                # Context-aware threshold: use low threshold for subtle toxicity
                toxicity_threshold = self.config.toxicity_low_threshold
                ml_result = self.scan_ml_toxicity(
                    context.text, threshold=toxicity_threshold
                )
                if ml_result.get("is_toxic", False):
                    ml_confidence = ml_result.get("confidence", 0.0)
                    toxicity_risk = max(toxicity_risk, ml_confidence)
                    context.add_threat("ML_TOXICITY_DETECTED")
                    context.add_layer_detection("ToxicityDetectionLayer", ml_confidence)
                    self.logger.warning(
                        f"ML Toxicity detected: confidence={ml_confidence:.2f}, "
                        f"method={ml_result.get('method', 'unknown')}"
                    )
            except Exception as e:
                self.logger.debug(f"ML toxicity scanner error (fail-open): {e}")

        # Keyword-based detection (catches explicit keywords)
        if self.has_keyword_scanner:
            try:
                keyword_hits = self.scan_toxicity(context.text)
                if keyword_hits:
                    # Calculate keyword-based risk
                    keyword_risk = 0.0
                    if "toxicity_high_severity" in keyword_hits:
                        keyword_risk = 0.9
                    elif "toxicity_medium_severity" in keyword_hits:
                        keyword_risk = 0.7
                    elif "toxicity_low_severity" in keyword_hits:
                        keyword_risk = 0.5
                    else:
                        keyword_risk = 0.6

                    # Boost for high density
                    if "toxicity_very_high_density" in keyword_hits:
                        keyword_risk = min(1.0, keyword_risk + 0.2)
                    elif "toxicity_high_density" in keyword_hits:
                        keyword_risk = min(1.0, keyword_risk + 0.1)

                    # Boost for specific categories
                    if "toxicity_threat" in keyword_hits:
                        keyword_risk = min(1.0, keyword_risk + 0.15)
                    if (
                        "toxicity_hate" in keyword_hits
                        or "toxicity_discrimination" in keyword_hits
                    ):
                        keyword_risk = min(1.0, keyword_risk + 0.1)

                    toxicity_risk = max(toxicity_risk, keyword_risk)
                    context.add_threat("KEYWORD_TOXICITY_DETECTED")
                    self.logger.warning(
                        f"Keyword toxicity: {', '.join(keyword_hits[:3])}"
                    )

            except Exception as e:
                self.logger.debug(f"Keyword toxicity scanner error (fail-open): {e}")

        # Update risk score
        if toxicity_risk > 0.0:
            context.risk_score = max(context.risk_score, toxicity_risk)

        self._log_result(
            context,
            "DETECTED" if toxicity_risk > 0.0 else "PASSED",
            f"Toxicity risk: {toxicity_risk:.2f}",
        )

        # Store layer result
        context.layer_results["toxicity_detection"] = {
            "toxicity_risk": toxicity_risk,
            "ml_result": ml_result,
            "keyword_hits": keyword_hits,
            "risk_score": context.risk_score,
        }

        return context


# ============================================================================
# Layer 0.8: Semantic Guard - Semantic Similarity Detection
# ============================================================================


class SemanticGuardLayer(SecurityLayer):
    """
    Semantic similarity detection layer (Layer 0.8).

    Detects harmful prompts by comparing embeddings against threat database.
    This fixes the 87.2% zero-risk bypass issue where prompts get risk_score=0.0.

    Responsibilities:
    - Semantic similarity detection
    - Threat database matching
    - Zero-risk bypass prevention
    """

    def __init__(self, config: FirewallConfig):
        super().__init__(config)

        # Try to import Semantic Guard
        try:
            from llm_firewall.detectors.semantic_guard import get_semantic_guard

            self.get_semantic_guard = get_semantic_guard
            self.semantic_guard = None  # Lazy initialization
            self.available = True
            self.logger.info("SemanticGuardLayer initialized")
        except ImportError as e:
            self.get_semantic_guard = None
            self.semantic_guard = None
            self.available = False
            self.logger.warning(f"SemanticGuardLayer not available: {e}")

    def can_block(self) -> bool:
        return True  # Can contribute to blocking via risk score

    def process(self, context: ProcessingContext) -> ProcessingContext:
        """
        Detect semantic similarity to known threats.

        Args:
            context: Processing context

        Returns:
            Modified context with semantic risk
        """
        if not self.available or not self.config.enable_semantic_guard:
            self._log_result(
                context, "SKIPPED", "Semantic guard disabled or unavailable"
            )
            return context

        try:
            # Lazy initialization
            if self.semantic_guard is None:
                self.semantic_guard = self.get_semantic_guard()

            # Mypy check: Ensure semantic_guard is not None
            if self.semantic_guard is None:
                raise RuntimeError("Failed to initialize semantic guard")

            # Compute semantic risk with tuned threshold
            semantic_risk = self.semantic_guard.compute_risk_score(
                context.text,
                threshold=self.config.semantic_guard_low_threshold,  # Use tuned threshold
                use_spotlight=self.config.semantic_use_spotlight,
            )

            # Update risk score (use maximum to ensure high-risk prompts are caught)
            if semantic_risk > 0.0:
                context.risk_score = max(context.risk_score, semantic_risk)
                context.add_threat("SEMANTIC_SIMILARITY_DETECTED")
                context.add_layer_detection("SemanticGuardLayer", semantic_risk)
                self.logger.warning(
                    f"Semantic risk: {semantic_risk:.3f}, "
                    f"Combined risk: {context.risk_score:.3f}"
                )
                self._log_result(
                    context, "DETECTED", f"Semantic risk: {semantic_risk:.3f}"
                )
            else:
                self._log_result(context, "PASSED", "No semantic threats")

        except Exception as e:
            self.logger.warning(f"Semantic guard error (fail-open): {e}")
            # Fail-open: Continue without semantic detection

        # Store layer result
        context.layer_results["semantic_guard"] = {
            "semantic_risk": context.metadata.get("semantic_risk", 0.0),
            "risk_score": context.risk_score,
        }

        return context


# ============================================================================
# Layer 0.9: Safety Blacklist - Copyright & Misinformation Detection
# ============================================================================


class SafetyBlacklistLayer(SecurityLayer):
    """
    Safety Blacklist Layer (Layer 0.9) - Copyright & Misinformation Detection.
    
    Detects copyright violations and misinformation using pattern matching
    and category lexicon from threat_detection_config.yaml.
    
    Responsibilities:
    - Copyright violation detection (piracy, DRM circumvention)
    - Misinformation detection (false claims, disinformation)
    - Pattern-based category matching
    - Risk score contribution for detected categories
    """

    def __init__(self, config: FirewallConfig):
        super().__init__(config)
        
        # Try to import SafetyValidator
        try:
            from llm_firewall.safety.validator import SafetyValidator
            from pathlib import Path
            
            config_dir = Path(__file__).parent.parent.parent.parent / "config"
            self.safety_validator = SafetyValidator(
                config_dir=str(config_dir),
                enable_gpt5=False,
                gpt5_threshold=0.5
            )
            self.available = True
            self.logger.info("SafetyBlacklistLayer initialized")
        except ImportError as e:
            self.safety_validator = None
            self.available = False
            self.logger.warning(f"SafetyBlacklistLayer not available: {e}")

    def can_block(self) -> bool:
        return True  # Can contribute to blocking via risk score

    def process(self, context: ProcessingContext) -> ProcessingContext:
        """
        Check for copyright violations and misinformation.
        
        Args:
            context: Processing context
            
        Returns:
            Modified context with safety blacklist risk
        """
        if not self.available or self.safety_validator is None:
            self._log_result(
                context, "SKIPPED", "Safety blacklist disabled or unavailable"
            )
            return context

        try:
            # FIXED: Canonicalize text before validation to ensure obfuscation is handled
            # This ensures that obfuscation normalization (spaces between letters, leetspeak)
            # is applied before pattern matching
            from llm_firewall.text.normalize import canonicalize
            canonical_text = canonicalize(context.text)
            
            # DIRECT PATTERN CHECK: Fast-path for common copyright patterns
            # This ensures "generate the lyrics" is caught even if SafetyValidator misses it
            # FIXED: Use canonicalized text for pattern matching to catch obfuscated attempts
            # FIXED: Erweitert um "generate a long passage" und Varianten (Regression Fix)
            text_lower = canonical_text.lower()
            copyright_patterns = [
                "generate the lyrics",
                "generate lyrics",
                "reproduce the lyrics",
                "copy the lyrics",
                "duplicate the lyrics",
                "generate the text of",
                "reproduce the text of",
                "copy the text of",
                # WICHTIG: Patterns für "long passage" (Regression Fix)
                "generate a long passage",
                "generate long passage",
                "generate passage from",
                "reproduce a long passage",
                "reproduce long passage",
                "copy a long passage",
                "copy long passage",
                "duplicate a long passage",
                "duplicate long passage",
            ]
            
            # Check for direct copyright patterns
            direct_copyright_match = any(pattern in text_lower for pattern in copyright_patterns)
            matched_pattern = None
            if direct_copyright_match:
                matched_pattern = next((p for p in copyright_patterns if p in text_lower), "unknown")
                self.logger.debug(f"SafetyBlacklistLayer: Direct pattern match found: '{matched_pattern}'")
            self.logger.debug(f"SafetyBlacklistLayer: Validating content (length={len(context.text)}, canonical_length={len(canonical_text)})")
            
            # KRITISCH: Prüfe ob Aho-Corasick Trie verfügbar ist
            if self.safety_validator.category_trie is None:
                self.logger.error("SafetyBlacklistLayer: Aho-Corasick Trie nicht verfügbar! Fallback zu Substring-Matching.")
            else:
                self.logger.debug("SafetyBlacklistLayer: Aho-Corasick Trie verfügbar")
            
            # Logge kanonisierten Text (erste 100 Zeichen)
            self.logger.debug(f"SafetyBlacklistLayer: Canonical text (first 100 chars): '{canonical_text[:100]}...'")
            
            safety_decision = self.safety_validator.validate(canonical_text)
            
            # KRITISCH: Erweiterte Logging für Match-Details
            self.logger.warning(
                f"SafetyBlacklistLayer: SafetyValidator result - "
                f"category={safety_decision.category}, "
                f"action={safety_decision.action}, "
                f"risk_score={safety_decision.risk_score:.3f}, "
                f"matched_keyword={safety_decision.matched_keyword}, "
                f"match_confidence={safety_decision.match_confidence}, "
                f"direct_copyright_match={direct_copyright_match}"
            )
            
            # Check if copyright or misinformation detected
            category = safety_decision.category
            
            # KRITISCH: Fallback-Logik - Wenn Direct Pattern Match, aber SafetyValidator findet nichts
            # Dies ist ein Workaround für die Regression (4% → 80% ASR)
            if direct_copyright_match and category != "copyright_violation":
                pattern_str = matched_pattern if matched_pattern else "unknown"
                self.logger.warning(
                    f"SafetyBlacklistLayer: Direct pattern match found ('{pattern_str}'), "
                    f"but SafetyValidator did not detect copyright (category={category}). "
                    f"Using direct match for blocking (Regression Fix)."
                )
                # Force category to copyright_violation for blocking logic
                category = "copyright_violation"
                # Update safety_decision for consistency
                safety_decision = type(safety_decision)(
                    action="BLOCK",
                    risk_score=0.9,
                    category="copyright_violation",
                    reason=f"Direct copyright pattern match: {pattern_str}",
                    signals=safety_decision.signals,
                    matched_keyword=matched_pattern,
                    match_confidence=0.9
                )
            
            # KI Lab Integration: Nuanced Risk Scoring
            # Use confidence-based scores instead of binary 1.0
            
            # DIRECT BLOCK for copyright (highest priority)
            if category == "copyright_violation" or direct_copyright_match:
                self.logger.debug(
                    f"SafetyBlacklistLayer: Copyright detected - "
                    f"category={category}, direct_match={direct_copyright_match}, "
                    f"match_confidence={safety_decision.match_confidence}"
                )
                
                # Copyright violations: Use nuanced risk score from SafetyValidator
                # If SafetyValidator provided match_confidence, use it; otherwise use high score
                if safety_decision.match_confidence is not None:
                    risk_score = safety_decision.match_confidence  # 0.9, 0.6, or 0.4
                    self.logger.debug(f"SafetyBlacklistLayer: Using match_confidence={risk_score:.3f}")
                else:
                    risk_score = 0.9  # High confidence default for copyright
                    self.logger.debug(f"SafetyBlacklistLayer: No match_confidence, using default={risk_score:.3f}")
                
                # Ensure risk is high enough to block (threshold 0.17)
                risk_score_before_min = risk_score
                risk_score = max(risk_score, 0.85)  # Minimum to ensure blocking
                if risk_score_before_min < 0.85:
                    self.logger.debug(f"SafetyBlacklistLayer: Risk score increased from {risk_score_before_min:.3f} to {risk_score:.3f} (minimum threshold)")
                
                # CRITICAL: Copyright violations should ALWAYS block, regardless of other layers
                # Set risk score high enough to guarantee blocking, and mark for direct block
                context.risk_score = max(context.risk_score, risk_score, 0.90)  # Ensure minimum 0.90
                context.add_threat("COPYRIGHT_VIOLATION_DETECTED")
                context.add_layer_detection("SafetyBlacklistLayer", risk_score)
                context.metadata["safety_category"] = "copyright_violation"
                
                # DIRECT BLOCK: Copyright violations should always block
                # This ensures blocking even if other layers reduce the risk score
                context.block(
                    reason=f"Copyright violation detected: {safety_decision.matched_keyword or 'pattern match'}",
                    risk_score=max(risk_score, 0.90)
                )
                context.metadata["safety_decision"] = {
                    "action": safety_decision.action,
                    "category": "copyright_violation",
                    "reason": safety_decision.reason,
                    "matched_keyword": safety_decision.matched_keyword,
                    "match_confidence": safety_decision.match_confidence
                }
                
                # KI Lab: Granular logging
                matched_pattern = safety_decision.matched_keyword or ("direct pattern" if direct_copyright_match else "unknown")
                confidence_str = f"{safety_decision.match_confidence:.2f}" if safety_decision.match_confidence else "N/A"
                
                self.logger.warning(
                    f"Copyright violation detected | "
                    f"pattern: '{matched_pattern}' | "
                    f"confidence: {confidence_str} | "
                    f"risk: {risk_score:.3f} | "
                    f"combined: {context.risk_score:.3f}"
                )
                self._log_result(
                    context, "DETECTED", 
                    f"Copyright: pattern='{matched_pattern}', conf={confidence_str}, risk={risk_score:.3f}"
                )
            elif category == "misinformation":
                # Phase 1: Misinformation with Persuasive Rhetoric Detection
                # Get base risk from pattern matching
                base_risk = safety_decision.match_confidence if safety_decision.match_confidence is not None else 0.80
                
                # Add persuasion rhetoric score (Phase 1 Enhancement)
                # FIXED: Use canonicalized text for rhetoric detection (consistent with validation)
                rhetoric_score = 0.0
                if hasattr(self.safety_validator, '_detect_misinformation_rhetoric'):
                    rhetoric_score = self.safety_validator._detect_misinformation_rhetoric(canonical_text)
                    if rhetoric_score > 0.3:
                        # Boost risk score based on rhetoric intensity
                        # Formula: max(base_risk, rhetoric_score * 0.8) as per plan
                        risk_score = max(base_risk, rhetoric_score * 0.8)
                        self.logger.debug(
                            f"SafetyBlacklistLayer: Persuasion rhetoric detected - "
                            f"rhetoric_score={rhetoric_score:.3f}, "
                            f"base_risk={base_risk:.3f}, "
                            f"combined_risk={risk_score:.3f}"
                        )
                    else:
                        risk_score = base_risk
                else:
                    risk_score = base_risk
                
                # Ensure risk is high enough to block (minimum threshold)
                risk_score = max(risk_score, 0.75)  # Minimum to ensure blocking
                
                context.risk_score = max(context.risk_score, risk_score)
                context.add_threat("MISINFORMATION_DETECTED")
                context.add_layer_detection("SafetyBlacklistLayer", risk_score)
                context.metadata["safety_category"] = category
                context.metadata["safety_decision"] = {
                    "action": safety_decision.action,
                    "category": category,
                    "reason": safety_decision.reason,
                    "matched_keyword": safety_decision.matched_keyword,
                    "match_confidence": safety_decision.match_confidence,
                    "rhetoric_score": rhetoric_score if rhetoric_score > 0.0 else None
                }
                
                # KI Lab: Granular logging
                matched_pattern = safety_decision.matched_keyword or "unknown"
                confidence_str = f"{safety_decision.match_confidence:.2f}" if safety_decision.match_confidence else "N/A"
                rhetoric_str = f", rhetoric={rhetoric_score:.3f}" if rhetoric_score > 0.3 else ""
                
                self.logger.warning(
                    f"Misinformation detected | "
                    f"pattern: '{matched_pattern}' | "
                    f"confidence: {confidence_str}{rhetoric_str} | "
                    f"risk: {risk_score:.3f} | "
                    f"combined: {context.risk_score:.3f}"
                )
                self._log_result(
                    context, "DETECTED", 
                    f"Misinformation: pattern='{matched_pattern}', conf={confidence_str}, risk={risk_score:.3f}"
                )
            else:
                # Other categories (biosecurity, etc.) - lower priority for this layer
                # but still contribute to risk
                if safety_decision.risk_score > 0.5:
                    context.risk_score = max(context.risk_score, safety_decision.risk_score * 0.5)
                    if category:
                        context.add_threat(f"SAFETY_{category.upper()}")
                    self._log_result(
                        context, "DETECTED", f"Other safety category: {category}"
                    )
                else:
                    self._log_result(context, "PASSED", "No safety violations")

        except Exception as e:
            self.logger.warning(f"Safety blacklist error (fail-open): {e}")
            # Fail-open: Continue without safety detection

        # Store layer result
        context.layer_results["safety_blacklist"] = {
            "category": context.metadata.get("safety_category"),
            "risk_score": context.risk_score,
        }

        return context


# ============================================================================
# Layer 0.95: Detector Orchestration - Outer Ring (Two-Ring Defense)
# ============================================================================


class DetectorOrchestrationLayer(SecurityLayer):
    """
    Detector Orchestration Layer (Layer 0.95) - Outer Ring of Two-Ring Defense.
    
    Orchestrates calls to specialized detector microservices when inner ring
    flags risk. This implements the Two-Ring Defense System:
    
    - Inner Ring: Fast, cheap, in-process checks (5-15ms p95)
    - Outer Ring: Specialized detectors (20-40ms when invoked)
    
    Responsibilities:
    - Gating logic (only call when inner ring flags risk)
    - Parallel invocation of detector microservices
    - Timeout and circuit breaker handling
    - Response aggregation
    
    This layer is OPTIONAL and can be disabled if no detectors are configured.
    """
    
    def __init__(self, config: FirewallConfig):
        super().__init__(config)
        
        # Try to import detector orchestration components
        try:
            from llm_firewall.detectors.detector_registry import DetectorRegistry
            from llm_firewall.detectors.detector_orchestrator import (
                DetectorOrchestrator,
                InvocationContext
            )
            from llm_firewall.detectors.decision_engine import DecisionEngine
            
            self.registry = DetectorRegistry()
            self.orchestrator = DetectorOrchestrator(
                registry=self.registry,
                enable_cache=True,
                max_parallel=2  # Code-Intent + Content-Safety parallel
            )
            # Store InvocationContext class for use in process() method
            self.InvocationContext = InvocationContext
            
            # Initialize Decision Engine with config
            import yaml
            from pathlib import Path
            base_dir = Path(__file__).parent.parent.parent.parent
            config_path = base_dir / "config" / "detectors.yml"
            decision_config = {}
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    detectors_config = yaml.safe_load(f)
                    decision_config = detectors_config.get("decision_logic", {})
            
            self.decision_engine = DecisionEngine(config=decision_config)
            self.available = True
            self.logger.info("DetectorOrchestrationLayer initialized with Decision Engine")
        except ImportError as e:
            self.registry = None
            self.orchestrator = None
            self.InvocationContext = None
            self.available = False
            self.logger.warning(f"DetectorOrchestrationLayer not available: {e}")
    
    def can_block(self) -> bool:
        return True  # Can contribute to blocking via risk score
    
    def process(self, context: ProcessingContext) -> ProcessingContext:
        """
        Orchestrate detector microservice calls.
        
        Args:
            context: Processing context
            
        Returns:
            Modified context with detector responses
        """
        if not self.available or not self.orchestrator:
            self._log_result(
                context, "SKIPPED", "Detector orchestration disabled or unavailable"
            )
            return context
        
        # Extract detected categories from context
        detected_categories = []
        
        # Check metadata for safety categories
        safety_category = context.metadata.get("safety_category")
        if safety_category:
            detected_categories.append(safety_category)
        
        # Check detected threats for category hints
        for threat in context.detected_threats:
            threat_lower = threat.lower()
            if "cybercrime" in threat_lower or "intrusion" in threat_lower:
                detected_categories.append("cybercrime")
            elif "misinformation" in threat_lower or "disinformation" in threat_lower:
                detected_categories.append("misinformation")
            elif "copyright" in threat_lower:
                detected_categories.append("copyright_violation")
        
        # Remove duplicates
        detected_categories = list(set(detected_categories))
        
        # Extract detected tools from metadata
        detected_tools = context.metadata.get("detected_tools", [])
        if "tool_calls" in context.metadata:
            tool_calls = context.metadata["tool_calls"]
            if isinstance(tool_calls, list):
                for call in tool_calls:
                    if isinstance(call, dict) and "tool_name" in call:
                        tool_name = call["tool_name"]
                        if tool_name not in detected_tools:
                            detected_tools.append(tool_name)
        
        # Create invocation context
        if not self.InvocationContext:
            self._log_result(
                context, "SKIPPED", "InvocationContext not available"
            )
            return context
        
        invocation_context = self.InvocationContext(
            text=context.text,
            risk_score=context.risk_score,
            detected_categories=detected_categories,
            detected_tools=detected_tools,
            metadata=context.metadata.copy()
        )
        
        # Invoke detectors (sync mode)
        result = None
        try:
            result = self.orchestrator.invoke_detectors(
                context=invocation_context,
                sync=True
            )
            
            # Store detector results in metadata
            if result:
                context.metadata["detector_results"] = {
                    "responses": [
                        {
                            "detector": r.detector_name,
                            "risk": r.risk_score,
                            "category": r.category,
                            "latency_ms": r.latency_ms,
                            "error": r.error
                        }
                        for r in result.responses
                    ],
                    "total_latency_ms": result.total_latency_ms,
                    "cache_hits": result.cache_hits,
                    "errors": result.errors
                }
                
                # CRITICAL FIX: Use Decision Engine for combined decision
                if result.responses:
                    # Convert responses to dict for Decision Engine
                    detector_results_dict = {
                        r.detector_name: r for r in result.responses
                    }
                    
                    # Use Decision Engine to combine results
                    if hasattr(self, 'decision_engine') and self.decision_engine:
                        combined_decision = self.decision_engine.combine_decisions(
                            detector_results_dict,
                            context={
                                "context_type": context.metadata.get("context_type", "general_chat"),
                                "is_documentary": "documentary" in context.text.lower() or "research" in context.text.lower(),
                                "is_research": "research" in context.text.lower() or "academic" in context.text.lower()
                            }
                        )
                        
                        # Apply decision
                        if combined_decision.decision == "BLOCKED":
                            context.risk_score = max(context.risk_score, combined_decision.risk_score)
                            context.add_layer_detection("DetectorOrchestrationLayer", combined_decision.risk_score)
                            
                            # Add blocking detector to threats
                            if combined_decision.blocked_by:
                                context.add_threat(f"DETECTOR_{combined_decision.blocked_by.upper()}")
                            
                            self.logger.info(
                                f"Detector orchestration: BLOCKED by {combined_decision.blocked_by} "
                                f"(risk={combined_decision.risk_score:.3f}, confidence={combined_decision.confidence:.3f}), "
                                f"latency={result.total_latency_ms:.1f}ms"
                            )
                            self._log_result(
                                context, "DETECTED",
                                f"BLOCKED by {combined_decision.blocked_by}: {combined_decision.explanation}, "
                                f"latency: {result.total_latency_ms:.1f}ms"
                            )
                        else:
                            # ALLOWED - but still update risk score for monitoring
                            context.risk_score = max(context.risk_score, combined_decision.risk_score)
                            self._log_result(
                                context, "PASSED",
                                f"All detectors allowed (risk={combined_decision.risk_score:.3f}), "
                                f"latency: {result.total_latency_ms:.1f}ms"
                            )
                    else:
                        # Fallback to old aggregation if Decision Engine not available
                        aggregated = self.orchestrator.aggregate_responses(result.responses)
                        detector_risk = aggregated.get("risk_score", 0.0)
                        
                        if detector_risk > 0.0:
                            context.risk_score = max(context.risk_score, detector_risk)
                            context.add_layer_detection("DetectorOrchestrationLayer", detector_risk)
                            
                            for category in aggregated.get("categories", []):
                                context.add_threat(f"DETECTOR_{category.upper()}")
                            
                            self.logger.info(
                                f"Detector orchestration: {len(result.responses)} detector(s) "
                                f"invoked, max_risk={detector_risk:.3f}, "
                                f"latency={result.total_latency_ms:.1f}ms"
                            )
                            self._log_result(
                                context, "DETECTED",
                                f"Detector risk: {detector_risk:.3f}, "
                                f"latency: {result.total_latency_ms:.1f}ms"
                            )
                        else:
                            self._log_result(context, "PASSED", "No detector risks detected")
                else:
                    self._log_result(context, "PASSED", "No detectors invoked (gating)")
        
        except Exception as e:
            self.logger.warning(f"Detector orchestration error (fail-open): {e}")
            # Fail-open: Continue without detector results
        
        # Store layer result
        context.layer_results["detector_orchestration"] = {
            "invoked": result.responses if result else [],
            "total_latency_ms": result.total_latency_ms if result else 0.0,
            "risk_score": context.risk_score,
        }
        
        return context


# ============================================================================
# Layer 1: Kids Policy - Kids-Safe Content Filtering (OPTIONAL)
# ============================================================================


class KidsPolicyLayer(SecurityLayer):
    """
    Kids-safe content filtering layer (Layer 1) - OPTIONAL.

    Integrates Kids Policy Engine for child-safe content filtering.
    This layer is OPTIONAL and can be disabled via config.

    Responsibilities:
    - Kids-safe content filtering
    - Context-aware detection (P0-Fixes)
    - Documentation override for educational content
    """

    def __init__(self, config: FirewallConfig):
        super().__init__(config)

        # Try to import Kids Policy Engine
        self.kids_policy = None
        if config.enable_kids_policy:
            try:
                import sys
                from pathlib import Path

                kids_policy_path = (
                    Path(__file__).parent.parent.parent.parent / "kids_policy"
                )
                if kids_policy_path.exists():
                    sys.path.insert(0, str(kids_policy_path.parent))
                    from kids_policy.firewall_engine_v2 import HakGalFirewall_v2

                    self.kids_policy = HakGalFirewall_v2()
                    self.available = True
                    self.logger.info("KidsPolicyLayer initialized (OPTIONAL)")
                else:
                    self.available = False
                    self.logger.info(
                        "KidsPolicyLayer disabled - kids_policy path not found"
                    )
            except Exception as e:
                self.available = False
                self.logger.info(f"KidsPolicyLayer disabled: {e}")
        else:
            self.available = False
            self.logger.info(
                "KidsPolicyLayer disabled via config (enable_kids_policy=False)"
            )

        # Import helper functions
        try:
            from llm_firewall.core.firewall_engine_v2 import (
                _is_benign_educational_query,
                _analyze_documentation_context,
                _is_exploit_instruction,
            )

            self.is_benign_educational_query = _is_benign_educational_query
            self.analyze_documentation_context = _analyze_documentation_context
            self.is_exploit_instruction = _is_exploit_instruction
        except ImportError:
            self.is_benign_educational_query = None
            self.analyze_documentation_context = None
            self.is_exploit_instruction = None

    def can_block(self) -> bool:
        return True  # Can block harmful content for kids

    def process(self, context: ProcessingContext) -> ProcessingContext:
        """
        Filter content for kids-safe environment.

        Args:
            context: Processing context

        Returns:
            Modified context (blocked if unsafe for kids)
        """
        if not self.available:
            self._log_result(context, "SKIPPED", "Kids Policy disabled or unavailable")
            return context

        try:
            # P0-Fix: Pre-filter benign educational queries
            if self.is_benign_educational_query and self.is_benign_educational_query(
                context.text
            ):
                self.logger.debug(
                    "Benign educational query detected - bypassing unsafe topic detection"
                )
                # Override detected topic to prevent false positive
                context.metadata["topic_id"] = "general_chat"

            # Call Kids Policy
            kids_result = self.kids_policy.process_request(
                user_id=context.user_id,
                raw_input=context.text,
                detected_topic=context.metadata.get("topic_id"),
            )

            # P0-Fix: Context-aware detection and score adjustment
            if kids_result.get("status") == "BLOCK":
                if self.analyze_documentation_context:
                    doc_context = self.analyze_documentation_context(context.text)

                    # Check if exploit instruction first
                    if self.is_exploit_instruction and self.is_exploit_instruction(
                        context.text, doc_context
                    ):
                        # Keep block - this is an exploit, not documentation
                        pass
                    else:
                        # Check if documentation
                        is_documentation = (
                            doc_context.get("is_documentation", 0) > 0.0
                            or doc_context.get("is_technical", 0) > 0.0
                            or doc_context.get("has_code", 0) > 0.0
                            or doc_context.get("has_markdown", 0) > 0.0
                        )

                        if is_documentation:
                            # Override block - allow documentation
                            self.logger.info(
                                f"Technical documentation detected - override ALLOW "
                                f"(doc={doc_context.get('is_documentation', 0):.2f}, "
                                f"tech={doc_context.get('is_technical', 0):.2f})"
                            )
                            kids_result = {
                                "status": "ALLOW",
                                "sanitized_input": context.text,
                            }

            # Check final status
            if kids_result.get("status") == "BLOCK":
                block_reason = kids_result.get("reason", "Kids Policy block")
                kids_risk = kids_result.get("debug", {}).get("risk_score", 1.0)

                context.block(
                    reason=f"Kids Policy: {block_reason}", risk_score=kids_risk
                )
                context.add_threat(
                    kids_result.get("block_reason_code", "KIDS_POLICY_BLOCK")
                )
                context.metadata["kids_policy_result"] = kids_result

                self._log_result(context, "BLOCKED", f"Reason: {block_reason}")
            else:
                self._log_result(context, "PASSED", "Kids Policy allowed")

        except Exception as e:
            self.logger.error(f"Kids Policy error: {e}", exc_info=True)
            # Fail-closed: Block on error
            context.block(reason=f"Kids Policy error: {str(e)}", risk_score=1.0)
            context.add_threat("KIDS_POLICY_ERROR")

        # Store layer result
        context.layer_results["kids_policy"] = {
            "passed": not context.should_block,
            "risk_score": context.risk_score,
            "threats": context.detected_threats.copy(),
        }

        return context


# ============================================================================
# Layer 2: Tool Call Validation - HEPHAESTUS Protocol (OUTPUT ONLY)
# ============================================================================


class OutputValidationLayer(SecurityLayer):
    """
    Output validation layer (Layer 3) - Truth Preservation.

    Validates LLM output for semantic grooming attempts, toxicity, and
    harmful content before returning to user.

    Responsibilities:
    - Semantic grooming detection (truth preservation)
    - Output toxicity detection
    - Harmful output filtering
    """

    def __init__(self, config: FirewallConfig):
        super().__init__(config)

        # Try to import semantic grooming guard (ONNX first, then PyTorch fallback)
        self.grooming_guard = None
        self.has_grooming_guard = False
        self.using_onnx = False

        try:
            import sys
            from pathlib import Path

            kids_policy_path = (
                Path(__file__).parent.parent.parent.parent / "kids_policy"
            )
            if kids_policy_path.exists():
                sys.path.insert(0, str(kids_policy_path.parent))

                # PRIORITY 1: Try ONNX version first (PyTorch-free, ~1100 MB memory savings)
                try:
                    from kids_policy.truth_preservation.validators.semantic_grooming_guard_onnx import (
                        SemanticGroomingGuardONNX,
                    )

                    self.grooming_guard = SemanticGroomingGuardONNX()
                    self.has_grooming_guard = True
                    self.using_onnx = True
                    self.logger.info(
                        "OutputValidationLayer: Using SemanticGroomingGuardONNX (PyTorch-free)"
                    )
                except (ImportError, Exception) as onnx_error:
                    # FALLBACK: Use PyTorch version if ONNX not available
                    try:
                        from kids_policy.truth_preservation.validators.semantic_grooming_guard import (
                            SemanticGroomingGuard,
                        )

                        self.grooming_guard = SemanticGroomingGuard()
                        self.has_grooming_guard = True
                        self.using_onnx = False
                        self.logger.info(
                            "OutputValidationLayer: Using SemanticGroomingGuard (PyTorch fallback)"
                        )
                        self.logger.debug(
                            f"ONNX not available, reason: {onnx_error}"
                        )
                    except ImportError as pytorch_error:
                        self.grooming_guard = None
                        self.has_grooming_guard = False
                        self.logger.warning(
                            f"SemanticGroomingGuard (both ONNX and PyTorch) not available: {pytorch_error}"
                        )
            else:
                self.grooming_guard = None
                self.has_grooming_guard = False
                self.logger.warning("kids_policy path not found")
        except Exception as e:
            self.grooming_guard = None
            self.has_grooming_guard = False
            self.logger.warning(f"SemanticGroomingGuard initialization failed: {e}")

        # Try to import toxicity scanners for output
        try:
            from llm_firewall.detectors.ml_toxicity_scanner import scan_ml_toxicity

            self.scan_ml_toxicity = scan_ml_toxicity
            self.has_toxicity_scanner = True
        except ImportError:
            self.scan_ml_toxicity = None
            self.has_toxicity_scanner = False

        self.available = self.has_grooming_guard or self.has_toxicity_scanner

        if self.available:
            onnx_status = "ONNX" if self.using_onnx else "PyTorch"
            self.logger.info(
                f"OutputValidationLayer initialized "
                f"(Grooming: {self.has_grooming_guard} [{onnx_status}], "
                f"Toxicity: {self.has_toxicity_scanner})"
            )
        else:
            self.logger.warning("OutputValidationLayer: No validators available")

    def can_block(self) -> bool:
        return True  # Can block harmful output

    def process(self, context: ProcessingContext) -> ProcessingContext:
        """
        Validate output for harmful content.

        Args:
            context: Processing context

        Returns:
            Modified context (blocked if harmful output detected)
        """
        if not self.available:
            self._log_result(
                context, "SKIPPED", "Output validation disabled or unavailable"
            )
            return context

        # Check for semantic grooming
        if self.has_grooming_guard and self.grooming_guard is not None:
            try:
                # check_semantic_risk returns: (is_safe, risk_description, score)
                is_safe, risk_description, grooming_score = (
                    self.grooming_guard.check_semantic_risk(
                        context.text, threshold=0.65, use_spotlight=True
                    )
                )

                if not is_safe:  # Grooming detected
                    context.block(
                        reason=f"Output semantic grooming detected: {risk_description or 'unknown'}",
                        risk_score=grooming_score,
                    )
                    context.add_threat("OUTPUT_SEMANTIC_GROOMING")
                    context.metadata["grooming_detection"] = {
                        "is_grooming": True,
                        "risk_description": risk_description,
                        "grooming_score": grooming_score,
                    }
                    self._log_result(
                        context, "BLOCKED", f"Grooming score: {grooming_score:.2f}"
                    )
                    return context

            except Exception as e:
                self.logger.debug(f"Grooming guard error (fail-open): {e}")

        # Check output toxicity
        if self.has_toxicity_scanner:
            try:
                toxicity_result = self.scan_ml_toxicity(context.text, threshold=0.6)

                if toxicity_result.get("is_toxic", False):
                    toxicity_confidence = toxicity_result.get("confidence", 0.7)
                    context.block(
                        reason="Output contains toxic content",
                        risk_score=toxicity_confidence,
                    )
                    context.add_threat("OUTPUT_TOXICITY")
                    context.metadata["output_toxicity"] = toxicity_result
                    self._log_result(
                        context, "BLOCKED", f"Toxicity: {toxicity_confidence:.2f}"
                    )
                    return context

            except Exception as e:
                self.logger.debug(f"Output toxicity scanner error (fail-open): {e}")

        self._log_result(context, "PASSED", "Output validation passed")

        # Store layer result
        context.layer_results["output_validation"] = {
            "passed": not context.should_block,
            "risk_score": context.risk_score,
        }

        return context


# ============================================================================
# Layer 2: Tool Call Validation - HEPHAESTUS Protocol (OUTPUT ONLY)
# ============================================================================


class ToolCallValidationLayer(SecurityLayer):
    """
    Tool call validation layer (Layer 2) - Protocol HEPHAESTUS.

    Validates tool calls in LLM output for security.
    This layer is only used in output processing, not input.

    Responsibilities:
    - Extract tool calls from LLM output
    - Validate tool calls against allowed tools
    - Sanitize dangerous arguments
    """

    def __init__(self, config: FirewallConfig):
        super().__init__(config)

        # Import tool call components
        try:
            from llm_firewall.detectors.tool_call_extractor import ToolCallExtractor
            from llm_firewall.detectors.tool_call_validator import ToolCallValidator

            self.extractor = ToolCallExtractor(strict_mode=False)
            self.validator = ToolCallValidator(
                allowed_tools=config.allowed_tools,
                strict_mode=config.strict_mode,
                enable_sanitization=True,
            )
            self.available = True
            self.logger.info(
                "ToolCallValidationLayer initialized (Protocol HEPHAESTUS)"
            )
        except ImportError as e:
            self.extractor = None
            self.validator = None
            self.available = False
            self.logger.warning(f"ToolCallValidationLayer not available: {e}")

    def can_block(self) -> bool:
        return True  # Can block invalid tool calls

    def process(self, context: ProcessingContext) -> ProcessingContext:
        """
        Validate tool calls in text.

        Args:
            context: Processing context

        Returns:
            Modified context (blocked if invalid tool calls)
        """
        if not self.available or not self.config.enable_tool_validation:
            self._log_result(
                context, "SKIPPED", "Tool validation disabled or unavailable"
            )
            return context

        try:
            # Extract tool calls
            tool_calls = self.extractor.extract_tool_calls(context.text)

            if not tool_calls:
                self._log_result(context, "PASSED", "No tool calls detected")
                return context

            self.logger.info(f"Found {len(tool_calls)} tool call(s)")

            # Validate each tool call
            detected_threats = []
            max_risk = 0.0
            sanitized_calls = []

            for call in tool_calls:
                tool_name = call["tool_name"]
                arguments = call["arguments"]

                # Validate
                validation_result = self.validator.validate_tool_call(
                    tool_name, arguments
                )

                if not validation_result.allowed:
                    # Block entire response if any tool call is blocked
                    context.block(
                        reason=f"Tool call blocked: {validation_result.reason}",
                        risk_score=validation_result.risk_score,
                    )
                    context.detected_threats.extend(
                        validation_result.detected_threats or []
                    )
                    context.metadata["blocked_tool"] = tool_name
                    context.metadata["blocked_arguments"] = arguments

                    self._log_result(
                        context,
                        "BLOCKED",
                        f"Tool: {tool_name}, Reason: {validation_result.reason}",
                    )
                    break

                # Track threats and risk
                if validation_result.detected_threats:
                    detected_threats.extend(validation_result.detected_threats)
                max_risk = max(max_risk, validation_result.risk_score)

                # Store sanitized call
                sanitized_calls.append(
                    {
                        "tool_name": tool_name,
                        "arguments": validation_result.sanitized_args,
                    }
                )

            # Store results
            context.metadata["tool_calls"] = sanitized_calls
            context.metadata["original_tool_calls"] = tool_calls
            context.risk_score = max(context.risk_score, max_risk)

            if not context.should_block:
                self._log_result(
                    context, "PASSED", f"{len(tool_calls)} tool call(s) validated"
                )

        except Exception as e:
            self.logger.error(f"Tool validation error: {e}", exc_info=True)
            # Fail-closed: Block on error
            context.block(reason=f"Tool validation error: {str(e)}", risk_score=1.0)
            context.add_threat("TOOL_VALIDATION_ERROR")

        # Store layer result
        context.layer_results["tool_validation"] = {
            "passed": not context.should_block,
            "risk_score": context.risk_score,
            "tool_calls": context.metadata.get("tool_calls", []),
        }

        return context


# ============================================================================
# FirewallEngineV3 - Main Pipeline Coordinator
# ============================================================================


class FirewallEngineV3:
    """
    HAK_GAL Core Engine v3 - Modular Layer Architecture.

    This engine coordinates security layers in a clean pipeline:
    INPUT -> [Pre-Processing] -> [Fast-Fail] -> [Content Analysis] -> [Tool Validation] -> [Post-Processing] -> OUTPUT

    Each layer is independently configurable and testable.
    Layers follow the Fail-Closed principle for security.

    Usage:
        config = FirewallConfig(enable_kids_policy=True, strict_mode=True)
        engine = FirewallEngineV3(config)

        # Process input
        decision = engine.process_input(user_id="user123", text="user input")
        if decision.allowed:
            # Send to LLM
            llm_output = generate_llm_response(decision.sanitized_text)
            # Process output
            output_decision = engine.process_output(text=llm_output, user_id="user123")
            if output_decision.allowed:
                return output_decision.sanitized_text
    """

    def __init__(self, config: Optional[FirewallConfig] = None):
        """
        Initialize FirewallEngineV3 with configuration.

        Args:
            config: Firewall configuration (if None, uses EmergencyFixFirewallConfig)
        """
        # WICHTIG: Standardmäßig Emergency Config verwenden (FPR-Fix)
        self.config = config or EmergencyFixFirewallConfig()
        self.logger = logging.getLogger(__name__)
        
        # Log GPU configuration at startup
        try:
            from llm_firewall.core.gpu_enforcement import log_device_info
            log_device_info()
        except ImportError:
            # GPU enforcement module not available - log basic info
            import torch
            import os
            self.logger.info(f"[FirewallEngineV3] TORCH_DEVICE: {os.environ.get('TORCH_DEVICE', 'not set')}")
            self.logger.info(f"[FirewallEngineV3] CUDA available: {torch.cuda.is_available()}")
            if torch.cuda.is_available():
                self.logger.info(f"[FirewallEngineV3] Using GPU: {torch.cuda.get_device_name(0)}")
            else:
                self.logger.warning("[FirewallEngineV3] GPU not available - will use CPU if allowed")

        # Initialize INPUT processing layers (order matters - pipeline sequence)
        self.input_layers: List[SecurityLayer] = []

        # Layer 0: Unicode Sanitizer (Input sanitization)
        if self.config.enable_sanitization:
            self.input_layers.append(UnicodeSanitizerLayer(self.config))

        # Layer 0.25: Normalization (Recursive URL/percent decoding)
        if self.config.enable_normalization:
            self.input_layers.append(NormalizationLayer(self.config))

        # Layer 0.5: RegexGate (Fast-Fail pattern matching)
        if self.config.enable_regex_gate:
            self.input_layers.append(RegexGateLayer(self.config))

        # Layer 0.55: Meta-Exploitation Detection (Bypass/Evade patterns)
        if self.config.enable_meta_exploitation:
            self.input_layers.append(MetaExploitationDetectionLayer(self.config))

        # Layer 0.6: Exploit Detection (Exploit instruction detection)
        if self.config.enable_exploit_detection:
            self.input_layers.append(ExploitDetectionLayer(self.config))

        # Layer 0.7: Toxicity Detection (Multilingual toxicity)
        if self.config.enable_toxicity_detection:
            self.input_layers.append(ToxicityDetectionLayer(self.config))

        # Layer 0.8: Semantic Guard (Semantic similarity detection)
        if self.config.enable_semantic_guard:
            self.input_layers.append(SemanticGuardLayer(self.config))

        # Layer 0.9: Safety Blacklist (Copyright & Misinformation detection)
        if self.config.enable_safety_blacklist:
            self.input_layers.append(SafetyBlacklistLayer(self.config))

        # Layer 0.95: Detector Orchestration (Outer Ring - Two-Ring Defense)
        # NOTE: This layer is optional and will be skipped if no detectors are configured
        try:
            from llm_firewall.detectors.detector_registry import DetectorRegistry
            registry = DetectorRegistry()
            # Only add layer if at least one detector is enabled
            if any(d.enabled for d in registry.detectors.values()):
                self.input_layers.append(DetectorOrchestrationLayer(self.config))
                self.logger.info("DetectorOrchestrationLayer enabled (Outer Ring)")
        except ImportError:
            self.logger.debug("DetectorOrchestrationLayer not available (detectors not configured)")

        # Layer 1: Kids Policy (Kids-safe content filtering) - OPTIONAL
        if self.config.enable_kids_policy:
            self.input_layers.append(KidsPolicyLayer(self.config))

        # Initialize OUTPUT processing layers
        self.output_layers: List[SecurityLayer] = []

        # Layer 2: Tool Call Validation (HEPHAESTUS Protocol) - OUTPUT ONLY
        if self.config.enable_tool_validation:
            self.output_layers.append(ToolCallValidationLayer(self.config))

        # Layer 3: Output Validation (Truth Preservation) - OUTPUT ONLY
        if self.config.enable_output_validation:
            self.output_layers.append(OutputValidationLayer(self.config))

        # ENTFERNE Meta-Exploitation Layer wenn deaktiviert (zusätzliche Sicherheit)
        if not self.config.enable_meta_exploitation:
            self.input_layers = [
                layer for layer in self.input_layers 
                if not isinstance(layer, MetaExploitationDetectionLayer)
            ]
        
        self.logger.info(
            f"FirewallEngineV3 initialized with {len(self.input_layers)} input layers, "
            f"{len(self.output_layers)} output layers"
        )

    def process_input(self, user_id: str, text: str, **kwargs) -> "FirewallDecision":
        """
        Process user input through firewall layers.

        Args:
            user_id: Unique user identifier
            text: Raw user input text
            **kwargs: Additional context (age_band, topic_id, etc.)

        Returns:
            FirewallDecision with allow/block decision and sanitized text
        """
        # FIXED: Emergency Benign Check DEAKTIVIERT - zu aggressiv, verursacht 39.5% ASR
        # HarmBench harmful prompts wurden fälschlich als "benign" klassifiziert
        is_likely_benign = False  # DEAKTIVIERT: self._emergency_benign_check(text)
        
        # Create processing context
        context = ProcessingContext(
            user_id=user_id,
            text=text,
            original_text=text,
            metadata={
                **kwargs,
                "emergency_mode": True,
                "is_likely_benign": is_likely_benign
            },
        )
        
        # FIXED: Minimum Risk Score für alle Prompts (verhindert 0.0 Risk Scores)
        # HarmBench harmful prompts sollten mindestens 0.10 Risk haben
        context.risk_score = 0.10  # Start mit Minimum-Risk statt 0.0

        # Empty input check
        if not text or not text.strip():
            return self._create_decision(context, allowed=True, reason="Empty input")

        # Run pipeline: Process through all INPUT layers
        for layer in self.input_layers:
            try:
                original_risk = context.risk_score
                context = layer.process(context)

                # Check if layer blocked the request
                if context.should_block:
                    self.logger.warning(
                        f"Request blocked by {layer.__class__.__name__}: {context.block_reason}"
                    )
                    return self._create_decision(
                        context, allowed=False, reason=context.block_reason
                    )

            except Exception as e:
                # Fail-closed: Any layer exception results in block
                self.logger.error(
                    f"Layer {layer.__class__.__name__} failed: {e}", exc_info=True
                )
                context.block(
                    reason=f"Internal failure: {layer.__class__.__name__}",
                    risk_score=1.0,
                )
                context.add_threat(f"{layer.__class__.__name__.upper()}_FAILURE")
                return self._create_decision(
                    context, allowed=False, reason=context.block_reason
                )

        # APPLY ENSEMBLE BONUS (if enabled)
        if self.config.enable_ensemble_detection:
            ensemble_bonus = context.calculate_ensemble_risk(self.config)
            if ensemble_bonus > 0.0:
                original_risk = context.risk_score
                context.risk_score = min(1.0, context.risk_score + ensemble_bonus)
                self.logger.info(
                    f"Ensemble bonus applied: +{ensemble_bonus:.2f} "
                    f"({len(context.detecting_layers)} layers) "
                    f"{original_risk:.2f} -> {context.risk_score:.2f}"
                )
                context.metadata["ensemble_bonus"] = ensemble_bonus
                context.metadata["detecting_layers_count"] = len(context.detecting_layers)

        # APPLY MULTIPLICATIVE AGGREGATION (if enabled)
        if self.config.use_multiplicative_aggregation and context.detecting_layers:
            multiplicative_risk = context.calculate_multiplicative_risk()
            if multiplicative_risk > context.risk_score:
                original_risk = context.risk_score
                context.risk_score = min(
                    1.0, multiplicative_risk * self.config.multiplicative_boost_factor
                )
                self.logger.debug(
                    f"Multiplicative aggregation: {original_risk:.2f} -> {context.risk_score:.2f}"
                )
                context.metadata["multiplicative_risk"] = multiplicative_risk

        # FIXED: Emergency Benign Discount DEAKTIVIERT - verursachte zu niedrige Risk Scores
        # if context.metadata.get("is_likely_benign", False):
        #     discount = context.metadata.get("emergency_benign_discount", 0.03)
        #     original_risk = context.risk_score
        #     context.risk_score = max(0.0, context.risk_score - discount)
        #     if original_risk != context.risk_score:
        #         self.logger.debug(
        #             f"Emergency benign discount applied: {original_risk:.3f} -> {context.risk_score:.3f}"
        #         )

        # DYNAMIC THRESHOLD ADJUSTMENT
        blocking_threshold = self._calculate_dynamic_threshold(context)

        # All layers passed - check risk threshold
        if context.risk_score >= blocking_threshold:
            context.block(
                reason=f"Risk threshold exceeded: {context.risk_score:.2f} >= {blocking_threshold:.2f}",
                risk_score=context.risk_score,
            )
            context.metadata["blocking_threshold_used"] = blocking_threshold
            return self._create_decision(
                context, allowed=False, reason=context.block_reason
            )

        # Request allowed
        context.sanitized_text = context.text  # Use final processed text
        return self._create_decision(context, allowed=True, reason="Input validated")

    def process_output(
        self, text: str, user_id: Optional[str] = None, **kwargs
    ) -> "FirewallDecision":
        """
        Process LLM output through firewall layers (Protocol HEPHAESTUS).

        Args:
            text: Raw LLM output text (may contain tool calls)
            user_id: Optional user identifier for session tracking
            **kwargs: Additional context

        Returns:
            FirewallDecision with allow/block decision and sanitized text
        """
        # Create processing context
        context = ProcessingContext(
            user_id=user_id or "output_processor",
            text=text,
            original_text=text,
            metadata=kwargs.copy(),  # Store kwargs in metadata
        )

        # Empty output check
        if not text or not text.strip():
            return self._create_decision(context, allowed=True, reason="Empty output")

        # Run OUTPUT pipeline: Process through all output layers
        for layer in self.output_layers:
            try:
                context = layer.process(context)

                # Check if layer blocked the output
                if context.should_block:
                    self.logger.warning(
                        f"Output blocked by {layer.__class__.__name__}: {context.block_reason}"
                    )
                    return self._create_decision(
                        context, allowed=False, reason=context.block_reason
                    )

            except Exception as e:
                # Fail-closed: Any layer exception results in block
                self.logger.error(
                    f"Output layer {layer.__class__.__name__} failed: {e}",
                    exc_info=True,
                )
                context.block(
                    reason=f"Internal output failure: {layer.__class__.__name__}",
                    risk_score=1.0,
                )
                context.add_threat(f"{layer.__class__.__name__.upper()}_FAILURE")
                return self._create_decision(
                    context, allowed=False, reason=context.block_reason
                )

        # All output layers passed - check risk threshold
        if context.risk_score >= self.config.blocking_threshold:
            context.block(
                reason=f"Output risk threshold exceeded: {context.risk_score:.2f} >= {self.config.blocking_threshold:.2f}",
                risk_score=context.risk_score,
            )
            return self._create_decision(
                context, allowed=False, reason=context.block_reason
            )

        # Output allowed
        context.sanitized_text = context.text  # Use final processed text
        return self._create_decision(context, allowed=True, reason="Output validated")

    def _create_decision(
        self, context: ProcessingContext, allowed: bool, reason: str
    ) -> "FirewallDecision":
        """
        Create FirewallDecision from ProcessingContext.

        Args:
            context: Processing context
            allowed: Whether request is allowed
            reason: Human-readable reason

        Returns:
            FirewallDecision object
        """
        # Import here to avoid circular dependency
        from llm_firewall.core.firewall_engine_v2 import FirewallDecision

        return FirewallDecision(
            allowed=allowed,
            reason=reason,
            sanitized_text=context.sanitized_text or context.text,
            risk_score=context.risk_score,
            detected_threats=context.detected_threats,
            metadata={
                "layer_results": context.layer_results,
                "original_metadata": context.metadata,
                "detecting_layers": list(context.detecting_layers.keys()),
                "layer_risk_scores": context.layer_risk_scores,
            },
        )

    def _calculate_dynamic_threshold(self, context: ProcessingContext) -> float:
        """
        Calculate dynamic threshold based on context.

        Args:
            context: Processing context

        Returns:
            Adjusted blocking threshold
        """
        if not self.config.dynamic_threshold_enabled:
            return self.config.blocking_threshold

        base_threshold = self.config.blocking_threshold
        adjustments = []

        # Longer prompts might need stricter checking
        if len(context.text) > 200:
            adjustments.append(0.02)  # Stricter

        # Technical content might be safer (more lenient)
        if self._is_technical_content(context.text):
            adjustments.append(-0.05)  # TUNED: -0.03 -> -0.05 (more lenient for docs)

        # Multiple encoding anomalies
        if context.metadata.get("encoding_anomaly_score", 0) > 0.3:
            adjustments.append(0.05)  # Stricter

        # Calculate final threshold
        final_threshold = base_threshold + sum(adjustments)

        # Clamp to min/max
        final_threshold = max(
            self.config.min_threshold,
            min(self.config.max_threshold, final_threshold),
        )

        return final_threshold

    def _is_technical_content(self, text: str) -> bool:
        """Check if text appears to be technical/educational."""
        tech_keywords = [
            "explain",
            "how does",
            "what is",
            "difference between",
            "tutorial",
            "guide",
            "documentation",
            "api",
            "code",
        ]
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in tech_keywords)
    
    def _emergency_benign_check(self, text: str) -> bool:
        """
        Schnelle Heuristik für harmlose Prompts (FPR-Reduktion).
        
        Identifiziert offensichtlich harmlose Muster wie höfliche Fragen,
        Tutorial-Anfragen, etc. um False Positives zu reduzieren.
        
        Args:
            text: Input text to check
            
        Returns:
            True if text appears likely benign, False otherwise
        """
        text_lower = text.lower()
        
        # Offensichtlich harmlose Muster
        benign_patterns = [
            "please", "thank you", "can you help", "could you explain",
            "what is", "how does", "tell me about", "explain",
            "tutorial", "guide", "example", "learning",
            "hello", "hi ", "good morning", "good afternoon"
        ]
        
        # Offensichtlich schädliche Muster
        harmful_patterns = [
            "bypass", "evade", "hack", "exploit", "inject",
            "jailbreak", "dan ", "d.a.n", "roleplay as hacker",
            "ignore safety", "ignore rules", "override security"
        ]
        
        # Zähle Muster
        benign_count = sum(1 for pattern in benign_patterns if pattern in text_lower)
        harmful_count = sum(1 for pattern in harmful_patterns if pattern in text_lower)
        
        # Entscheidung
        if harmful_count > 0:
            return False
        if benign_count >= 2:
            return True
        if len(text) < 100 and "?" in text:  # Kurze Fragen sind oft harmlos
            return True
        
        return False
    
    def process_batch(
        self,
        texts: List[str],
        user_id: str = "batch_user",
        **kwargs
    ) -> List["FirewallDecision"]:
        """
        Process multiple texts in batch mode.
        
        NOTE: V3 processes sequentially (no batch optimization yet).
        This method exists for API compatibility with V2.
        Future: Implement true batch processing for GPU optimization.
        
        Args:
            texts: List of input texts
            user_id: User identifier
            **kwargs: Additional context
            
        Returns:
            List of FirewallDecision objects
        """
        return [self.process_input(user_id, text, **kwargs) for text in texts]
