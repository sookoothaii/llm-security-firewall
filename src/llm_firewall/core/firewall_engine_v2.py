"""
HAK_GAL Core Engine v2 - Protocol HEPHAESTUS Integration
========================================================

Clean, linear layer architecture for LLM security firewall.
Integrates Protocol HEPHAESTUS (Tool Security) for tool call validation.

Architecture:
- Layer 0: UnicodeSanitizer (Input sanitization)
- Layer 0.25: NormalizationLayer (Recursive URL/percent decoding)
- Layer 0.5: RegexGate (Fast-fail pattern matching)
- Layer 1: Input Analysis (Optional: Kids Policy, Semantic Guard)
- Layer 2: Tool Inspection (HEPHAESTUS - Tool Call Validation)
- Layer 3: Output Validation (Optional: Truth Preservation)

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-29
Status: Core Engine v2 - Protocol HEPHAESTUS
License: MIT
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

# Import UnicodeSanitizer and Kids Policy Engine from kids_policy
try:
    import sys
    from pathlib import Path

    # Add kids_policy to path
    kids_policy_path = Path(__file__).parent.parent.parent.parent / "kids_policy"
    if kids_policy_path.exists():
        sys.path.insert(0, str(kids_policy_path.parent))
        from kids_policy.unicode_sanitizer import UnicodeSanitizer
        from kids_policy.firewall_engine_v2 import HakGalFirewall_v2

        HAS_UNICODE_SANITIZER = True
        HAS_KIDS_POLICY = True
    else:
        HAS_UNICODE_SANITIZER = False
        HAS_KIDS_POLICY = False
        UnicodeSanitizer = None  # type: ignore[misc,assignment]
        HakGalFirewall_v2 = None  # type: ignore[misc,assignment]
except ImportError:
    HAS_UNICODE_SANITIZER = False
    HAS_KIDS_POLICY = False
    UnicodeSanitizer = None  # type: ignore[misc,assignment]
    HakGalFirewall_v2 = None  # type: ignore[misc,assignment]

# Import NormalizationLayer for recursive URL decoding (Layer 0.25)
try:
    from hak_gal.layers.inbound.normalization_layer import NormalizationLayer

    HAS_NORMALIZATION_LAYER = True
except ImportError:
    HAS_NORMALIZATION_LAYER = False
    NormalizationLayer = None  # type: ignore[misc,assignment]

# Import RegexGate for fast-fail pattern matching (Layer 0.5)
try:
    from hak_gal.layers.inbound.regex_gate import RegexGate
    from hak_gal.core.exceptions import SecurityException

    HAS_REGEX_GATE = True
except ImportError:
    HAS_REGEX_GATE = False
    RegexGate = None  # type: ignore[misc,assignment]
    SecurityException = None  # type: ignore[misc,assignment]

# Import Protocol HEPHAESTUS components
from llm_firewall.detectors.tool_call_extractor import ToolCallExtractor
from llm_firewall.detectors.tool_call_validator import ToolCallValidator

# Import Decision Cache Port (abstraction, no direct dependency)
try:
    from llm_firewall.core.ports import DecisionCachePort

    HAS_DECISION_CACHE_PORT = True
except ImportError:
    HAS_DECISION_CACHE_PORT = False
    DecisionCachePort = None  # type: ignore

# Legacy import (for backward compatibility - will be removed)
try:
    from llm_firewall.cache.decision_cache import get_cached, set_cached

    HAS_DECISION_CACHE = True
except ImportError:
    HAS_DECISION_CACHE = False
    get_cached = None  # type: ignore
    set_cached = None  # type: ignore

# Import AnswerPolicy (optional - epistemic decision layer)
try:
    from llm_firewall.core.policy_provider import PolicyProvider

    HAS_ANSWER_POLICY = True
except ImportError:
    HAS_ANSWER_POLICY = False
    PolicyProvider = None  # type: ignore

# Import Dempster-Shafer Fusion (optional - evidence-based p_correct)
try:
    from llm_firewall.fusion.dempster_shafer import (
        DempsterShaferFusion,
        EvidenceMass,
        make_mass,
    )

    HAS_DEMPSTER_SHAFER = True
except ImportError:
    HAS_DEMPSTER_SHAFER = False
    DempsterShaferFusion = None  # type: ignore
    EvidenceMass = None  # type: ignore
    make_mass = None  # type: ignore

logger = logging.getLogger(__name__)


@dataclass
class FirewallDecision:
    """
    Decision result from firewall processing.

    Attributes:
        allowed: Whether the request/response is allowed
        reason: Human-readable reason for allow/block decision
        sanitized_text: Sanitized text (if sanitization was applied)
        risk_score: Risk score [0.0, 1.0]
        detected_threats: List of detected threat patterns
        metadata: Additional metadata (tool calls, etc.)
    """

    allowed: bool
    reason: str
    sanitized_text: Optional[str] = None
    risk_score: float = 0.0
    detected_threats: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.detected_threats is None:
            self.detected_threats = []
        if self.metadata is None:
            self.metadata = {}


class FirewallEngineV2:
    """
    HAK_GAL Core Engine v2 - Clean Layer Architecture.

    Architecture:
    - Layer 0: UnicodeSanitizer (Input sanitization)
    - Layer 0.25: NormalizationLayer (Recursive URL/percent decoding)
    - Layer 0.5: RegexGate (Fast-fail pattern matching)
    - Layer 1: Input Analysis (Optional: Kids Policy, Semantic Guard)
    - Layer 2: Tool Inspection (HEPHAESTUS - Tool Call Validation)
    - Layer 3: Output Validation (Optional: Truth Preservation)

    Usage:
        engine = FirewallEngineV2()
        input_decision = engine.process_input(user_id="user123", text="user input")
        if input_decision.allowed:
            # Send to LLM
            llm_output = generate_llm_response(input_decision.sanitized_text)
            output_decision = engine.process_output(text=llm_output, user_id="user123")
            if output_decision.allowed:
                # Return to user
                return output_decision.sanitized_text
    """

    def __init__(
        self,
        allowed_tools: Optional[List[str]] = None,
        strict_mode: bool = True,
        enable_sanitization: bool = True,
        cache_adapter: Optional[
            Any
        ] = None,  # DecisionCachePort (type hint avoided due to optional import)
        dempster_shafer_fuser: Optional[Any] = None,  # DempsterShaferFusion (optional)
        use_evidence_based_p_correct: bool = False,  # Enable evidence-based p_correct
        p_correct_stretch_factor: float = 1.0,  # Stretch factor for p_correct distribution (1.0 = no stretch)
        vector_guard: Optional[
            Any
        ] = None,  # VectorGuard instance (optional, for CUSUM evidence)
        uncertainty_boost_factor: float = 0.0,  # Uncertainty boost for intermediate confidence values (0.0 = disabled)
        use_optimized_mass_calibration: bool = False,  # Use optimized mass calibration (experimental)
        p_correct_formula: str = "stretched",  # p_correct formula: 'stretched', 'weighted', 'plausibility', 'transformed'
        p_correct_scale_method: str = "none",  # Scaling method: 'linear_shift', 'power_transform', 'simple_shift', 'none'
    ):
        """
        Initialize Firewall Engine v2.

        Args:
            allowed_tools: List of allowed tool names for Protocol HEPHAESTUS
            strict_mode: If True, blocks on any detected threat. If False, sanitizes and warns.
            enable_sanitization: If True, attempts to sanitize dangerous arguments.
            cache_adapter: Optional DecisionCachePort adapter (if None, uses legacy import fallback)
        """
        # Layer 0: UnicodeSanitizer
        if HAS_UNICODE_SANITIZER and UnicodeSanitizer is not None:
            self.sanitizer = UnicodeSanitizer()  # type: ignore[misc,assignment]
            logger.info("UnicodeSanitizer initialized (Layer 0)")
        else:
            self.sanitizer = None  # type: ignore[assignment]
            logger.warning(
                "UnicodeSanitizer not available. Input sanitization disabled."
            )

        # Layer 0.25: NormalizationLayer - Recursive URL/percent decoding
        if HAS_NORMALIZATION_LAYER and NormalizationLayer is not None:
            self.normalization_layer = NormalizationLayer(max_decode_depth=3)  # type: ignore[misc,assignment]
            logger.info("NormalizationLayer initialized (Layer 0.25)")
        else:
            self.normalization_layer = None  # type: ignore[assignment]
            logger.warning(
                "NormalizationLayer not available. URL decoding normalization disabled."
            )

        # Layer 0.5: RegexGate - Fast-fail pattern matching for command injection, jailbreaks, etc.
        if HAS_REGEX_GATE and RegexGate is not None:
            self.regex_gate = RegexGate()  # type: ignore[misc,assignment]
            logger.info("RegexGate initialized (Layer 0.5)")
        else:
            self.regex_gate = None  # type: ignore[assignment]
            logger.warning(
                "RegexGate not available. Fast-fail pattern matching disabled."
            )

        # Protocol HEPHAESTUS: Tool Call Extractor
        self.extractor = ToolCallExtractor(strict_mode=False)
        logger.info("ToolCallExtractor initialized (Protocol HEPHAESTUS)")

        # Protocol HEPHAESTUS: Tool Call Validator
        self.validator = ToolCallValidator(
            allowed_tools=allowed_tools,
            strict_mode=strict_mode,
            enable_sanitization=enable_sanitization,
        )
        logger.info("ToolCallValidator initialized (Protocol HEPHAESTUS)")

        # Kids Policy Engine (v2.1.0-HYDRA) - Full Integration
        self.kids_policy = None
        if HAS_KIDS_POLICY and HakGalFirewall_v2 is not None:
            try:
                self.kids_policy = HakGalFirewall_v2()
                logger.info(
                    "Kids Policy Engine v2.1.0-HYDRA initialized (TAG-2 + HYDRA-13)"
                )
            except Exception as e:
                logger.warning(f"Kids Policy Engine initialization failed: {e}")
                self.kids_policy = None
        else:
            logger.warning(
                "Kids Policy Engine not available. Input/Output validation limited."
            )

        # Cache adapter (Dependency Injection - fixes Dependency Rule violation)
        self.cache_adapter = cache_adapter
        if cache_adapter is None and HAS_DECISION_CACHE:
            # Legacy fallback: Use global functions (backward compatibility)
            logger.info("Using legacy cache import (backward compatibility)")
        elif cache_adapter is not None:
            logger.info("Cache adapter injected via Dependency Injection")
        else:
            logger.info("No cache adapter available - cache disabled")

        # Dempster-Shafer Fuser (optional - for evidence-based p_correct)
        self.use_evidence_based_p_correct = use_evidence_based_p_correct
        if (
            use_evidence_based_p_correct
            and HAS_DEMPSTER_SHAFER
            and DempsterShaferFusion is not None
        ):
            self.dempster_shafer_fuser = dempster_shafer_fuser or DempsterShaferFusion()
            logger.info("Dempster-Shafer Fusion enabled for evidence-based p_correct")
        else:
            self.dempster_shafer_fuser = None
            if use_evidence_based_p_correct:
                logger.warning(
                    "Evidence-based p_correct requested but Dempster-Shafer not available. "
                    "Falling back to heuristic."
                )

        # VectorGuard (optional - for CUSUM drift evidence)
        self.vector_guard = (
            vector_guard  # Can be injected or set via dependency injection
        )

        # p_correct stretch factor (for distribution calibration)
        self.p_correct_stretch_factor = float(p_correct_stretch_factor)

        # Uncertainty boost factor (for evidence calibration)
        self.uncertainty_boost_factor = float(
            uncertainty_boost_factor
        )  # Evidence calibration parameter

        # Optimized mass calibration (experimental)
        self.use_optimized_mass_calibration = use_optimized_mass_calibration

        # p_correct formula selection
        valid_formulas = ["stretched", "weighted", "plausibility", "transformed"]
        if p_correct_formula not in valid_formulas:
            raise ValueError(
                f"p_correct_formula must be one of {valid_formulas}, got {p_correct_formula}"
            )
        self.p_correct_formula = p_correct_formula

        # p_correct scaling method
        valid_scale_methods = [
            "none",
            "linear_shift",
            "power_transform",
            "simple_shift",
        ]
        if p_correct_scale_method not in valid_scale_methods:
            raise ValueError(
                f"p_correct_scale_method must be one of {valid_scale_methods}, got {p_correct_scale_method}"
            )
        self.p_correct_scale_method = p_correct_scale_method

    def _get_cusum_evidence(
        self, context: Optional[Dict[str, Any]] = None, user_id: Optional[str] = None
    ) -> float:
        """
        Get CUSUM drift evidence from VectorGuard.

        Attempts multiple access paths:
        1. Direct VectorGuard instance (if injected)
        2. VectorGuard from context
        3. SessionManager lookup (if available)
        4. Fallback: 0.0 (no drift assumed)

        Args:
            context: Optional request context (may contain vector_guard, session_id, etc.)
            user_id: Optional user/session identifier for session-based lookup

        Returns:
            Normalized CUSUM drift score [0.0, 1.0] where 1.0 = maximum drift
        """
        vector_guard = None
        session_id = None

        # 1. Try direct instance variable (if injected via __init__ or setter)
        if self.vector_guard is not None:
            vector_guard = self.vector_guard

        # 2. Try context dictionary
        if vector_guard is None and context is not None:
            vector_guard = context.get("vector_guard")
            session_id = context.get("session_id") or context.get("user_id")

        # 3. Try user_id as session_id
        if session_id is None and user_id is not None:
            session_id = user_id

        # 4. If VectorGuard found, try to get CUSUM score
        if vector_guard is not None:
            try:
                # Try multiple access patterns
                cusum_score = None
                cusum_threshold = 1.0  # Default normalization

                # Pattern 1: Direct attribute access (SessionTrajectory)
                if hasattr(vector_guard, "cusum_score"):
                    cusum_score = vector_guard.cusum_score
                    if hasattr(vector_guard, "cusum_threshold"):
                        cusum_threshold = vector_guard.cusum_threshold

                # Pattern 2: Session-based lookup (VectorGuard with _get_trajectory)
                elif session_id is not None and hasattr(
                    vector_guard, "_get_trajectory"
                ):
                    try:
                        trajectory = vector_guard._get_trajectory(session_id)
                        if hasattr(trajectory, "cusum_score"):
                            cusum_score = trajectory.cusum_score
                            if hasattr(trajectory, "cusum_threshold"):
                                cusum_threshold = trajectory.cusum_threshold
                    except Exception as e:
                        logger.debug(
                            f"[CUSUM] Failed to get trajectory for session {session_id}: {e}"
                        )

                # Pattern 3: Method call (if VectorGuard has get_cusum_score method)
                elif hasattr(vector_guard, "get_cusum_score"):
                    try:
                        if session_id is not None:
                            cusum_score = vector_guard.get_cusum_score(session_id)
                        else:
                            cusum_score = vector_guard.get_cusum_score()
                    except Exception as e:
                        logger.debug(f"[CUSUM] get_cusum_score() failed: {e}")

                # Normalize score: cusum_score / cusum_threshold, clamped to [0, 1]
                if cusum_score is not None:
                    if cusum_threshold > 0:
                        normalized = max(0.0, min(1.0, cusum_score / cusum_threshold))
                    else:
                        normalized = max(0.0, min(1.0, cusum_score))
                    logger.debug(
                        f"[CUSUM] Retrieved score: {cusum_score:.4f} / {cusum_threshold:.4f} = {normalized:.4f}"
                    )
                    return normalized

            except Exception as e:
                logger.debug(f"[CUSUM] Error accessing VectorGuard: {e}")

        # Fallback: No CUSUM evidence available
        return 0.0

    def _compute_adaptive_ignorance(
        self, confidence: float, evidence_type: str = "risk_scorer"
    ) -> float:
        """
        Compute adaptive ignorance based on confidence value.

        Higher ignorance for intermediate confidence values (uncertain cases),
        lower ignorance for extreme values (clear cases).

        Args:
            confidence: Confidence score [0.0, 1.0]
            evidence_type: Type of evidence (risk_scorer, cusum_drift, encoding_anomaly)

        Returns:
            Adaptive ignorance value [0.0, 1.0]
        """
        if evidence_type == "risk_scorer":
            # Risk scorer: Higher ignorance for intermediate risks
            if 0.4 < confidence < 0.6:
                # High uncertainty for uncertain risks
                return 0.5
            elif 0.2 < confidence < 0.8:
                # Moderate uncertainty
                return 0.3
            else:
                # Low uncertainty for clear cases
                return 0.2
        elif evidence_type == "cusum_drift":
            # CUSUM: Moderate uncertainty (drift detection is inherently uncertain)
            if 0.3 < confidence < 0.7:
                return 0.4
            else:
                return 0.25
        else:
            # Encoding anomaly: Lower uncertainty (more deterministic)
            if 0.4 < confidence < 0.6:
                return 0.3
            else:
                return 0.2

    def _apply_uncertainty_boost(
        self, confidence: float, boost_factor: Optional[float] = None
    ) -> float:
        """
        Kontinuierliche Uncertainty Boost-Funktion.

        Transformiert Confidence-Werte näher zu 0.5, ohne Diskontinuität.
        Erhält Monotonie und Unterscheidungsfähigkeit für alle Werte.

        Formula: boosted = 0.5 + (confidence - 0.5) * (1.0 - boost_factor)

        Bei boost_factor=0.4:
        - 0.0 → 0.2, 1.0 → 0.8 (Extreme werden gemildert)
        - 0.5 → 0.5 (Mittelwert bleibt erhalten)
        - 0.8 → 0.68, 0.2 → 0.32 (lineare Transformation)
        - 0.4 → 0.44, 0.6 → 0.56 (Unterscheidung erhalten!)

        Beispiel-Transformationen (boost_factor=0.4):
        - confidence=0.0 → returns 0.2 (increased from 0.0)
        - confidence=0.2 → returns 0.32 (increased from 0.2)
        - confidence=0.4 → returns 0.44 (increased from 0.4, NOT 0.5!)
        - confidence=0.5 → returns 0.5 (unchanged, maximum uncertainty)
        - confidence=0.6 → returns 0.56 (decreased from 0.6, NOT 0.5!)
        - confidence=0.8 → returns 0.68 (decreased from 0.8)
        - confidence=1.0 → returns 0.8 (decreased from 1.0)

        Args:
            confidence: Confidence score [0.0, 1.0]
            boost_factor: Boost factor [0.0, 1.0]. If None, uses self.uncertainty_boost_factor.

        Returns:
            Boosted confidence value [0.0, 1.0]
        """
        if boost_factor is None:
            boost_factor = self.uncertainty_boost_factor

        if boost_factor <= 0.0:
            # No boost: return original confidence
            return confidence

        # Clamp boost_factor to valid range
        boost_factor = max(0.0, min(1.0, boost_factor))

        # Kontinuierliche lineare Transformation: Verschiebt alle Werte näher zu 0.5
        # Formel: boosted = 0.5 + (confidence - 0.5) * (1.0 - boost_factor)
        #
        # Mathematische Eigenschaften:
        # - Monoton: confidence1 < confidence2 → boosted1 < boosted2
        # - Kontinuierlich: keine Sprünge
        # - Symmetrisch: boost(0.5 + d) = 0.5 + boost_factor * d
        # - Bei boost_factor=0.4: 0.4 → 0.44, 0.5 → 0.5, 0.6 → 0.56
        boosted = 0.5 + (confidence - 0.5) * (1.0 - boost_factor)

        # Sicherstellen, dass Werte im [0,1] Bereich bleiben
        return max(0.0, min(1.0, boosted))

    def _stretched_p_correct(self, belief_quarantine: float) -> float:
        """
        Apply stretch factor to p_correct to expand the sensitive range.

        The stretch factor transforms the compressed Dempster-Shafer distribution
        by applying a power function to belief_quarantine before computing p_correct.

        Formula: p_correct = 1.0 - (belief_quarantine ^ (1.0 / stretch_factor))

        Examples (stretch_factor=2.0):
        - belief_quarantine=0.05 → stretched=0.2236 → p_correct=0.7764
        - belief_quarantine=0.20 → stretched=0.4472 → p_correct=0.5528
        - belief_quarantine=0.50 → stretched=0.7071 → p_correct=0.2929

        Args:
            belief_quarantine: Belief that item should be quarantined [0.0, 1.0]

        Returns:
            Stretched p_correct value [0.0, 1.0]
        """
        if self.p_correct_stretch_factor <= 1.0:
            # No stretching: use linear formula
            return max(0.0, min(1.0, 1.0 - belief_quarantine))

        # Apply power transformation to expand sensitive range
        # Higher stretch_factor = more expansion (more aggressive)
        stretched_quarantine = belief_quarantine ** (
            1.0 / self.p_correct_stretch_factor
        )
        p_correct = max(0.0, min(1.0, 1.0 - stretched_quarantine))

        return p_correct

    def _scale_p_correct_distribution(
        self, p_correct_raw: float, method: str = "linear_shift"
    ) -> float:
        """
        Skaliert die p_correct-Verteilung in den optimalen Bereich.

        Aktuelle Verteilung (mit weighted-Formel): min=0.829, max=0.992, mean=0.939
        Ziel-Verteilung: min≈0.3, max≈0.95, mean_redteam≈0.5, mean_benign≈0.7

        Args:
            p_correct_raw: Raw p_correct value from formula [0.0, 1.0]
            method: Scaling method ('linear_shift', 'power_transform', 'none')

        Returns:
            Scaled p_correct value [0.0, 1.0]
        """
        if method == "none" or method is None:
            return p_correct_raw

        if method == "linear_shift":
            # Einfache lineare Transformation: Verschiebt gesamte Verteilung nach unten
            # Formel: scaled = (raw - current_min) * (target_range/current_range) + target_min
            current_min = 0.8290
            current_max = 0.9916
            target_min = 0.30
            target_max = 0.95

            if p_correct_raw <= current_min:
                return target_min
            elif p_correct_raw >= current_max:
                return target_max
            else:
                # Lineare Interpolation
                scaled = target_min + (p_correct_raw - current_min) * (
                    target_max - target_min
                ) / (current_max - current_min)
                return max(0.0, min(1.0, scaled))

        elif method == "power_transform":
            # Nicht-lineare Transformation: Behält relative Unterschiede bei
            # Reduziert hohe Werte stärker als niedrige
            power = 0.7
            return max(0.0, min(1.0, p_correct_raw**power))

        elif method == "simple_shift":
            # Einfache Verschiebung: p_correct - 0.35 (empirisch kalibriert)
            return max(0.0, min(1.0, p_correct_raw - 0.35))

        else:
            # Unknown method: return raw
            return p_correct_raw

    def _compute_evidence_based_p_correct(
        self,
        base_risk_score: float,
        encoding_anomaly_score: float = 0.0,
        context: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Compute p_correct using Dempster-Shafer evidence fusion.

        Combines multiple evidence sources (risk score, CUSUM drift, encoding anomalies)
        into a single p_correct estimate using Dempster-Shafer theory.

        Args:
            base_risk_score: Base risk score [0.0, 1.0]
            encoding_anomaly_score: Encoding anomaly score [0.0, 1.0]
            context: Optional request context

        Returns:
            Dictionary with:
            - p_correct: Estimated correctness probability [0.0, 1.0]
            - belief_quarantine: Belief that request should be quarantined
            - plausibility_quarantine: Plausibility that request should be quarantined
            - evidence_masses: Raw evidence masses for debugging
            - combined_mass: Fused evidence mass
        """
        # Fallback to heuristic if evidence-based computation not available
        if (
            not self.use_evidence_based_p_correct
            or self.dempster_shafer_fuser is None
            or not HAS_DEMPSTER_SHAFER
            or make_mass is None
        ):
            p_correct = max(0.0, min(1.0, 1.0 - base_risk_score))
            return {
                "p_correct": p_correct,
                "belief_quarantine": base_risk_score,
                "plausibility_quarantine": base_risk_score,
                "evidence_masses": {
                    "risk_scorer": base_risk_score,
                    "cusum_drift": 0.0,
                    "encoding_anomaly": encoding_anomaly_score,
                },
                "combined_mass": None,
                "method": "heuristic",
            }

        # 1. Collect evidence sources
        risk_score = float(base_risk_score)
        cusum_drift = self._get_cusum_evidence(context=context, user_id=user_id)
        encoding_anomaly = float(encoding_anomaly_score)

        # 2. Convert evidence to promote confidence (invert scores)
        # Higher scores = higher quarantine mass (invert for promote confidence)
        risk_promote_confidence_raw = 1.0 - risk_score
        cusum_promote_confidence_raw = 1.0 - cusum_drift
        encoding_promote_confidence_raw = 1.0 - encoding_anomaly

        # 3. Apply uncertainty boost (if enabled) to force more uncertainty for intermediate values
        risk_promote_confidence = self._apply_uncertainty_boost(
            risk_promote_confidence_raw
        )
        cusum_promote_confidence = self._apply_uncertainty_boost(
            cusum_promote_confidence_raw
        )
        encoding_promote_confidence = self._apply_uncertainty_boost(
            encoding_promote_confidence_raw
        )

        # Log evidence inputs for calibration analysis
        evidence_values = {
            "risk_confidence_raw": risk_promote_confidence_raw,
            "risk_confidence_boosted": risk_promote_confidence,
            "cusum_confidence_raw": cusum_promote_confidence_raw,
            "cusum_confidence_boosted": cusum_promote_confidence,
            "encoding_confidence_raw": encoding_promote_confidence_raw,
            "encoding_confidence_boosted": encoding_promote_confidence,
            "base_risk_score": risk_score,
            "cusum_drift": cusum_drift,
            "encoding_anomaly": encoding_anomaly,
        }
        logger.debug(f"[EvidenceFusion] Evidence inputs: {evidence_values}")

        # 4. Convert evidence to EvidenceMass objects

        # Adaptive ignorance: More uncertainty for intermediate confidence values
        risk_ignorance = self._compute_adaptive_ignorance(
            risk_promote_confidence, evidence_type="risk_scorer"
        )
        cusum_ignorance = self._compute_adaptive_ignorance(
            cusum_promote_confidence, evidence_type="cusum_drift"
        )
        encoding_ignorance = self._compute_adaptive_ignorance(
            encoding_promote_confidence, evidence_type="encoding_anomaly"
        )

        # Use optimized mass calibration if enabled (experimental)
        use_optimized_mass = getattr(self, "use_optimized_mass_calibration", False)
        if use_optimized_mass:
            from llm_firewall.fusion.dempster_shafer import make_mass_optimized

            risk_mass = make_mass_optimized(
                confidence=risk_promote_confidence, evidence_type="risk_scorer"
            )
            cusum_mass = make_mass_optimized(
                confidence=cusum_promote_confidence, evidence_type="cusum_drift"
            )
            encoding_mass = make_mass_optimized(
                confidence=encoding_promote_confidence, evidence_type="encoding_anomaly"
            )
        else:
            risk_mass = make_mass(
                score=risk_promote_confidence, allow_ignorance=risk_ignorance
            )
            cusum_mass = make_mass(
                score=cusum_promote_confidence, allow_ignorance=cusum_ignorance
            )
            encoding_mass = make_mass(
                score=encoding_promote_confidence, allow_ignorance=encoding_ignorance
            )

        # Log evidence masses for calibration analysis
        evidence_masses_log = {
            "risk_mass": {
                "promote": risk_mass.promote,
                "quarantine": risk_mass.quarantine,
                "unknown": risk_mass.unknown,
            },
            "cusum_mass": {
                "promote": cusum_mass.promote,
                "quarantine": cusum_mass.quarantine,
                "unknown": cusum_mass.unknown,
            },
            "encoding_mass": {
                "promote": encoding_mass.promote,
                "quarantine": encoding_mass.quarantine,
                "unknown": encoding_mass.unknown,
            },
        }
        logger.debug(f"[EvidenceFusion] Evidence masses: {evidence_masses_log}")

        # 5. Fuse evidence using Dempster-Shafer
        masses = [risk_mass, cusum_mass, encoding_mass]
        combined_mass = self.dempster_shafer_fuser.combine_masses(masses)

        # Log fusion result for calibration analysis
        fusion_result_log = {
            "combined_mass": {
                "promote": combined_mass.promote,
                "quarantine": combined_mass.quarantine,
                "unknown": combined_mass.unknown,
            },
        }
        logger.debug(f"[EvidenceFusion] Fusion result: {fusion_result_log}")

        # 6. Compute belief functions
        belief_promote, belief_quarantine = self.dempster_shafer_fuser.compute_belief(
            combined_mass
        )

        # Log belief functions for calibration analysis
        logger.debug(
            f"[EvidenceFusion] Belief functions: belief_promote={belief_promote:.4f}, "
            f"belief_quarantine={belief_quarantine:.4f}"
        )

        # 7. Compute plausibility (belief + unknown mass) - needed for some formulas
        plausibility_quarantine = belief_quarantine + combined_mass.unknown

        # 8. Derive p_correct from belief
        # Multiple formula options for testing
        p_correct_formula = getattr(
            self, "p_correct_formula", "stretched"
        )  # 'stretched', 'weighted', 'plausibility', 'transformed'

        if p_correct_formula == "weighted":
            # Option B: Weighted combination (promote + 0.5 * unknown)
            p_correct_raw = belief_promote + (combined_mass.unknown * 0.5)
            # Apply scaling if enabled (shifts distribution down from min=0.829 to target min≈0.3)
            p_correct = self._scale_p_correct_distribution(
                p_correct_raw, method=self.p_correct_scale_method
            )
        elif p_correct_formula == "plausibility":
            # Option C: Plausibility-based (1 - plausibility_quarantine)
            p_correct = 1.0 - plausibility_quarantine
        elif p_correct_formula == "transformed":
            # Option D: Transformed (1 - belief_quarantine^0.7)
            p_correct = 1.0 - (belief_quarantine**0.7)
        else:
            # Option A: Stretched (default, current implementation)
            # p_correct = 1 - belief_quarantine (higher quarantine belief = lower p_correct)
            # Apply stretch factor to expand the sensitive range
            p_correct = self._stretched_p_correct(belief_quarantine)

        # Log final p_correct for calibration analysis
        logger.debug(
            f"[EvidenceFusion] Final p_correct: {p_correct:.4f} (stretch_factor={self.p_correct_stretch_factor})"
        )

        return {
            "p_correct": p_correct,
            "belief_quarantine": belief_quarantine,
            "plausibility_quarantine": plausibility_quarantine,
            "evidence_masses": {
                "risk_scorer": {
                    "promote": risk_mass.promote,
                    "quarantine": risk_mass.quarantine,
                    "unknown": risk_mass.unknown,
                },
                "cusum_drift": {
                    "promote": cusum_mass.promote,
                    "quarantine": cusum_mass.quarantine,
                    "unknown": cusum_mass.unknown,
                },
                "encoding_anomaly": {
                    "promote": encoding_mass.promote,
                    "quarantine": encoding_mass.quarantine,
                    "unknown": encoding_mass.unknown,
                },
            },
            "combined_mass": {
                "promote": combined_mass.promote,
                "quarantine": combined_mass.quarantine,
                "unknown": combined_mass.unknown,
            },
            "method": "dempster_shafer",
        }

    def _create_decision_with_metadata(
        self,
        allowed: bool,
        reason: str,
        sanitized_text: Optional[str] = None,
        risk_score: float = 0.0,
        detected_threats: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        blocked_by_answer_policy: bool = False,
        base_risk_score: Optional[float] = None,
        **kwargs,
    ) -> FirewallDecision:
        """
        Create FirewallDecision with guaranteed AnswerPolicy metadata.

        This ensures AnswerPolicy metadata is ALWAYS present in all decision paths,
        even when AnswerPolicy is disabled or unavailable.

        Args:
            allowed: Whether request is allowed
            reason: Human-readable reason
            sanitized_text: Sanitized text (if applicable)
            risk_score: Risk score [0.0, 1.0]
            detected_threats: List of detected threats
            metadata: Additional metadata (will be merged with AnswerPolicy metadata)
            blocked_by_answer_policy: Whether this decision was blocked by AnswerPolicy
            base_risk_score: Base risk score for AnswerPolicy calculation (if None, uses risk_score)
            **kwargs: Additional context (use_answer_policy, policy_provider, tenant_id, route, context)

        Returns:
            FirewallDecision with guaranteed AnswerPolicy metadata
        """
        # Initialize metadata dict
        if metadata is None:
            metadata = {}
        else:
            metadata = dict(metadata)  # Copy to avoid mutation

        # Always add AnswerPolicy metadata (even if disabled)
        use_answer_policy = kwargs.get("use_answer_policy", False)
        policy_provider = kwargs.get("policy_provider", None)
        base_risk = base_risk_score if base_risk_score is not None else risk_score

        answer_policy_metadata = {
            "enabled": use_answer_policy
            and HAS_ANSWER_POLICY
            and PolicyProvider is not None
            and policy_provider is not None,
            "policy_name": None,
            "p_correct": None,
            "threshold": None,
            "mode": None,
            "blocked_by_answer_policy": blocked_by_answer_policy,
        }

        # If AnswerPolicy is enabled, try to compute metadata
        if (
            use_answer_policy
            and HAS_ANSWER_POLICY
            and PolicyProvider is not None
            and policy_provider is not None
        ):
            try:
                tenant_id_meta = kwargs.get("tenant_id", "default")
                route_meta = kwargs.get("route", None)
                context_meta = kwargs.get("context", {})
                policy_meta = policy_provider.for_tenant(
                    tenant_id_meta, route=route_meta, context=context_meta
                )

                # Compute p_correct using evidence fusion (if enabled) or heuristic
                encoding_anomaly = (
                    metadata.get("encoding_anomaly_score", 0.0) if metadata else 0.0
                )
                user_id_meta = kwargs.get("user_id") or context_meta.get("user_id")
                evidence_result = self._compute_evidence_based_p_correct(
                    base_risk_score=base_risk,
                    encoding_anomaly_score=encoding_anomaly,
                    context=context_meta,
                    user_id=user_id_meta,
                )
                p_correct_meta = evidence_result["p_correct"]
                decision_mode_meta = policy_meta.decide(
                    p_correct_meta, risk_score=base_risk
                )

                answer_policy_metadata.update(
                    {
                        "policy_name": policy_meta.policy_name,
                        "p_correct": p_correct_meta,
                        "threshold": policy_meta.threshold(),
                        "mode": decision_mode_meta,
                        # Extended metadata (if evidence-based)
                        "belief_quarantine": evidence_result.get("belief_quarantine"),
                        "plausibility_quarantine": evidence_result.get(
                            "plausibility_quarantine"
                        ),
                        "evidence_masses": evidence_result.get("evidence_masses"),
                        "combined_mass": evidence_result.get("combined_mass"),
                        "p_correct_method": evidence_result.get("method", "heuristic"),
                    }
                )
            except Exception as e:
                logger.debug(f"[AnswerPolicy] Metadata collection failed: {e}")
                # Keep defaults (enabled=False) on error

        # Merge AnswerPolicy metadata into main metadata
        metadata["answer_policy"] = answer_policy_metadata

        return FirewallDecision(
            allowed=allowed,
            reason=reason,
            sanitized_text=sanitized_text,
            risk_score=risk_score,
            detected_threats=detected_threats,
            metadata=metadata,
        )

    def process_input(
        self,
        user_id: str,
        text: str,
        **kwargs,
    ) -> FirewallDecision:
        """
        Process user input through firewall layers.

        Args:
            user_id: Unique user identifier
            text: Raw user input text
            **kwargs: Additional context (age_band, topic_id, etc.)

        Returns:
            FirewallDecision with allow/block decision and sanitized text
        """
        if not text or not text.strip():
            return self._create_decision_with_metadata(
                allowed=True,
                reason="Empty input",
                sanitized_text="",
                risk_score=0.0,
                **kwargs,
            )

        # Layer 0: UnicodeSanitizer
        clean_text = text
        unicode_flags: dict[str, Any] = {}
        if self.sanitizer:
            try:
                clean_text, unicode_flags = self.sanitizer.sanitize(text)
                if clean_text != text:
                    logger.debug(
                        f"[Layer 0] Unicode sanitization applied: {len(unicode_flags)} flags"
                    )
            except Exception as e:
                logger.warning(
                    f"[Layer 0] UnicodeSanitizer error: {e}. Using original text."
                )
                clean_text = text

        # Layer 0.25: NormalizationLayer - Recursive URL/percent decoding
        encoding_anomaly_score = 0.0
        if self.normalization_layer:
            try:
                clean_text, encoding_anomaly_score = self.normalization_layer.normalize(
                    clean_text
                )
                if encoding_anomaly_score > 0.0:
                    logger.warning(
                        f"[Layer 0.25] Encoding anomaly detected: score={encoding_anomaly_score:.2f}"
                    )
                    # If encoding anomaly is high, boost risk score
                    if encoding_anomaly_score > 0.5:
                        # High anomaly = suspicious, but don't block yet (let RegexGate check)
                        logger.warning(
                            f"[Layer 0.25] High encoding anomaly ({encoding_anomaly_score:.2f}) - "
                            "normalized text will be checked by RegexGate"
                        )
            except Exception as e:
                logger.warning(
                    f"[Layer 0.25] NormalizationLayer error: {e}. Using previous text."
                )

        # Cache Layer: Check for cached decision (after normalization, before RegexGate)
        tenant_id = kwargs.get("tenant_id", "default")

        # Use injected cache adapter if available, otherwise fallback to legacy import
        cached = None
        if self.cache_adapter is not None:
            try:
                cached = self.cache_adapter.get(tenant_id, clean_text)
            except Exception as e:
                logger.debug(f"[Cache] Adapter error (fail-open): {e}")
                cached = None
        elif HAS_DECISION_CACHE and get_cached is not None:
            # Legacy fallback (backward compatibility)
            try:
                cached = get_cached(tenant_id, clean_text)
            except Exception as e:
                logger.debug(f"[Cache] Legacy error (fail-open): {e}")
                cached = None

        if cached:
            logger.debug(f"[Cache] HIT for tenant {tenant_id}")
            # Reconstruct FirewallDecision from cached dict, but ensure AnswerPolicy metadata is present
            cached_metadata = cached.get("metadata", {})
            # Use helper to ensure AnswerPolicy metadata is always present (even for cached decisions)
            return self._create_decision_with_metadata(
                allowed=cached.get("allowed", True),
                reason=cached.get("reason", "Cached decision"),
                sanitized_text=cached.get("sanitized_text"),
                risk_score=cached.get("risk_score", 0.0),
                detected_threats=cached.get("detected_threats", []),
                metadata=cached_metadata,
                base_risk_score=cached.get("risk_score", 0.0),
                **kwargs,
            )

        # Layer 0.5: RegexGate - Fast-fail pattern matching (command injection, jailbreaks, etc.)
        if self.regex_gate:
            try:
                self.regex_gate.check(clean_text)
                logger.debug("[Layer 0.5] RegexGate: PASSED")
            except SecurityException as e:
                # Fast-fail: Block immediately on pattern match
                logger.warning(
                    f"[Layer 0.5] BLOCKED by RegexGate: {e.message} (threat: {e.metadata.get('threat_name', 'unknown')})"
                )
                risk = min(
                    1.0, 0.65 + encoding_anomaly_score * 0.35
                )  # Boost if encoding anomaly
                return self._create_decision_with_metadata(
                    allowed=False,
                    reason=f"RegexGate: {e.message}",
                    sanitized_text=None,
                    risk_score=risk,
                    detected_threats=[
                        e.metadata.get("threat_name", "REGEX_GATE_VIOLATION")
                    ],
                    metadata={
                        "regex_gate_violation": e.metadata,
                        "unicode_flags": unicode_flags,
                        "encoding_anomaly_score": encoding_anomaly_score,
                    },
                    base_risk_score=risk,
                    **kwargs,
                )
            except Exception as e:
                logger.error(f"[Layer 0.5] RegexGate error: {e}", exc_info=True)
                # Fail-closed: Block on error (security first)
                return self._create_decision_with_metadata(
                    allowed=False,
                    reason=f"RegexGate error: {str(e)}",
                    sanitized_text=None,
                    risk_score=1.0,
                    detected_threats=["REGEX_GATE_ERROR"],
                    metadata={"unicode_flags": unicode_flags},
                    base_risk_score=1.0,
                    **kwargs,
                )

        # Layer 1: Kids Policy Engine (v2.1.0-HYDRA) - Input Validation
        if self.kids_policy:
            try:
                # Call Kids Policy process_request (includes all layers: PersonaSkeptic, MetaExploitationGuard, TopicRouter, etc.)
                kids_result = self.kids_policy.process_request(
                    user_id=user_id,
                    raw_input=clean_text,
                    detected_topic=kwargs.get("topic_id"),
                )

                # Check if Kids Policy blocked the input
                if kids_result.get("status") == "BLOCK":
                    # Security First: Block immediately
                    logger.warning(
                        f"[Layer 1] BLOCKED by Kids Policy: {kids_result.get('reason', 'Unknown')}"
                    )
                    kids_risk = kids_result.get("debug", {}).get("risk_score", 1.0)
                    return self._create_decision_with_metadata(
                        allowed=False,
                        reason=f"Kids Policy: {kids_result.get('reason', 'BLOCKED')}",
                        sanitized_text=None,
                        risk_score=kids_risk,
                        detected_threats=[
                            kids_result.get("block_reason_code", "KIDS_POLICY_BLOCK")
                        ],
                        metadata={
                            "kids_policy_result": kids_result,
                            "unicode_flags": unicode_flags,
                        },
                        base_risk_score=kids_risk,
                        **kwargs,
                    )

                # Kids Policy allowed - continue
                logger.debug("[Layer 1] Kids Policy: ALLOWED")
                # Update clean_text if Kids Policy modified it (though it usually doesn't)
                if "debug" in kids_result and "input" in kids_result["debug"]:
                    clean_text = kids_result["debug"]["input"]

            except Exception as e:
                logger.error(f"[Layer 1] Kids Policy Engine error: {e}", exc_info=True)
                # Fail-open: Continue if Kids Policy fails (could be made fail-closed)
                # For now, we continue to allow the input

        # Calculate base risk score from unicode flags and encoding anomalies
        base_risk_score = 0.0

        # Zero-width characters indicate evasion attempts
        if unicode_flags.get("has_zero_width", False) or unicode_flags.get(
            "zero_width_removed", False
        ):
            base_risk_score += 0.6
            logger.warning("[Risk] Zero-width characters detected - evasion attempt")

        # RTL/LTR override characters indicate obfuscation
        if (
            unicode_flags.get("has_bidi", False)
            or unicode_flags.get("has_directional_override", False)
            or unicode_flags.get("bidi_detected", False)
        ):
            base_risk_score += 0.5
            logger.warning(
                "[Risk] Bidi/directional override detected - obfuscation attempt"
            )

        # Encoding anomalies increase risk
        base_risk_score += encoding_anomaly_score * 0.3

        # Check for concatenated patterns (API keys, secrets, etc.)
        try:
            from llm_firewall.rules.patterns import detect_concatenated_pattern

            suspicious_patterns = ["sk-live", "api-key", "secret", "password", "token"]
            for pattern in suspicious_patterns:
                if detect_concatenated_pattern(clean_text, pattern):
                    base_risk_score += 0.5
                    logger.warning(f"[Risk] Concatenated pattern detected: {pattern}")
                    break  # Only count once
        except Exception:
            pass  # Fail-open if concatenation check fails

        # AnswerPolicy Integration (optional epistemic decision layer)
        # This replaces/additional to simple threshold-based decisions with explicit cost-benefit trade-offs
        use_answer_policy = kwargs.get("use_answer_policy", False)
        policy_provider = kwargs.get("policy_provider", None)

        if (
            use_answer_policy
            and HAS_ANSWER_POLICY
            and PolicyProvider is not None
            and policy_provider is not None
        ):
            try:
                tenant_id = kwargs.get("tenant_id", "default")
                route = kwargs.get("route", None)
                context = kwargs.get("context", {})

                policy = policy_provider.for_tenant(
                    tenant_id, route=route, context=context
                )

                # Compute p_correct using evidence fusion (if enabled) or heuristic
                evidence_result = self._compute_evidence_based_p_correct(
                    base_risk_score=base_risk_score,
                    encoding_anomaly_score=encoding_anomaly_score,
                    context=context,
                    user_id=user_id,
                )

                # Adaptive threshold selection: Use evidence-optimized policy if evidence-based p_correct is enabled
                # and policy is "kids" (which uses threshold 0.98 for heuristic, but needs 0.65 for evidence)
                if (
                    self.use_evidence_based_p_correct
                    and policy.policy_name == "kids"
                    and evidence_result.get("method") == "dempster_shafer"
                ):
                    # Switch to kids_evidence policy (threshold 0.65) for evidence-based fusion
                    from llm_firewall.core.decision_policy import get_policy

                    try:
                        policy = get_policy("kids_evidence")
                        logger.debug(
                            f"[AnswerPolicy] Using adaptive threshold: switched from 'kids' to 'kids_evidence' "
                            f"(threshold: {policy.threshold():.3f}) for evidence-based p_correct"
                        )
                    except KeyError:
                        # Fallback: use original policy if kids_evidence not available
                        logger.warning(
                            "[AnswerPolicy] kids_evidence policy not found, using original 'kids' policy"
                        )

                p_correct = evidence_result["p_correct"]
                decision_mode = policy.decide(p_correct, risk_score=base_risk_score)

                if decision_mode == "silence":
                    # Epistemic gate: expected utility of silence > expected utility of answer
                    decision = self._create_decision_with_metadata(
                        allowed=False,
                        reason=(
                            f"Epistemic gate: p_correct={p_correct:.3f} < threshold={policy.threshold():.3f} "
                            f"(policy: {policy.policy_name or 'unknown'})"
                        ),
                        sanitized_text=clean_text,
                        risk_score=base_risk_score,
                        metadata={
                            "unicode_flags": unicode_flags,
                            "encoding_anomaly_score": encoding_anomaly_score,
                            "answer_policy_extra": {
                                "expected_utility_answer": policy.expected_utility_answer(
                                    p_correct
                                ),
                                "expected_utility_silence": policy.expected_utility_silence(),
                            },
                        },
                        blocked_by_answer_policy=True,
                        base_risk_score=base_risk_score,
                        **kwargs,
                    )
                    # Manually set AnswerPolicy metadata since we have full policy info here
                    if decision.metadata and "answer_policy" in decision.metadata:
                        decision.metadata["answer_policy"].update(
                            {
                                "policy_name": policy.policy_name,
                                "p_correct": p_correct,
                                "threshold": policy.threshold(),
                                "mode": decision_mode,
                                "expected_utility_answer": policy.expected_utility_answer(
                                    p_correct
                                ),
                                "expected_utility_silence": policy.expected_utility_silence(),
                                # Extended metadata (if evidence-based)
                                "belief_quarantine": evidence_result.get(
                                    "belief_quarantine"
                                ),
                                "plausibility_quarantine": evidence_result.get(
                                    "plausibility_quarantine"
                                ),
                                "evidence_masses": evidence_result.get(
                                    "evidence_masses"
                                ),
                                "combined_mass": evidence_result.get("combined_mass"),
                                "p_correct_method": evidence_result.get(
                                    "method", "heuristic"
                                ),
                            }
                        )

                    # Cache and return early
                    tenant_id_cache = kwargs.get("tenant_id", "default")
                    decision_dict = {
                        "allowed": decision.allowed,
                        "reason": decision.reason,
                        "sanitized_text": decision.sanitized_text,
                        "risk_score": decision.risk_score,
                        "detected_threats": decision.detected_threats or [],
                        "metadata": decision.metadata or {},
                    }

                    if self.cache_adapter is not None:
                        try:
                            self.cache_adapter.set(
                                tenant_id_cache, clean_text, decision_dict
                            )
                            logger.debug(
                                f"[Cache] Stored AnswerPolicy decision for tenant {tenant_id_cache}"
                            )
                        except Exception as e:
                            logger.debug(
                                f"[Cache] Adapter store failed (fail-open): {e}"
                            )
                    elif HAS_DECISION_CACHE and set_cached is not None:
                        try:
                            set_cached(tenant_id_cache, clean_text, decision_dict)
                            logger.debug(
                                f"[Cache] Stored AnswerPolicy decision for tenant {tenant_id_cache}"
                            )
                        except Exception as e:
                            logger.debug(
                                f"[Cache] Legacy store failed (fail-open): {e}"
                            )

                    logger.debug(
                        f"[AnswerPolicy] Blocked by epistemic gate: p_correct={p_correct:.3f}, "
                        f"threshold={policy.threshold():.3f}, policy={policy.policy_name}"
                    )
                    return decision

                # If decision_mode == "answer", continue to normal decision logic
                logger.debug(
                    f"[AnswerPolicy] Allowed by epistemic gate: p_correct={p_correct:.3f}, "
                    f"threshold={policy.threshold():.3f}, policy={policy.policy_name}"
                )

            except Exception as e:
                logger.warning(
                    f"[AnswerPolicy] Error in policy evaluation: {e}. Falling back to threshold-based decision.",
                    exc_info=True,
                )
                # Fall through to normal threshold logic

        # Normal threshold-based decision (existing code, fallback if AnswerPolicy disabled or fails)
        # Helper method ensures AnswerPolicy metadata is always present
        decision = self._create_decision_with_metadata(
            allowed=True if base_risk_score < 0.7 else False,  # Block if risk too high
            reason="Input validated"
            if base_risk_score < 0.7
            else "High risk from unicode obfuscation",
            sanitized_text=clean_text,
            risk_score=base_risk_score,
            metadata={
                "unicode_flags": unicode_flags,
                "encoding_anomaly_score": encoding_anomaly_score,
            },
            blocked_by_answer_policy=False,  # Normal threshold-based decision, not AnswerPolicy
            base_risk_score=base_risk_score,
            **kwargs,
        )

        # Cache Layer: Store decision for future requests (fail-open)
        tenant_id = kwargs.get("tenant_id", "default")

        # Convert FirewallDecision to dict for caching
        decision_dict = {
            "allowed": decision.allowed,
            "reason": decision.reason,
            "sanitized_text": decision.sanitized_text,
            "risk_score": decision.risk_score,
            "detected_threats": decision.detected_threats or [],
            "metadata": decision.metadata or {},
        }

        # Use injected cache adapter if available, otherwise fallback to legacy import
        if self.cache_adapter is not None:
            try:
                self.cache_adapter.set(tenant_id, clean_text, decision_dict)
                logger.debug(f"[Cache] Stored decision for tenant {tenant_id}")
            except Exception as e:
                logger.debug(f"[Cache] Adapter store failed (fail-open): {e}")
        elif HAS_DECISION_CACHE and set_cached is not None:
            # Legacy fallback (backward compatibility)
            try:
                set_cached(tenant_id, clean_text, decision_dict)
                logger.debug(f"[Cache] Stored decision for tenant {tenant_id}")
            except Exception as e:
                logger.debug(f"[Cache] Legacy store failed (fail-open): {e}")
                # Fail-open: Continue even if cache write fails

        return decision

    def process_output(
        self,
        text: str,
        user_id: Optional[str] = None,
        **kwargs,
    ) -> FirewallDecision:
        """
        Process LLM output through firewall layers (Protocol HEPHAESTUS).

        This is the core method for Protocol HEPHAESTUS integration.

        Args:
            text: Raw LLM output text (may contain tool calls)
            user_id: Optional user identifier for session tracking
            **kwargs: Additional context

        Returns:
            FirewallDecision with allow/block decision and sanitized text
        """
        if not text or not text.strip():
            return self._create_decision_with_metadata(
                allowed=True,
                reason="Empty output",
                sanitized_text="",
                risk_score=0.0,
                **kwargs,
            )

        # Step A: Extract tool calls from LLM output
        tool_calls = self.extractor.extract_tool_calls(text)

        if not tool_calls:
            # No tool calls found - output is plain text
            # Layer 3: Kids Policy Truth Preservation (TAG-2)
            if self.kids_policy:
                try:
                    # Call Kids Policy validate_output for Truth Preservation
                    kids_output_result = self.kids_policy.validate_output(
                        user_id=user_id or "unknown",
                        user_input=kwargs.get("user_input", ""),
                        llm_response=text,
                        age_band=kwargs.get("age_band"),
                        topic_id=kwargs.get("topic_id"),
                        cultural_context=kwargs.get("cultural_context", "none"),
                    )

                    # Check if Kids Policy blocked the output (Truth Violation)
                    if kids_output_result.get("status") == "BLOCK":
                        logger.warning(
                            f"[Layer 3] BLOCKED by Kids Policy Truth Preservation: {kids_output_result.get('reason', 'Unknown')}"
                        )
                        kids_output_risk = kids_output_result.get("debug", {}).get(
                            "risk_score", 1.0
                        )
                        return self._create_decision_with_metadata(
                            allowed=False,
                            reason=f"Truth Preservation: {kids_output_result.get('reason', 'TRUTH_VIOLATION')}",
                            sanitized_text=None,
                            risk_score=kids_output_risk,
                            detected_threats=["TRUTH_VIOLATION"],
                            metadata={
                                "kids_policy_output_result": kids_output_result,
                            },
                            base_risk_score=kids_output_risk,
                            **kwargs,
                        )

                    # Kids Policy allowed - output is valid
                    logger.debug("[Layer 3] Kids Policy Truth Preservation: ALLOWED")

                except Exception as e:
                    logger.error(
                        f"[Layer 3] Kids Policy Truth Preservation error: {e}",
                        exc_info=True,
                    )
                    # Fail-open: Continue if Truth Preservation fails

            return self._create_decision_with_metadata(
                allowed=True,
                reason="No tool calls detected, plain text output validated",
                sanitized_text=text,
                risk_score=0.0,
                **kwargs,
            )

        # Step B: Validate each tool call
        logger.info(f"[HEPHAESTUS] Found {len(tool_calls)} tool call(s) in output")
        detected_threats = []
        max_risk_score = 0.0
        sanitized_calls = []

        for call in tool_calls:
            tool_name = call["tool_name"]
            arguments = call["arguments"]

            # Step C: Validate tool call
            validation_result = self.validator.validate_tool_call(tool_name, arguments)

            if not validation_result.allowed:
                # Security First: Block entire response if any tool call is blocked
                logger.warning(
                    f"[HEPHAESTUS] BLOCKED: Tool '{tool_name}' rejected. Reason: {validation_result.reason}"
                )
                return self._create_decision_with_metadata(
                    allowed=False,
                    reason=f"Tool call blocked: {validation_result.reason}",
                    sanitized_text=None,
                    risk_score=validation_result.risk_score,
                    detected_threats=validation_result.detected_threats,
                    metadata={
                        "blocked_tool": tool_name,
                        "blocked_arguments": arguments,
                        "validation_result": validation_result,
                    },
                    base_risk_score=validation_result.risk_score,
                    **kwargs,
                )

            # Tool call is allowed, but may have sanitized arguments
            if validation_result.sanitized_args != arguments:
                # Arguments were sanitized - replace in tool call
                sanitized_call = {
                    "tool_name": tool_name,
                    "arguments": validation_result.sanitized_args,
                }
                sanitized_calls.append(sanitized_call)
                threat_count = (
                    len(validation_result.detected_threats)
                    if validation_result.detected_threats
                    else 0
                )
                logger.info(
                    f"[HEPHAESTUS] Sanitized arguments for tool '{tool_name}': {threat_count} threats removed"
                )
            else:
                # No sanitization needed
                sanitized_calls.append(call)

            # Track threats and risk
            if validation_result.detected_threats:
                detected_threats.extend(validation_result.detected_threats)
            max_risk_score = max(max_risk_score, validation_result.risk_score)

        # Step D: Rebuild text with sanitized tool calls (if any were sanitized)
        sanitized_text = text
        if any(
            call.get("arguments") != tool_calls[i]["arguments"]
            for i, call in enumerate(sanitized_calls)
        ):
            # At least one tool call was sanitized - rebuild text
            sanitized_text = self._rebuild_text_with_sanitized_calls(
                text, tool_calls, sanitized_calls
            )
            logger.info("[HEPHAESTUS] Rebuilt text with sanitized tool calls")

        # All tool calls validated and allowed
        return self._create_decision_with_metadata(
            allowed=True,
            reason=f"All {len(tool_calls)} tool call(s) validated successfully",
            sanitized_text=sanitized_text,
            risk_score=max_risk_score,
            detected_threats=detected_threats,
            base_risk_score=max_risk_score,
            **kwargs,
            metadata={
                "tool_calls": sanitized_calls,
                "original_tool_calls": tool_calls,
            },
        )

    def _rebuild_text_with_sanitized_calls(
        self,
        original_text: str,
        original_calls: List[Dict[str, Any]],
        sanitized_calls: List[Dict[str, Any]],
    ) -> str:
        """
        Rebuild text with sanitized tool calls.

        This is a simple implementation that replaces JSON objects in the text.
        For v1, this is sufficient. Future versions may need more sophisticated
        text reconstruction.

        Args:
            original_text: Original LLM output text
            original_calls: Original tool calls (before sanitization)
            sanitized_calls: Sanitized tool calls (after validation)

        Returns:
            Text with sanitized tool calls
        """
        import json

        result = original_text

        # Simple approach: Replace each original tool call JSON with sanitized version
        for original, sanitized in zip(original_calls, sanitized_calls):
            # Try to find the original JSON in the text
            # This is a simple heuristic - may not work for all cases
            try:
                # Convert sanitized call back to JSON
                sanitized_json = json.dumps(sanitized, ensure_ascii=False)

                # Try to find and replace the original JSON
                # We'll search for the tool name as a marker
                tool_name = original["tool_name"]
                # Simple replacement: find JSON containing tool_name and replace
                # This is a basic implementation - can be improved
                import re

                pattern = rf'\{{[^}}]*["\']?tool["\']?\s*:\s*["\']?{re.escape(tool_name)}["\']?[^}}]*\}}'
                matches = list(re.finditer(pattern, result, re.IGNORECASE | re.DOTALL))
                if matches:
                    # Replace first match
                    result = (
                        result[: matches[0].start()]
                        + sanitized_json
                        + result[matches[0].end() :]
                    )
            except Exception as e:
                logger.warning(
                    f"[HEPHAESTUS] Failed to rebuild text for tool '{original.get('tool_name')}': {e}"
                )
                # If rebuilding fails, return original text (security: we already validated)
                continue

        return result
