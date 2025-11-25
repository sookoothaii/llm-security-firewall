"""
LLM Security Firewall - Core API
=================================

Unified interface for the 9-layer security framework.

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations

import json
import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml  # type: ignore

from llm_firewall.evidence.pipeline import (
    EvidencePipeline,
    EvidenceRecord,
    PipelineConfig,
)
from llm_firewall.evidence.source_verifier import SourceVerifier
from llm_firewall.evidence.validator import EvidenceValidator
from llm_firewall.monitoring.influence_budget import InfluenceBudgetTracker
from llm_firewall.monitoring.shingle_hasher import ShingleHasher
from llm_firewall.safety.embedding_detector import EmbeddingJailbreakDetector
from llm_firewall.safety.ensemble_validator import EnsembleValidator
from llm_firewall.safety.llm_judge import LLMJudgeDetector
from llm_firewall.safety.perplexity_detector import PerplexityDetector
from llm_firewall.safety.validator import SafetyValidator
from llm_firewall.trust.domain_scorer import DomainTrustScorer

# RC5/RC6/RC7/RC8 Detectors (Integration)
from llm_firewall.detectors.emoji_normalize import (
    normalize_emoji_homoglyphs,
    detect_emoji_homoglyphs,
)
from llm_firewall.detectors.multilingual_keywords import scan_multilingual_attacks
from llm_firewall.detectors.indirect_execution import scan_indirect_and_multimodal

# Core Detectors (Complete Pipeline Integration)
from llm_firewall.detectors.attack_patterns import scan_attack_patterns
from llm_firewall.normalizers.encoding_chain import try_decode_chain
from llm_firewall.detectors.unicode_hardening import strip_bidi_zw
from llm_firewall.detectors.entropy import entropy_signal
from llm_firewall.detectors.dense_alphabet import dense_alphabet_flag

# Policy & Context (Risk Aggregation)
from llm_firewall.preprocess.context import classify_context
from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb

# Early Canonicalization & Fuzzy Detection
from llm_firewall.pipeline.normalize import (
    early_canon,
    transport_light,
    comment_join_in_quotes,
)
from llm_firewall.detectors.keyword_calls import detect_fuzzy_calls

# Context Detection (RC9-FPR1)
from llm_firewall.pipeline.context import (
    detect_documentation_context,
    is_exec_context,
    is_network_context,
    is_exploit_context,
)

logger = logging.getLogger(__name__)


def _artifacts_base() -> Path:
    """Get path to meta-ensemble artifacts directory."""
    return Path(__file__).parent.parent / "artifacts" / "meta"


def _pick_lex_base() -> Path:
    """
    Automatically detect lexicon directory with fallback chain.

    Priority:
    1. lexicons_gpt5/ (GPT-5 Detection Pack)
    2. lexicons/ (default)
    """
    base = Path(__file__).parent / "lexicons_gpt5"
    if (base / "intents.json").exists():
        return base
    base = Path(__file__).parent / "lexicons"
    if not (base / "intents.json").exists():
        raise FileNotFoundError("Lexicons missing; ensure repo is synced")
    return base


LEX_BASE = _pick_lex_base()


def compute_features(
    text: str, detectors: Dict[str, float] | None = None
) -> List[float]:
    """
    Compute feature vector for meta-ensemble.

    Args:
        text: Canonicalized input text
        detectors: Optional detector results (emb_sim, ppl_anom, llm_judge)

    Returns:
        7-dimensional feature vector matching META_FEATURES order
    """
    from llm_firewall.config import SETTINGS
    from llm_firewall.rules.scoring_gpt5 import (
        intent_lex_score,
        load_lexicons,
        pattern_score,
    )

    intents, evasions, harms = load_lexicons(LEX_BASE)
    patterns_path = Path(__file__).parent / "rules" / "patterns_gpt5.json"
    patterns_json = json.loads(patterns_path.read_text())

    p = pattern_score(text, patterns_json, harms["stems"])
    i = intent_lex_score(text, intents, evasions, max_gap=SETTINGS.max_gap)

    emb_sim = float((detectors or {}).get("emb_sim", 0.0))
    ppl_anom = float((detectors or {}).get("ppl_anom", 0.0))
    llm_judge = float((detectors or {}).get("llm_judge", 0.0))
    intent_lex = float(i["lex_score"])
    intent_margin = float(i.get("margin", 0.0))
    pattern_s = float(p["score"])

    # Evasion density from category weights
    ev_cat = p["by_category"].get("obfuscation_encoding", 0.0) + p["by_category"].get(
        "unicode_evasion", 0.0
    )
    evasion_density = 1.0 - math.exp(-ev_cat / 3.0)

    # Order must match META_FEATURES in stacking.py
    feats = [
        emb_sim,
        ppl_anom,
        llm_judge,
        intent_lex,
        intent_margin,
        pattern_s,
        evasion_density,
    ]
    return feats


@dataclass
class FirewallConfig:
    """Firewall configuration."""

    config_dir: str = "config"
    instance_id: str = "default"

    # Evidence pipeline
    tau_trust: float = 0.75
    tau_nli: float = 0.85
    require_corroboration: bool = True
    min_corroborations: int = 2

    # Safety
    safety_threshold: float = 0.8

    # Multi-layer detection
    use_embedding_detector: bool = True
    embedding_threshold: float = 0.75
    use_perplexity_detector: bool = True
    perplexity_threshold: float = 500.0
    use_llm_judge: bool = False  # Optional (higher latency)
    use_ensemble_voting: bool = True  # Ensemble voting to reduce false positives
    min_votes_to_block: int = 2  # Require 2 of 3 layers to block

    # GPT-5 Detection Pack (A/B testable)
    enable_gpt5_detector: bool = False  # Experimental feature
    gpt5_threshold: float = 0.5  # Risk threshold for GPT-5 patterns

    # Monitoring
    drift_threshold: float = 0.15
    influence_z_threshold: float = 2.5
    kl_threshold: float = 0.05

    @classmethod
    def from_yaml(cls, config_path: str) -> FirewallConfig:
        """Load configuration from YAML file."""
        path = Path(config_path)

        if not path.exists():
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return cls()

        with open(path) as f:
            config_data = yaml.safe_load(f)

        return cls(
            config_dir=str(path.parent),
            instance_id=config_data.get("instance_id", "default"),
            tau_trust=config_data.get("evidence", {}).get("tau_trust", 0.75),
            tau_nli=config_data.get("evidence", {}).get("tau_nli", 0.85),
            safety_threshold=config_data.get("safety", {}).get("threshold", 0.8),
            # Multi-layer detection thresholds
            use_embedding_detector=config_data.get("safety", {}).get(
                "use_embedding_detector", True
            ),
            embedding_threshold=config_data.get("safety", {}).get(
                "embedding_threshold", 0.75
            ),
            use_perplexity_detector=config_data.get("safety", {}).get(
                "use_perplexity_detector", True
            ),
            perplexity_threshold=config_data.get("safety", {}).get(
                "perplexity_threshold", 500.0
            ),
            use_llm_judge=config_data.get("safety", {}).get("use_llm_judge", False),
            # GPT-5 Detection Pack
            enable_gpt5_detector=config_data.get("safety", {}).get(
                "enable_gpt5_detector", False
            ),
            gpt5_threshold=config_data.get("safety", {}).get("gpt5_threshold", 0.5),
            # Monitoring
            drift_threshold=config_data.get("canaries", {}).get(
                "drift_threshold", 0.15
            ),
            influence_z_threshold=config_data.get("influence", {}).get(
                "z_score_threshold", 2.5
            ),
            kl_threshold=config_data.get("shingle", {}).get("kl_threshold", 0.05),
        )


@dataclass
class ValidationResult:
    """Result from input validation."""

    is_safe: bool
    reason: str
    risk_score: float = 0.0
    category: Optional[str] = None


@dataclass
class EvidenceDecision:
    """Result from evidence validation."""

    should_promote: bool
    should_quarantine: bool
    should_reject: bool
    confidence: float
    reason: str
    evidence_hash: Optional[str] = None


class SecurityFirewall:
    """
    Unified security firewall for LLM systems.

    Provides:
    - Input validation (HUMAN → LLM)
    - Output validation (LLM → HUMAN)
    - Memory monitoring (drift, influence, duplicates)

    Example:
        config = FirewallConfig.from_yaml("config.yaml")
        firewall = SecurityFirewall(config)

        is_safe, reason = firewall.validate_input(user_query)
        decision = firewall.validate_evidence(content, sources, kb_facts)
    """

    def __init__(self, config: FirewallConfig):
        """Initialize firewall with configuration."""
        self.config = config

        # Initialize components
        pipeline_config = PipelineConfig(
            tau_trust=config.tau_trust,
            tau_nli=config.tau_nli,
            require_corroboration=config.require_corroboration,
            min_corroborations=config.min_corroborations,
        )

        evidence_validator = EvidenceValidator(instance_id=config.instance_id)
        domain_trust_scorer = DomainTrustScorer()
        source_verifier = SourceVerifier()

        self.evidence_pipeline = EvidencePipeline(
            config=pipeline_config,
            evidence_validator=evidence_validator,
            domain_trust_scorer=domain_trust_scorer,
            source_verifier=source_verifier,
        )

        self.safety_validator = SafetyValidator(
            config_dir=config.config_dir,
            enable_gpt5=config.enable_gpt5_detector,
            gpt5_threshold=config.gpt5_threshold,
        )

        # Multi-layer detection
        self.embedding_detector = None
        if config.use_embedding_detector:
            try:
                self.embedding_detector = EmbeddingJailbreakDetector(
                    threshold=config.embedding_threshold
                )
                logger.info("Embedding detector enabled")
            except Exception as e:
                logger.warning(f"Embedding detector failed to initialize: {e}")

        self.perplexity_detector = None
        if config.use_perplexity_detector:
            try:
                self.perplexity_detector = PerplexityDetector(
                    threshold=config.perplexity_threshold
                )
                logger.info("Perplexity detector enabled")
            except Exception as e:
                logger.warning(f"Perplexity detector failed to initialize: {e}")

        self.llm_judge = None
        if config.use_llm_judge:
            try:
                self.llm_judge = LLMJudgeDetector()
                logger.info("LLM judge enabled")
            except Exception as e:
                logger.warning(f"LLM judge failed to initialize: {e}")

        # Ensemble validator for multi-layer voting
        self.ensemble_validator = None
        if config.use_ensemble_voting:
            self.ensemble_validator = EnsembleValidator(
                min_votes_to_block=config.min_votes_to_block
            )
            logger.info(
                f"Ensemble voting enabled (min_votes: {config.min_votes_to_block})"
            )

        # Canaries require NLI model - initialize later when needed
        self.canary_monitor = None
        self.shingle_hasher = ShingleHasher()
        self.influence_tracker = InfluenceBudgetTracker(
            z_score_threshold=config.influence_z_threshold
        )

        logger.info(f"SecurityFirewall initialized (instance: {config.instance_id})")

    def validate_input(self, text: str) -> Tuple[bool, str]:
        """
        Validate input text for safety (Multi-Layer Defense with Ensemble Voting).

        Args:
            text: Input text to validate

        Returns:
            (is_safe, reason) tuple
        """
        # Layer 0: Complete Detector Pipeline (RC + Core Detectors)
        all_hits = []
        contrib = {}

        # Step 0: Early Canonicalization (NFKC + ZW strip) - before ALL detectors
        raw_text = text
        text = early_canon(text)

        # Step 0.5: Transport Light (URL %XX, QP =HH) - only in quotes, FPR-safe
        text = transport_light(text, contrib)
        text = comment_join_in_quotes(text)

        # Step 0.6: Context Detection (RC9-FPR1/FPR2 - reduce false positives in docs)
        context_meta = detect_documentation_context(text)
        context = context_meta["ctx"]  # "documentation" or "generic"
        is_exec = is_exec_context(text, context)  # Context-aware exec detection
        is_network = is_network_context(text)
        is_exploit = is_exploit_context(
            text, context
        )  # Context-aware exploit detection

        # Pre-normalization: Unicode (Bidi, ZW, Fullwidth, Greek Homoglyphs)
        # Note: early_canon already handles FULLWIDTH→ASCII, this catches remaining patterns
        text_prenorm, prenorm_flags = strip_bidi_zw(text)
        if prenorm_flags.get("bidi_seen"):
            all_hits.append("bidi_controls")
        if prenorm_flags.get("zw_seen"):
            all_hits.append("zero_width_chars")
        if prenorm_flags.get("fullwidth_seen"):
            all_hits.append("fullwidth_forms")
        if prenorm_flags.get("mixed_scripts"):
            all_hits.append("mixed_scripts")
        if prenorm_flags.get("homoglyph_spoof_ge_1"):
            all_hits.append("homoglyph_spoof_ge_1")
        if prenorm_flags.get("homoglyph_spoof_ge_2"):
            all_hits.append("homoglyph_spoof_ge_2")

        # Use normalized text for all subsequent detectors
        text = text_prenorm

        # RC5: Emoji Homoglyphs (Pre-processing + Detection)
        normalized_text, emoji_meta = normalize_emoji_homoglyphs(text)
        emoji_hits = detect_emoji_homoglyphs(text)
        all_hits.extend(emoji_hits)
        if emoji_meta["changed"]:
            text = normalized_text  # Use normalized text for subsequent layers

        # RC6: Multilingual + RC8: Semantic Synonyms + Fuzzy Calls
        ml_hits = scan_multilingual_attacks(text)
        all_hits.extend(ml_hits)

        # Fuzzy Function Call Detection (gaps/fullwidth-resistant)
        fuzzy_hits = detect_fuzzy_calls(text)
        all_hits.extend(fuzzy_hits)

        # RC7: Indirect Execution + MultiModal
        indirect_hits = scan_indirect_and_multimodal(text)
        all_hits.extend(indirect_hits)

        # Core: Attack Patterns (jAvAscript, XSS, SQL, etc)
        attack_hits = scan_attack_patterns(text)
        all_hits.extend(attack_hits)

        # Core: Encoding Chain Detection
        decoded, stages, _, buf = try_decode_chain(text)
        if stages >= 1:
            all_hits.append(f"chain_decoded_{stages}_stages")
            all_hits.append("base64_secret")

        # Core: Statistical Signals (already using normalized text)
        if entropy_signal(text, threshold=4.0):
            all_hits.append("high_entropy")
        if dense_alphabet_flag(text):
            all_hits.append("dense_alphabet")

        # RC9-FPR2/FPR3/FPR4: Surgical signal dampening (invasive, context-aware)
        # Dampen ONLY in documentation context WITHOUT exec/exploit markers
        if context == "documentation" and not (is_exec or is_exploit):
            # Whitelist: Signals that stay STRONG even in docs (actual exploits)
            CRITICAL_IN_DOCS = {
                "chain_decoded_3_stages",  # Deep encoding chains
                "rce_log4j_jndi",  # Critical vulns
                "sql_injection",  # Direct injection patterns
            }

            # Carefully check patterns that might be mentions vs actual code
            dampened_hits = []

            for hit in all_hits:
                # Critical patterns - always keep
                if hit in CRITICAL_IN_DOCS:
                    dampened_hits.append(hit)

                # xss_script_tag - only if in actual executable position (not just text mention)
                elif hit == "xss_script_tag":
                    # In pure doc, <script> is often just mentioned in text
                    # Keep only if followed by actual JS code indicators
                    if re.search(r"(?i)<script[^>]*>\s*\w+\s*\(", text):
                        dampened_hits.append(hit)
                    # else: dampened (just mention)

                # indirect_* - only if NOT in teaching context
                elif hit.startswith("indirect_"):
                    # Teaching markers
                    if not re.search(
                        r"(?i)\b(example|tutorial|demo|reference|illustration)\b", text
                    ):
                        dampened_hits.append(hit)
                    # else: dampened (educational example)

                # xss_event_handler - only in executable position
                elif hit == "xss_event_handler":
                    if re.search(r"(?i)<\w+[^>]*\bon\w+\s*=", text):
                        dampened_hits.append(hit)
                    # else: dampened

                # xss_dangerous_scheme - only if in href/src attribute
                elif hit == "xss_dangerous_scheme":
                    if re.search(
                        r'(?i)\b(?:href|src)\s*=\s*["\']?\s*javascript\s*:', text
                    ):
                        dampened_hits.append(hit)
                    # else: dampened

                # emoji_homoglyph - only if actual obfuscated call
                elif hit.startswith("emoji_") or hit.startswith("fuzzy_call_emoji"):
                    if any(h.startswith("fuzzy_call") for h in all_hits):
                        dampened_hits.append(hit)
                    # else: dampened

                # chain_decoded_1_stages in pure doc - likely base64 example
                # Only keep if >=2 stages OR secretlike
                elif hit == "chain_decoded_1_stages":
                    if (
                        "chain_decoded_2_stages" in all_hits
                        or "chain_decoded_3_stages" in all_hits
                    ):
                        dampened_hits.append(hit)
                    # else: dampened (1-stage is often just base64 example)

                # base64_secret in pure doc - often example data
                elif hit == "base64_secret":
                    # Only keep if multi-stage or in exec context proximity
                    if (
                        "chain_decoded_2_stages" in all_hits
                        or "chain_decoded_3_stages" in all_hits
                    ):
                        dampened_hits.append(hit)
                    # else: dampened

                # ALL other signals - dampen in pure doc context
                # (multilingual, encoding_near, path, ssrf, homoglyph, entropy, etc)
                else:
                    pass  # Dampened

            # Replace with dampened hits
            all_hits = dampened_hits

        # Risk Aggregation & Decision
        if all_hits:
            ctx = classify_context(text)
            action, risk, _ = decide_action_otb(all_hits, ctx, text=text)

            if action in ("WARN", "BLOCK"):
                # Return immediately - don't call ensemble (avoid unicode surrogate issues)
                return (
                    False,
                    f"Layer 0 (Detectors): {action} (risk={risk:.2f}) - {', '.join(all_hits[:3])}{'...' if len(all_hits) > 3 else ''}",
                )

        # Only call ensemble if Layer 0 passed (safer unicode handling)
        if self.ensemble_validator:
            # RC9-FPR1/FPR3: Skip ensemble for documentation + short doc-like snippets
            # (pattern blacklists too aggressive for benign metadata)
            from llm_firewall.pipeline.context import detect_short_snippet_like_docs

            is_doc_like = (
                context == "documentation"
            ) or detect_short_snippet_like_docs(raw_text)

            if is_doc_like and not (is_exec or is_exploit):
                return True, "Documentation/metadata context - passed through firewall"

            # Sanitize text for ensemble layers (avoid surrogate issues in transformers)
            text_safe = text.encode("utf-8", errors="replace").decode("utf-8")
            return self.ensemble_validator.validate(
                text_safe,
                self.safety_validator,
                self.embedding_detector,
                self.perplexity_detector,
            )

        # Fallback: Sequential layer checking (legacy mode)
        # Layer 1: Pattern-based safety check
        safety_decision = self.safety_validator.validate(text)

        if safety_decision.action == "BLOCK":
            return (
                False,
                f"Layer 1 (Pattern): {safety_decision.reason} (category: {safety_decision.category})",
            )

        # Layer 2: Embedding-based detection
        if self.embedding_detector and self.embedding_detector.available:
            embedding_result = self.embedding_detector.detect(text)
            if embedding_result.is_jailbreak:
                return (
                    False,
                    f"Layer 2 (Embedding): Semantic jailbreak detected (similarity: {embedding_result.max_similarity:.3f})",
                )

        # Layer 3: Perplexity-based detection
        if self.perplexity_detector and self.perplexity_detector.available:
            perplexity_result = self.perplexity_detector.detect(text)
            if perplexity_result.is_adversarial:
                return (
                    False,
                    f"Layer 3 (Perplexity): Adversarial content detected (perplexity: {perplexity_result.perplexity:.1f})",
                )

        # Layer 4: LLM-as-Judge (optional)
        if self.llm_judge and self.llm_judge.available:
            judge_result = self.llm_judge.detect(text)
            if judge_result.is_jailbreak:
                return False, f"Layer 4 (LLM Judge): {judge_result.reasoning[:100]}"
        elif safety_decision.action == "GATE":
            return False, f"Gated: {safety_decision.reason}"

        # Safe
        return True, "Input passed safety validation"

    def validate_evidence(
        self, content: str, sources: List[Dict], kb_facts: List[str]
    ) -> EvidenceDecision:
        """
        Validate evidence through full pipeline.

        Args:
            content: Claim to validate
            sources: List of source dicts with 'name', 'url', 'doi' keys
            kb_facts: List of KB facts for corroboration

        Returns:
            EvidenceDecision with promote/quarantine/reject decision
        """
        # Create evidence record
        source_url = sources[0].get("url") if sources else None
        source_domain = sources[0].get("domain") if sources else None
        doi = sources[0].get("doi") if sources else None

        record = EvidenceRecord(
            content=content,
            source_url=source_url,
            source_domain=source_domain,
            doi=doi,
            kb_corroborations=len(kb_facts),
        )

        # Run evidence pipeline
        result = self.evidence_pipeline.process(record=record, kb_sentences=kb_facts)

        # Map to decision
        decision = result.get("decision", "REJECT")

        if decision == "PROMOTE":
            should_promote = True
            should_quarantine = False
            should_reject = False
        elif decision == "QUARANTINE":
            should_promote = False
            should_quarantine = True
            should_reject = False
        else:  # REJECT
            should_promote = False
            should_quarantine = False
            should_reject = True

        return EvidenceDecision(
            should_promote=should_promote,
            should_quarantine=should_quarantine,
            should_reject=should_reject,
            confidence=result.get("confidence", 0.0),
            reason=result.get("reason", "Unknown"),
            evidence_hash=result.get("evidence_hash"),
        )

    def check_drift(self, sample_size: int = 10) -> Tuple[bool, Dict]:
        """
        Check for memory drift using canaries.

        Args:
            sample_size: Number of canaries to test

        Returns:
            (has_drift, canary_scores) tuple
        """
        # Simplified implementation - full version requires NLI model
        if self.canary_monitor is None:
            logger.warning("Canary monitor not initialized, returning no drift")
            return False, {}

        canaries = self.canary_monitor.get_random_sample(sample_size)
        scores = {}

        failures = 0
        for canary in canaries:
            # Simulate verification (in production, check against actual KB)
            score = 1.0 if canary.expected_truth else 0.0
            scores[canary.claim] = score

            if score < 0.5:
                failures += 1

        failure_rate = failures / len(canaries) if canaries else 0.0
        has_drift = failure_rate > self.config.drift_threshold

        return has_drift, scores

    def get_alerts(self, domain: str = "SCIENCE") -> List[str]:
        """
        Get active alerts for domain.

        Args:
            domain: Domain to filter alerts

        Returns:
            List of alert messages
        """
        # Placeholder - in production, query from monitoring system
        alerts = []

        # Check influence budget
        if hasattr(self.influence_tracker, "current_z_score"):
            z = self.influence_tracker.current_z_score
            if abs(z) > self.config.influence_z_threshold:
                alerts.append(f"Influence spike detected: Z={z:.2f}")

        return alerts


# Export main classes
__all__ = [
    "SecurityFirewall",
    "FirewallConfig",
    "ValidationResult",
    "EvidenceDecision",
]
