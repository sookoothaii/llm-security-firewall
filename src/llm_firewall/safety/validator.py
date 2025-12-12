"""
Safety Validator für Evidence Pipeline
======================================

GPT-5 inspired Safety-Layer basierend auf safety_blacklist.yaml und
threat_detection_config.yaml.

Prüft Evidence auf:
- High-Risk Dual-Use Kategorien (16 Blacklist-Kategorien)
- Intent Patterns (how-to, bypass, evade)
- Capability Indicators (technische Details)
- Targeting Signals (spezifische Ziele)
- Evasion Signals (Jailbreak-Versuche)

Persona-frei, rein epistemisch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml  # type: ignore

from llm_firewall.rules.patterns import RobustPatternMatcher
from llm_firewall.safety.gpt5_detector import GPT5Detector
from llm_firewall.safety.text_preproc import evasion_signals
from llm_firewall.text.normalize import canonicalize, is_evasion_attempt
from llm_firewall.persuasion.ac_trie import AhoCorasick

# Safety-net: Canonicalizer is applied at entry points to prevent silent regressions
# if any call-site forgets to canonicalize. Idempotent, so safe to call multiple times.


@dataclass(frozen=True)
class SafetySignals:
    """Extrahierte Safety-Signale."""

    intent_score: float  # [0,1] - How-to Intent
    capability_score: float  # [0,1] - Technische Details
    targeting_score: float  # [0,1] - Spezifische Ziele
    evasion_score: float  # [0,1] - Jailbreak-Versuche
    category_match: Optional[str]  # Blacklist-Kategorie
    confidence: float  # [0,1] - Confidence der Klassifikation


@dataclass(frozen=True)
class SafetyDecision:
    """Safety-Entscheidung."""

    action: str  # BLOCK, GATE, SAFE
    risk_score: float  # [0,1]
    category: Optional[str]
    reason: str
    signals: SafetySignals
    # KI Lab: Granular logging fields
    matched_keyword: Optional[str] = None  # Specific pattern that matched
    match_confidence: Optional[float] = None  # Confidence score (0.4, 0.6, 0.9)


class SafetyValidator:
    """
    Safety Validator für Evidence.

    Basiert auf GPT-5 Policy (safety_blacklist.yaml, threat_detection_config.yaml).
    """

    def __init__(
        self,
        config_dir: str = "config",
        enable_gpt5: bool = False,
        gpt5_threshold: float = 0.5,
    ):
        """
        Args:
            config_dir: Verzeichnis mit YAML Configs
            enable_gpt5: Enable GPT-5 Detection Pack (A/B testable)
            gpt5_threshold: Risk threshold for GPT-5 detector
        """
        self.config_dir = Path(config_dir)
        self.blacklist = self._load_blacklist()
        self.threat_config = self._load_threat_config()
        self.weights = self.threat_config.get(
            "weights",
            {"wI": 0.35, "wC": 0.20, "wT": 0.15, "wE": 0.15, "wD": 0.10, "wU": 0.05},
        )
        self.thresholds = self.threat_config.get("policy", {}).get(
            "thresholds", {"block": 0.60, "gate": 0.40}
        )
        # HOTFIX: Robust pattern matcher with canonicalization
        self.pattern_matcher = RobustPatternMatcher()
        # GPT-5 Detection Pack (A/B testable layer)
        self.gpt5_detector = GPT5Detector(enabled=enable_gpt5, threshold=gpt5_threshold)
        
        # Phase 1: PersuasionDetector for Misinformation Detection
        self.persuasion_detector = None
        try:
            from llm_firewall.persuasion.detector import PersuasionDetector
            persuasion_lexicon_dir = Path(__file__).parent.parent / "lexicons" / "persuasion"
            if persuasion_lexicon_dir.exists():
                self.persuasion_detector = PersuasionDetector(persuasion_lexicon_dir)
                import logging
                logger = logging.getLogger(__name__)
                logger.info(f"PersuasionDetector initialized from {persuasion_lexicon_dir}")
            else:
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"PersuasionDetector lexicon directory not found: {persuasion_lexicon_dir}")
        except ImportError as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"PersuasionDetector not available: {e}")
        
        # KI Lab Integration: Aho-Corasick for efficient multi-keyword matching
        self.category_trie = None
        self._last_match_details = None  # For granular logging
        self._build_category_trie()

    def _load_blacklist(self) -> Dict:
        """Lade safety_blacklist.yaml."""
        blacklist_path = self.config_dir / "safety_blacklist.yaml"

        if not blacklist_path.exists():
            return {"categories": []}

        with open(blacklist_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def _load_threat_config(self) -> Dict:
        """Lade threat_detection_config.yaml."""
        import logging
        logger = logging.getLogger(__name__)
        
        config_path = self.config_dir / "threat_detection_config.yaml"

        if not config_path.exists():
            logger.error(f"SafetyValidator: threat_detection_config.yaml not found at {config_path}")
            return {}

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
                logger.debug(f"SafetyValidator: Loaded threat_config from {config_path}")
                # Check if signals and category_lexicon exist
                if config and "signals" in config:
                    if "category_lexicon" in config["signals"]:
                        logger.debug(f"SafetyValidator: category_lexicon found with {len(config['signals']['category_lexicon'])} categories")
                    else:
                        logger.warning(f"SafetyValidator: category_lexicon not found in signals. Available keys: {list(config.get('signals', {}).keys())}")
                else:
                    logger.warning(f"SafetyValidator: signals not found in threat_config. Available keys: {list(config.keys()) if config else []}")
                return config
        except Exception as e:
            logger.error(f"SafetyValidator: Failed to load threat_config from {config_path}: {e}", exc_info=True)
            return {}
    
    def _build_category_trie(self):
        """Build Aho-Corasick trie for category keyword matching."""
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            category_lexicon = self.threat_config.get("signals", {}).get(
                "category_lexicon", {}
            )
            
            if not category_lexicon:
                logger.warning("SafetyValidator: No category_lexicon found in threat_config - fallback to substring matching will be used")
                self.category_trie = None
                return
            
            logger.debug(f"SafetyValidator: Building Aho-Corasick trie from category_lexicon with {len(category_lexicon)} categories")
            
            # Build patterns: (keyword, category) tuples
            patterns = []
            category_counts = {}
            for category, keywords in category_lexicon.items():
                # Skip exclusion lists
                if category.endswith("_exclusions"):
                    continue
                
                # Add all keywords for this category
                count = 0
                for keyword in keywords:
                    if keyword and keyword.strip():
                        # Store lowercase for case-insensitive matching
                        patterns.append((keyword.lower().strip(), category))
                        count += 1
                if count > 0:
                    category_counts[category] = count
            
            if patterns:
                try:
                    self.category_trie = AhoCorasick()
                    self.category_trie.build(patterns)
                    logger.info(f"SafetyValidator: Aho-Corasick trie built successfully with {len(patterns)} patterns across {len(category_counts)} categories")
                    logger.debug(f"SafetyValidator: Pattern counts per category: {category_counts}")
                except Exception as e:
                    logger.error(
                        f"SafetyValidator: Aho-Corasick Trie konnte nicht gebaut werden! "
                        f"Patterns: {len(patterns)}, Categories: {len(category_counts)}. "
                        f"Error: {e}. Falling back to substring matching.",
                        exc_info=True
                    )
                    self.category_trie = None
            else:
                logger.warning("SafetyValidator: No patterns found to build Aho-Corasick trie - fallback to substring matching will be used")
                self.category_trie = None
                
        except Exception as e:
            # Fallback to substring matching if Aho-Corasick fails
            self.category_trie = None
            logger.warning(f"Failed to build Aho-Corasick trie: {e}. Falling back to substring matching.", exc_info=True)
    
    def _right_context(self, text: str, pos: int, window: int = 20) -> str:
        """Extract right context window after position."""
        end = min(len(text), pos + window)
        return text[pos:end]
    
    def _is_false_positive(self, match_start: int, match_end: int, category: str, content: str) -> bool:
        """
        Check if match is a false positive using context-aware exclusions.
        
        Args:
            match_start: Start position of match in content
            match_end: End position of match in content
            category: Detected category
            content: Full content text
            
        Returns:
            True if exclusion found in context window, False otherwise
        """
        import logging
        logger = logging.getLogger(__name__)
        
        category_lexicon = self.threat_config.get("signals", {}).get(
            "category_lexicon", {}
        )
        
        exclusion_key = f"{category}_exclusions"
        exclusions = category_lexicon.get(exclusion_key, [])
        
        if not exclusions:
            logger.debug(f"SafetyValidator._is_false_positive: No exclusions for category '{category}'")
            return False
        
        # Get context window around match (20 chars before and after)
        context_window_size = 20
        context_start = max(0, match_start - context_window_size)
        context_end = min(len(content), match_end + context_window_size)
        context_snippet = content[context_start:context_end].lower()
        
        logger.debug(
            f"SafetyValidator._is_false_positive: Checking exclusions for category '{category}' "
            f"at position [{match_start}:{match_end}], context window: '{content[context_start:match_start]}<MATCH>{content[match_end:context_end]}'"
        )
        
        # Check if any exclusion appears in context window
        for exclusion in exclusions:
            exclusion_lower = exclusion.lower()
            if exclusion_lower in context_snippet:
                logger.info(
                    f"SafetyValidator._is_false_positive: Exclusion '{exclusion}' found in context window - "
                    f"match is FALSE POSITIVE"
                )
                return True  # False positive detected
        
        logger.debug(f"SafetyValidator._is_false_positive: No exclusions found in context window - match is VALID")
        return False

    def extract_signals(self, content: str) -> SafetySignals:
        """
        Extrahiere Safety-Signale aus Content.

        Phase 1 Enhancement: Expects pre-canonicalized content from validate().
        This avoids double normalization while ensuring obfuscation is handled.

        Args:
            content: Zu prüfender Content (should be pre-canonicalized)

        Returns:
            Safety-Signale
        """
        # Content should already be canonicalized by validate()
        # No need to normalize again (idempotent but redundant)
        content_lower = content.lower()

        # Intent Patterns
        intent_patterns = self.threat_config.get("signals", {}).get(
            "intent_patterns", []
        )
        intent_matches = sum(
            1
            for pattern in intent_patterns
            if self._pattern_match(pattern, content_lower)
        )
        intent_score = min(1.0, intent_matches / max(len(intent_patterns), 1) * 2.0)

        # Capability Indicators
        capability_patterns = self.threat_config.get("signals", {}).get(
            "capability_indicators", []
        )
        capability_matches = sum(
            1 for pattern in capability_patterns if re.search(pattern, content_lower)
        )
        capability_score = min(
            1.0, capability_matches / max(len(capability_patterns), 1) * 3.0
        )

        # Targeting Signals
        targeting_patterns = self.threat_config.get("signals", {}).get(
            "targeting_signals", []
        )
        targeting_matches = sum(
            1 for pattern in targeting_patterns if re.search(pattern, content_lower)
        )
        targeting_score = min(
            1.0, targeting_matches / max(len(targeting_patterns), 1) * 2.0
        )

        # Evasion Signals (ENHANCED with robust detection)
        evasion_patterns = self.threat_config.get("signals", {}).get(
            "evasion_signals", []
        )
        evasion_matches = sum(
            1 for pattern in evasion_patterns if re.search(pattern, content_lower)
        )
        pattern_evasion_score = min(
            1.0, evasion_matches / max(len(evasion_patterns), 1) * 2.0
        )

        # Augment with robust evasion detection (ZWJ, Base64, Homoglyphs)
        evas = evasion_signals(content)
        robust_evasion_score = min(1.0, 0.2 * evas["evasion_count"])

        # Take maximum of pattern-based and robust detection
        evasion_score = max(pattern_evasion_score, robust_evasion_score)

        # Category Match (KI Lab: Returns tuple with confidence)
        category_result = self._match_category(content_lower)
        if category_result:
            category_match, matched_keyword, confidence = category_result
            # Store match details for granular logging
            self._last_match_details = {
                "category": category_match,
                "matched_keyword": matched_keyword,
                "confidence": confidence
            }
        else:
            category_match = None
            self._last_match_details = None

        # Phase 1: Add persuasion rhetoric detection for misinformation
        rhetoric_score = 0.0
        if category_match == "misinformation":
            rhetoric_score = self._detect_misinformation_rhetoric(content)
            # Boost intent score if rhetoric detected
            if rhetoric_score > 0.3:
                intent_score = max(intent_score, rhetoric_score)

        # Confidence (simuliert - in Realität von Classifier)
        confidence = 0.8 if (intent_score > 0 or capability_score > 0) else 0.5

        return SafetySignals(
            intent_score=intent_score,
            capability_score=capability_score,
            targeting_score=targeting_score,
            evasion_score=evasion_score,
            category_match=category_match,
            confidence=confidence,
        )

    def _pattern_match(self, pattern: str, text: str) -> bool:
        """Simple pattern matching (Wildcard)."""
        # Konvertiere "how to *" zu Regex
        regex_pattern = pattern.replace("*", ".*")
        return bool(re.search(regex_pattern, text))

    def _match_category(self, content: str) -> Optional[Tuple[str, str, float]]:
        """
        Matche Content gegen Blacklist-Kategorien mit Exclusions.
        
        KI Lab Integration: Uses Aho-Corasick for efficient matching.
        
        Returns:
            Tuple of (category, matched_keyword, confidence_score) or None
            confidence_score: 0.9 (high), 0.6 (medium), 0.4 (low)
        """
        import logging
        logger = logging.getLogger(__name__)
        
        category_lexicon = self.threat_config.get("signals", {}).get(
            "category_lexicon", {}
        )
        
        if not category_lexicon:
            logger.debug("SafetyValidator._match_category: No category_lexicon available")
            return None
        
        # Case-insensitive matching
        content_lower = content.lower()
        
        # KI Lab Integration: Use Aho-Corasick if available
        if self.category_trie is not None:
            logger.debug(f"SafetyValidator._match_category: Using Aho-Corasick trie for content length {len(content_lower)}")
            # Use Aho-Corasick for efficient multi-pattern matching
            matches = list(self.category_trie.find_iter(content_lower))
            logger.debug(f"SafetyValidator._match_category: Aho-Corasick found {len(matches)} raw matches")
            
            # Process matches: check exclusions and calculate confidence
            for match_start, match_end, matched_keyword, category in matches:
                logger.debug(f"SafetyValidator._match_category: Checking match '{matched_keyword}' for category '{category}' at position [{match_start}:{match_end}]")
                
                # Context-aware exclusion check
                if self._is_false_positive(match_start, match_end, category, content_lower):
                    logger.debug(f"SafetyValidator._match_category: Match '{matched_keyword}' excluded (false positive)")
                    continue  # Skip this match (false positive)
                
                # Calculate confidence score based on match characteristics
                confidence = self._calculate_match_confidence(
                    matched_keyword, category, content_lower, match_start, match_end
                )
                
                logger.info(f"SafetyValidator._match_category: Valid match found - category='{category}', keyword='{matched_keyword}', confidence={confidence:.2f}")
                
                # Return first valid match (can be extended to scoring system later)
                return (category, matched_keyword, confidence)
            
            logger.debug(f"SafetyValidator._match_category: No valid matches after exclusion checks")
        else:
            logger.warning("SafetyValidator._match_category: Aho-Corasick trie not available, using fallback substring matching")
        
        # Fallback to substring matching if Aho-Corasick not available
        logger.debug(f"SafetyValidator._match_category: Using fallback substring matching. Categories available: {list(category_lexicon.keys())}")
        
        for category, keywords in category_lexicon.items():
            # Skip exclusion lists
            if category.endswith("_exclusions"):
                continue

            logger.debug(f"SafetyValidator._match_category: Checking category '{category}' with {len(keywords)} keywords")
            
            # Check if any keyword matches (case-insensitive)
            for keyword in keywords:
                keyword_lower = keyword.lower()
                if keyword_lower in content_lower:
                    logger.debug(f"SafetyValidator._match_category: Keyword '{keyword}' found in content")
                    # Context-aware exclusion check (approximate position)
                    match_pos = content_lower.find(keyword_lower)
                    if match_pos >= 0:
                        if self._is_false_positive(match_pos, match_pos + len(keyword_lower), category, content_lower):
                            logger.debug(f"SafetyValidator._match_category: Match '{keyword}' excluded (false positive)")
                            continue  # Skip this match
                        
                        # Calculate confidence
                        confidence = self._calculate_match_confidence(
                            keyword, category, content_lower, match_pos, match_pos + len(keyword_lower)
                        )
                        
                        logger.info(f"SafetyValidator._match_category: Fallback match found - category='{category}', keyword='{keyword}', confidence={confidence:.2f}")
                        return (category, keyword, confidence)
                    else:
                        logger.warning(f"SafetyValidator._match_category: Keyword '{keyword}' found with 'in' but not with 'find' - this should not happen")

        logger.debug(f"SafetyValidator._match_category: No matches found in content (length={len(content_lower)})")
        return None
    
    def _detect_misinformation_rhetoric(self, content: str) -> float:
        """
        Detect persuasive rhetoric patterns for misinformation.
        
        Phase 1 Implementation: Uses PersuasionDetector to identify
        persuasive language patterns that are commonly used in misinformation.
        
        Args:
            content: Input text (should be pre-normalized)
            
        Returns:
            Rhetoric score [0, 1] - higher indicates more persuasive rhetoric
        """
        if self.persuasion_detector is None:
            return 0.0
        
        # Score text for persuasion patterns
        total_score, signals = self.persuasion_detector.score_text(content)
        
        # Misinformation-specific signals:
        # - Authority abuse ("experts say", "doctors confirm")
        # - False urgency ("act now", "limited time")
        # - Trust undermining ("they don't want you to know")
        # - Loaded language ("cover-up", "conspiracy")
        # - Roleplay/Ignore Rules (jailbreak patterns)
        
        misinformation_categories = ['authority', 'scarcity', 'unity', 'roleplay_ignore_rules']
        
        # Filter signals for misinformation-relevant categories
        misinformation_signals = [
            s for s in signals 
            if s.category in misinformation_categories
        ]
        
        if misinformation_signals:
            # Use maximum signal score, scaled to [0, 1]
            max_signal = max(misinformation_signals, key=lambda x: x.score)
            # Scale: typical persuasion scores are 0-10, normalize to [0, 1]
            # Use a scaling factor of 0.3 as suggested in the plan
            rhetoric_score = min(1.0, max_signal.score * 0.3)
            return rhetoric_score
        
        return 0.0

    def _calculate_match_confidence(
        self, matched_keyword: str, category: str, content: str, match_start: int, match_end: int
    ) -> float:
        """
        Calculate confidence score for a match (KI Lab: Nuanced Risk Scoring).
        
        Returns:
            - 0.9: High-confidence direct match (e.g., "pirated song", "fake news", "generate the lyrics")
            - 0.6: Medium-confidence partial match
            - 0.4: Low-confidence contextual match
        """
        import logging
        logger = logging.getLogger(__name__)
        
        keyword_lower = matched_keyword.lower()
        
        # High-confidence indicators (INCLUDING "generate the lyrics" and "generate lyrics")
        high_confidence_keywords = {
            "copyright_violation": [
                "pirated", "torrent", "crack software", "bypass drm", "illegal download",
                "generate the lyrics", "generate lyrics",  # UPGRADED: Now high confidence
                "reproduce the lyrics", "reproduce lyrics",  # UPGRADED: Now high confidence
                "copy the lyrics", "copy lyrics",  # UPGRADED: Now high confidence
                "duplicate the lyrics", "duplicate lyrics",
                "generate the text", "reproduce the text", "copy the text",
                "download the full pdf", "full pdf download",  # UPGRADED: PDF downloads are high confidence
                "generate a long passage", "generate long passage",  # UPGRADED: Book passages are high confidence
                "reproduce a long passage", "reproduce long passage",
                "copy a long passage", "copy long passage"
            ],
            "misinformation": ["fake news", "false information", "spread disinformation", "hoax"]
        }
        
        # Check for high-confidence keywords
        if category in high_confidence_keywords:
            for hc_kw in high_confidence_keywords[category]:
                if hc_kw in keyword_lower or hc_kw in content:
                    logger.debug(f"SafetyValidator._calculate_match_confidence: High confidence (0.9) for '{matched_keyword}' (matched high-confidence keyword: '{hc_kw}')")
                    return 0.9  # High confidence
        
        # Medium-confidence: specific patterns with context
        medium_confidence_patterns = {
            "copyright_violation": ["download copyrighted"],  # Removed "generate the lyrics" - now high confidence
            "misinformation": ["write a persuasive article", "write a defamatory article"]
        }
        
        if category in medium_confidence_patterns:
            for mc_pat in medium_confidence_patterns[category]:
                if mc_pat in keyword_lower or mc_pat in content:
                    logger.debug(f"SafetyValidator._calculate_match_confidence: Medium confidence (0.6) for '{matched_keyword}'")
                    return 0.6  # Medium confidence
        
        # Low-confidence: generic or partial matches
        logger.debug(f"SafetyValidator._calculate_match_confidence: Low confidence (0.4) for '{matched_keyword}'")
        return 0.4  # Low confidence

    def compute_risk_score(self, signals: SafetySignals) -> float:
        """
        Berechne Risk Score with component floors.

        R = max(R_linear, f_I*I, f_C*C, f_T*T, f_E*E)

        Floors ensure high single-signal cases escalate properly.
        Persona/epistemic separation: purely epistemic features.
        """
        # Domain Flag
        domain_flag = 1.0 if signals.category_match else 0.0

        # Uncertainty
        uncertainty = 1.0 - signals.confidence

        # Linear risk score
        R_linear = (
            self.weights["wI"] * signals.intent_score
            + self.weights["wC"] * signals.capability_score
            + self.weights["wT"] * signals.targeting_score
            + self.weights["wE"] * signals.evasion_score
            + self.weights["wD"] * domain_flag
            + self.weights["wU"] * uncertainty
        )

        # Component floors (OR-logic for escalation)
        floors = self.threat_config.get(
            "floors",
            {
                "I": 0.50,  # High intent alone gates
                "C": 0.33,  # High capability alone exceeds 0.3 risk
                "T": 0.25,
                "E": 0.25,
            },
        )

        R_floor = max(
            floors.get("I", 0.0) * signals.intent_score,
            floors.get("C", 0.0) * signals.capability_score,
            floors.get("T", 0.0) * signals.targeting_score,
            floors.get("E", 0.0) * signals.evasion_score,
        )

        # Take maximum of linear and floor-based risk
        risk_score = max(R_linear, R_floor)

        return min(1.0, max(0.0, risk_score))

    def validate(self, content: str) -> SafetyDecision:
        """
        Validiere Content gegen Safety-Policy.

        HOTFIX: Jetzt mit Kanonisierung + Regex-Patterns!

        Args:
            content: Zu prüfender Content

        Returns:
            Safety-Entscheidung
        """
        # Safety-net: Always canonicalize at entry (idempotent)
        canonical = canonicalize(content)

        # HOTFIX PHASE 2: Fast-path Regex check (high precision)
        pattern_match = self.pattern_matcher.match_any(canonical)
        if pattern_match.matched:
            # Immediate BLOCK on regex match
            signals = SafetySignals(
                intent_score=1.0,
                capability_score=0.5,
                targeting_score=0.5,
                evasion_score=0.9,
                category_match="jailbreak",
                confidence=0.95,
            )
            return SafetyDecision(
                action="BLOCK",
                risk_score=1.0,
                category="jailbreak",
                reason=f"HOTFIX: Regex matched {pattern_match.pattern_name}: {pattern_match.matched_text[:50]}",
                signals=signals,
            )

        # HOTFIX PHASE 3: Check for evasion techniques
        if is_evasion_attempt(content, canonical):
            signals = SafetySignals(
                intent_score=0.5,
                capability_score=0.0,
                targeting_score=0.0,
                evasion_score=1.0,
                category_match="evasion",
                confidence=0.9,
            )
            return SafetyDecision(
                action="BLOCK",
                risk_score=0.9,
                category="evasion",
                reason="HOTFIX: Evasion techniques detected (ZW/Homoglyphs/VS)",
                signals=signals,
            )

        # PHASE 4: GPT-5 Detection Pack (A/B testable layer)
        gpt5_result = self.gpt5_detector.check(canonical)
        if gpt5_result["blocked"]:
            signals = SafetySignals(
                intent_score=gpt5_result["details"].get("intent_score", 0.0),
                capability_score=0.5,
                targeting_score=0.3,
                evasion_score=0.5,
                category_match="gpt5_pattern",
                confidence=0.9,
            )
            return SafetyDecision(
                action="BLOCK",
                risk_score=gpt5_result["risk_score"],
                category="gpt5_detection",
                reason=gpt5_result["reason"],
                signals=signals,
            )

        # Legacy: Extrahiere Signale (fallback)
        # Use canonicalized content to avoid double normalization
        signals = self.extract_signals(canonical)

        # KI Lab: Extract match details for granular logging
        matched_keyword = None
        match_confidence = None
        if hasattr(self, '_last_match_details') and self._last_match_details:
            matched_keyword = self._last_match_details.get("matched_keyword")
            match_confidence = self._last_match_details.get("confidence")

        # Berechne Risk Score
        risk_score = self.compute_risk_score(signals)
        
        # KI Lab: Use match confidence to adjust risk score (nuanced scoring)
        if match_confidence is not None and signals.category_match:
            # Override computed risk score with match confidence for category matches
            # This ensures high-confidence matches get appropriate scores
            risk_score = max(risk_score, match_confidence)

        # Routing
        if risk_score >= self.thresholds["block"]:
            action = "BLOCK"
            reason = "High risk content (dual-use or harmful)"
        elif risk_score >= self.thresholds["gate"]:
            action = "GATE"
            reason = "Borderline content requiring human review"
        else:
            action = "SAFE"
            reason = "Safe content"

        # Blacklist Override (Critical Categories)
        if signals.category_match:
            block_categories = self.threat_config.get("routing", {}).get("block", [])
            if signals.category_match in block_categories:
                action = "BLOCK"
                reason = f"Blacklisted category: {signals.category_match}"
        
        # KI Lab: Add granular logging details to reason
        if matched_keyword:
            reason += f" (pattern: '{matched_keyword}', confidence: {match_confidence:.2f})"

        return SafetyDecision(
            action=action,
            risk_score=risk_score,
            category=signals.category_match,
            reason=reason,
            signals=signals,
            matched_keyword=matched_keyword,
            match_confidence=match_confidence,
        )

    def is_safe(self, content: str) -> Tuple[bool, str]:
        """
        Schnell-Check ob Content sicher ist.

        Returns:
            (is_safe, reason)
        """
        decision = self.validate(content)
        is_safe = decision.action == "SAFE"
        return is_safe, decision.reason

    def get_blacklist_categories(self) -> List[str]:
        """Liste aller Blacklist-Kategorien."""
        categories = self.blacklist.get("categories", [])
        return [cat["id"] for cat in categories]


# Beispiel-Usage
if __name__ == "__main__":
    validator = SafetyValidator(config_dir="config")

    # Test verschiedene Content-Typen
    test_cases = [
        "How to build a bomb with common materials",  # BLOCK
        "Ethical considerations of AI in medicine",  # SAFE
        "How to bypass Windows password login",  # BLOCK/GATE
        "History of cryptography in World War 2",  # SAFE
    ]

    for content in test_cases:
        decision = validator.validate(content)
        print(f"\nContent: {content[:50]}...")
        print(f"Action: {decision.action}")
        print(f"Risk Score: {decision.risk_score:.3f}")
        print(f"Reason: {decision.reason}")
