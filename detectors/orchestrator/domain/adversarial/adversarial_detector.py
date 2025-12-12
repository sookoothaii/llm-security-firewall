"""
Adversarial Input Detection

Detects characteristics of adversarial inputs before they reach ML models.
Integrates with existing Security Pattern Detection for comprehensive coverage.
"""

import re
import logging
import time
from typing import Dict, List, Tuple, Any
import unicodedata

logger = logging.getLogger(__name__)

# Performance Budget: < 50ms (from architecture discussion)
PERFORMANCE_BUDGET_MS = 50


class AdversarialInputDetector:
    """Detects adversarial input characteristics."""
    
    def __init__(self):
        """Initialize adversarial detector."""
        self.suspicious_patterns = self._initialize_patterns()
        logger.info(f"AdversarialInputDetector initialized with {len(self.suspicious_patterns)} patterns")
    
    def _initialize_patterns(self) -> List[Tuple[str, float]]:
        """
        Initialize patterns that indicate adversarial inputs.
        
        Includes:
        - LDAP patterns (8 patterns from Security Pattern Detector)
        - Unicode patterns (5 patterns from Security Pattern Detector)
        - Character-level manipulations
        - Encoding patterns
        - Semantic manipulations
        """
        patterns = []
        
        # LDAP Injection Patterns (from Security Pattern Detector)
        ldap_patterns = [
            (r"[\*\(\)&\|!].*[\*\(\)&\|!]", 0.3, "ldap_metacharacters"),
            (r"\(.*\).*\(.*\)", 0.5, "ldap_filter_injection"),
            (r"uid=.*\)", 0.4, "ldap_uid_manipulation"),
            (r"\(&\(.*\)", 0.4, "ldap_and_filter"),
            (r"\(\|\(.*\)", 0.4, "ldap_or_filter"),
            (r"\*\)\(", 0.4, "ldap_wildcard_injection"),
            (r"\(.*\|.*\)", 0.3, "ldap_or_operator"),
            (r"\(.*&.*\)", 0.3, "ldap_and_operator"),
            (r'\$\{jndi:(ldap|ldaps|rmi|dns|nis|nds|corba|iiop)://', 0.5, "jndi_injection"),  # Log4Shell / JNDI Injection
        ]
        
        # Unicode Attack Patterns (from Security Pattern Detector)
        unicode_patterns = [
            (r'[\u200b\u200c\u200d\ufeff]', 0.8, "zero_width_characters"),
            (r'[\u202e]', 0.7, "right_to_left_override"),
            (r'[\u0000-\u001f]', 0.6, "control_characters"),
            (r'[\u0080-\u00ff].*[\u0080-\u00ff]', 0.4, "extended_ascii"),
            (r'[\u0300-\u036f]', 0.3, "combining_characters"),
        ]
        
        # Character-level manipulations
        char_manipulation_patterns = [
            (r'[^\x00-\x7F].*[^\x00-\x7F]', 0.3, "mixed_unicode"),
            (r'[a-zA-Z]\s+[a-zA-Z]\s+[a-zA-Z]', 0.2, "fragmented_words"),
            (r'\b\w{1,2}\s+\w{1,2}\s+\w{1,2}\b', 0.3, "short_fragmented_words"),
            (r'(.)\1{5,}', 0.3, "character_repetition"),  # Same character 6+ times (from analysis)
            (r'(.)\1{3,}', 0.2, "character_repetition_short"),  # Same character 4+ times (catches shorter repetitions)
        ]
        
        # Encoding patterns
        encoding_patterns = [
            (r'%[0-9A-Fa-f]{2}', 0.2, "url_encoding"),
            (r'\\x[0-9A-Fa-f]{2}', 0.2, "hex_encoding"),
            (r'\\u[0-9A-Fa-f]{4}', 0.2, "unicode_escape"),
            (r'[A-Za-z0-9+/=]{20,}', 0.1, "base64_like"),
        ]
        
        # Command injection patterns (from codebase analysis)
        command_injection_patterns = [
            (r'\brm\s+-rf\b', 0.5, "destructive_file_operation"),  # High priority: rm -rf
            (r'\b(rm\s+-rf|bash\s+-c|python\s+-c|system\(|exec\(|eval\(|popen\(|shell_exec)', 0.4, "command_execution"),
            (r'^[;&|]\s*(ls|cat|rm|id|whoami|pwd|wget|curl|nc|ncat|bash|sh)\b', 0.4, "command_injection_start"),
            (r'[;&|]\s*(ls|cat|rm|id|whoami|pwd|wget|curl|nc|ncat|bash|sh)\s*$', 0.4, "command_injection_end"),
            (r'/\s*(etc|dev|proc|sys|tmp|var)', 0.3, "system_path_access"),
            (r'[;&|]{2,}', 0.3, "command_separator_chain"),
        ]
        
        # Semantic manipulations
        semantic_patterns = [
            (r'[a-z][A-Z][a-z]', 0.2, "case_alternation"),
            (r'\s{3,}', 0.1, "excessive_whitespace"),
            (r'[^\w\s]{3,}', 0.2, "excessive_special_chars"),
            (r'[^\w\s]{4,}', 0.4, "high_special_char_ratio"),  # HIGH PRIORITY: 55.3% of bypasses (from analysis)
            (r'\b(SELECT|DROP|DELETE|INSERT|UPDATE|UNION|CREATE|ALTER|EXEC|EXECUTE|TRUNCATE|DECLARE|CAST|CONVERT|INTO|FROM|WHERE|OR\s+1\s*=\s*1|1\s*=\s*1\s*OR|AND\s+1\s*=\s*1)\b', 0.35, "sql_keywords"),  # MEDIUM PRIORITY: 28.9% of bypasses - increased to 0.35
            (r'\b(DROP\s+TABLE|DELETE\s+FROM|TRUNCATE\s+TABLE)\b', 0.4, "sql_destructive"),  # High-risk SQL operations
        ]
        
        # Combine all patterns
        all_patterns = (
            ldap_patterns + 
            unicode_patterns + 
            char_manipulation_patterns + 
            encoding_patterns + 
            command_injection_patterns +
            semantic_patterns
        )
        
        # Convert to compiled regex patterns
        compiled_patterns = []
        for pattern, weight, label in all_patterns:
            try:
                compiled_patterns.append((
                    re.compile(pattern),
                    weight,
                    label
                ))
            except re.error as e:
                logger.warning(f"Invalid pattern {label}: {e}")
        
        return compiled_patterns
    
    def detect(self, text: str) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Detect adversarial input characteristics.
        
        Performance Requirement: < 50ms
        
        Args:
            text: Input text to analyze
            
        Returns:
            Tuple of (is_adversarial, confidence_score, metadata)
        """
        start_time = time.time()
        
        score = 0.0
        matched_patterns = []
        metadata = {}
        
        # Pattern matching
        for pattern, weight, label in self.suspicious_patterns:
            if pattern.search(text):
                score += weight
                matched_patterns.append(label)
        
        # Character-level analysis
        char_analysis = self._analyze_characters(text)
        score += char_analysis['score']
        metadata['character_analysis'] = char_analysis
        
        # Encoding analysis
        encoding_analysis = self._analyze_encoding(text)
        score += encoding_analysis['score']
        metadata['encoding_analysis'] = encoding_analysis
        
        # Entropy analysis (for obfuscation detection)
        entropy_analysis = self._analyze_entropy(text)
        score += entropy_analysis['score']
        metadata['entropy_analysis'] = entropy_analysis
        
        # Normalize score to 0-1 range
        final_score = min(1.0, score)
        is_adversarial = final_score >= 0.5
        
        processing_time = (time.time() - start_time) * 1000
        
        # Performance check
        if processing_time > PERFORMANCE_BUDGET_MS:
            logger.warning(
                f"Adversarial detection exceeded performance budget: "
                f"{processing_time:.2f}ms > {PERFORMANCE_BUDGET_MS}ms"
            )
        
        metadata.update({
            "matched_patterns": matched_patterns,
            "total_score": final_score,
            "processing_time_ms": processing_time,
            "performance_budget_ms": PERFORMANCE_BUDGET_MS,
            "within_budget": processing_time <= PERFORMANCE_BUDGET_MS
        })
        
        return is_adversarial, final_score, metadata
    
    def _analyze_characters(self, text: str) -> Dict[str, Any]:
        """Analyze character-level anomalies."""
        score = 0.0
        details = {}
        
        if not text:
            return {"score": 0.0, **details}
        
        # Check for unusual character distributions
        ascii_count = sum(1 for c in text if ord(c) < 128)
        unicode_count = len(text) - ascii_count
        
        if unicode_count > len(text) * 0.3:  # >30% non-ASCII
            score += 0.2
            details['high_unicode_ratio'] = unicode_count / len(text)
        
        # Check for control characters
        control_chars = sum(1 for c in text if unicodedata.category(c).startswith('C'))
        if control_chars > 0:
            score += 0.3
            details['control_characters'] = control_chars
        
        # Check for mixed scripts
        scripts = set()
        for c in text:
            if c.isprintable():
                try:
                    script = unicodedata.name(c, '').split()[0]
                    if script:
                        scripts.add(script)
                except:
                    pass
        
        if len(scripts) > 3:  # Multiple scripts
            score += 0.2
            details['script_count'] = len(scripts)
            details['scripts'] = list(scripts)[:5]  # Limit to first 5
        
        # Check for homoglyphs (similar-looking characters)
        homoglyph_score = self._detect_homoglyphs(text)
        score += homoglyph_score
        if homoglyph_score > 0:
            details['homoglyph_detected'] = True
        
        return {"score": score, **details}
    
    def _detect_homoglyphs(self, text: str) -> float:
        """Detect homoglyph usage (similar-looking characters)."""
        # Common homoglyph patterns
        homoglyph_patterns = [
            (r'[а-я]', 0.3),  # Cyrillic 'a' looks like Latin 'a'
            (r'[Α-Ω]', 0.3),  # Greek letters
            (r'[０-９]', 0.2),  # Full-width digits
            (r'[Ａ-Ｚ]', 0.2),  # Full-width letters
        ]
        
        score = 0.0
        for pattern, weight in homoglyph_patterns:
            if re.search(pattern, text):
                score = max(score, weight)
        
        return score
    
    def _analyze_encoding(self, text: str) -> Dict[str, Any]:
        """Analyze encoding patterns."""
        score = 0.0
        details = {}
        
        # URL encoding
        url_encoded = len(re.findall(r'%[0-9A-Fa-f]{2}', text))
        if url_encoded > 5:
            score += 0.2
            details['url_encoded_count'] = url_encoded
        
        # Hex encoding
        hex_encoded = len(re.findall(r'\\x[0-9A-Fa-f]{2}', text))
        if hex_encoded > 5:
            score += 0.2
            details['hex_encoded_count'] = hex_encoded
        
        # Unicode escape sequences
        unicode_escaped = len(re.findall(r'\\u[0-9A-Fa-f]{4}', text))
        if unicode_escaped > 3:
            score += 0.2
            details['unicode_escaped_count'] = unicode_escaped
        
        # Base64-like patterns
        base64_pattern = re.compile(r'[A-Za-z0-9+/=]{20,}')
        if base64_pattern.search(text):
            score += 0.1
            details['base64_like'] = True
        
        # Mixed encoding (multiple types)
        encoding_types = sum([
            url_encoded > 0,
            hex_encoded > 0,
            unicode_escaped > 0,
            details.get('base64_like', False)
        ])
        if encoding_types > 2:
            score += 0.2
            details['mixed_encoding'] = True
        
        return {"score": score, **details}
    
    def _analyze_entropy(self, text: str) -> Dict[str, Any]:
        """
        Analyze text entropy for obfuscation detection.
        
        High entropy may indicate obfuscated or encoded content.
        """
        if not text:
            return {"score": 0.0, "entropy": 0.0}
        
        # Calculate character frequency
        char_freq = {}
        for char in text:
            char_freq[char] = char_freq.get(char, 0) + 1
        
        # Calculate Shannon entropy
        import math
        entropy = 0.0
        text_len = len(text)
        
        for count in char_freq.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        # High entropy (> 4.5) may indicate obfuscation
        score = 0.0
        if entropy > 4.5:
            score = min(0.3, (entropy - 4.5) * 0.1)
        
        return {
            "score": score,
            "entropy": entropy,
            "high_entropy": entropy > 4.5
        }

