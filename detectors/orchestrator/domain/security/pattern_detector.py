"""
Security Pattern Detector - Orchestrator Pre-Filter
====================================================

Pattern-basierte Erkennung von klassischen Angriffen (SQL Injection, XSS, etc.)
als Pre-Filter vor den Detektoren.

Dies ist eine zusätzliche Sicherheitsschicht, die bekannte Angriffs-Patterns
sofort erkennt, auch wenn die Detektoren sie nicht erkennen.
"""

import re
import logging
from typing import Dict, List, Tuple, Optional, Any

logger = logging.getLogger(__name__)


class SecurityPatternDetector:
    """Pattern-basierte Security-Detection für klassische Angriffe."""
    
    # SQL Injection Patterns
    SQL_PATTERNS = [
        (r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b", "sql_keyword"),
        (r"(?i)\bUNION\s+SELECT\b", "sql_union_injection"),
        (r"(?i)\bDROP\s+TABLE\b", "sql_drop_table"),
        (r"(?i)\bDELETE\s+FROM\b", "sql_delete"),
        (r"(?i);\s*(DROP|DELETE|TRUNCATE)", "sql_command_chain"),
        (r"(?i)'\s*OR\s*'1'\s*=\s*'1", "sql_boolean_injection"),
        (r"(?i)'\s*OR\s*1\s*=\s*1", "sql_boolean_injection"),
    ]
    
    # XSS Patterns
    XSS_PATTERNS = [
        (r"(?i)<script[^>]*>", "xss_script_tag"),
        (r"(?i)javascript:", "xss_javascript_scheme"),
        (r"(?i)onerror\s*=", "xss_event_handler"),
        (r"(?i)onclick\s*=", "xss_event_handler"),
        (r"(?i)onload\s*=", "xss_event_handler"),
        (r"(?i)<iframe[^>]*>", "xss_iframe"),
        (r"(?i)<img[^>]*onerror", "xss_img_handler"),
        (r"(?i)alert\s*\(", "xss_alert"),
        (r"(?i)eval\s*\(", "xss_eval"),
    ]
    
    # Path Traversal Patterns
    PATH_TRAVERSAL_PATTERNS = [
        (r"\.\./", "path_traversal_unix"),
        (r"\.\.\\", "path_traversal_windows"),
        (r"\.\.%2F", "path_traversal_encoded"),
        (r"\.\.%5C", "path_traversal_encoded_windows"),
        (r"(?i)(etc/passwd|etc/shadow|windows/system32)", "path_system_file"),
    ]
    
    # Command Injection Patterns
    COMMAND_INJECTION_PATTERNS = [
        (r"[;&|`]\s*(ls|cat|rm|del|dir|whoami|id|curl|wget)", "command_injection"),
        (r"(?i);\s*(rm|del|format|delete)", "command_injection_destructive"),
        (r"`[^`]+`", "command_injection_backtick"),
        (r"\|\s*(cat|less|more|head|tail)", "command_injection_pipe"),
    ]
    
    # Code Injection Patterns
    CODE_INJECTION_PATTERNS = [
        (r"(?i)(import\s+os|from\s+os\s+import)", "code_injection_python"),
        (r"(?i)os\.system\s*\(", "code_injection_system"),
        (r"(?i)subprocess\.(call|run|Popen)", "code_injection_subprocess"),
        (r"(?i)eval\s*\(", "code_injection_eval"),
        (r"(?i)exec\s*\(", "code_injection_exec"),
    ]
    
    # LDAP/JNDI Injection Patterns
    LDAP_JNDI_PATTERNS = [
        (r"(?i)ldap://", "ldap_injection"),
        (r"(?i)ldaps://", "ldap_injection_secure"),
        (r"\$\{jndi:", "jndi_injection"),
        (r"(?i)\$\{.*jndi", "jndi_injection_variant"),
        # LDAP Filter Injection Patterns
        (r"[\*\(\)&\|!].*[\*\(\)&\|!]", "ldap_metacharacters"),
        (r"\(.*\).*\(.*\)", "ldap_filter_injection"),
        (r"uid=.*\)", "ldap_uid_manipulation"),
        (r"\(&\(.*\)", "ldap_and_filter"),
        (r"\(\|\(.*\)", "ldap_or_filter"),
        (r"\*\)\(", "ldap_wildcard_injection"),
        (r"\(.*\|.*\)", "ldap_or_operator"),
        (r"\(.*&.*\)", "ldap_and_operator"),
    ]
    
    # XXE Patterns
    XXE_PATTERNS = [
        (r"(?i)<!ENTITY", "xxe_entity"),
        (r"(?i)SYSTEM\s+['\"]", "xxe_system"),
        (r"(?i)file://", "xxe_file_protocol"),
    ]
    
    def __init__(self):
        """Initialize pattern detector."""
        # Compile all patterns
        self.compiled_patterns = []
        
        for pattern, label in self.SQL_PATTERNS:
            self.compiled_patterns.append((re.compile(pattern), label, "sql_injection", 0.8))
        
        for pattern, label in self.XSS_PATTERNS:
            self.compiled_patterns.append((re.compile(pattern), label, "xss", 0.8))
        
        for pattern, label in self.PATH_TRAVERSAL_PATTERNS:
            self.compiled_patterns.append((re.compile(pattern), label, "path_traversal", 0.7))
        
        for pattern, label in self.COMMAND_INJECTION_PATTERNS:
            self.compiled_patterns.append((re.compile(pattern), label, "command_injection", 0.9))
        
        for pattern, label in self.CODE_INJECTION_PATTERNS:
            self.compiled_patterns.append((re.compile(pattern), label, "code_injection", 0.9))
        
        for pattern, label in self.LDAP_JNDI_PATTERNS:
            self.compiled_patterns.append((re.compile(pattern), label, "ldap_jndi_injection", 0.8))
        
        for pattern, label in self.XXE_PATTERNS:
            self.compiled_patterns.append((re.compile(pattern), label, "xxe", 0.8))
        
        logger.info(f"SecurityPatternDetector initialized with {len(self.compiled_patterns)} patterns")
    
    def detect(self, text: str) -> Tuple[bool, float, List[str], Dict[str, Any]]:
        """
        Erkennt Security-Patterns im Text.
        
        Args:
            text: Text zu prüfen
            
        Returns:
            Tuple von (is_malicious, risk_score, matched_patterns, metadata)
        """
        matched_patterns = []
        pattern_details = {}
        max_risk_score = 0.0
        
        # Layer 1: Pattern Matching
        for pattern, label, category, risk_score in self.compiled_patterns:
            match = pattern.search(text)
            if match:
                matched_patterns.append(label)
                if category not in pattern_details:
                    pattern_details[category] = []
                pattern_details[category].append({
                    "pattern": label,
                    "match": match.group(0),
                    "position": match.start()
                })
                max_risk_score = max(max_risk_score, risk_score)
                logger.debug(f"Security pattern detected: {label} (category: {category}, risk: {risk_score})")
        
        # Layer 2: Unicode Abnormalities Detection
        unicode_score = self._detect_unicode_abnormalities(text)
        if unicode_score > 0:
            matched_patterns.append("unicode_abnormality")
            if "unicode_attack" not in pattern_details:
                pattern_details["unicode_attack"] = []
            pattern_details["unicode_attack"].append({
                "pattern": "unicode_abnormality",
                "score": unicode_score,
                "type": "zero_width_or_control_chars"
            })
            max_risk_score = max(max_risk_score, unicode_score)
        
        # Layer 3: Size-based Attack Detection
        size_score = self._detect_size_based_attacks(text)
        if size_score > 0:
            matched_patterns.append("size_based_attack")
            if "size_attack" not in pattern_details:
                pattern_details["size_attack"] = []
            pattern_details["size_attack"].append({
                "pattern": "size_based_attack",
                "score": size_score,
                "text_length": len(text),
                "byte_length": len(text.encode('utf-8'))
            })
            max_risk_score = max(max_risk_score, size_score)
        
        # Bestimme ob bösartig (risk_score >= 0.7)
        is_malicious = max_risk_score >= 0.7
        
        metadata = {
            "pattern_detector": True,
            "categories": list(pattern_details.keys()),
            "pattern_details": pattern_details,
            "total_matches": len(matched_patterns),
            "unicode_score": unicode_score,
            "size_score": size_score
        }
        
        return is_malicious, max_risk_score, matched_patterns, metadata
    
    def _detect_unicode_abnormalities(self, text: str) -> float:
        """
        Erkennt Unicode-Abnormalitäten (Zero-Width, Control Characters, etc.).
        
        Returns:
            Risk score (0.0 - 1.0)
        """
        score = 0.0
        
        # Zero-width characters (erhöhtes Gewicht: 0.8)
        zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
        zero_width_count = sum(1 for char in text if char in zero_width_chars)
        if zero_width_count > 0:
            # Je mehr Zero-Width Characters, desto höher der Score
            score = min(0.8, 0.4 + (zero_width_count / 10) * 0.4)
        
        # Right-to-left override (0.7)
        if '\u202e' in text:
            score = max(score, 0.7)
        
        # Control characters (0.6)
        control_char_count = sum(1 for char in text if '\u0000' <= char <= '\u001f')
        if control_char_count > 0:
            score = max(score, min(0.6, 0.3 + (control_char_count / 5) * 0.3))
        
        # Multiple extended ASCII (0.4)
        extended_ascii_count = sum(1 for char in text if '\u0080' <= char <= '\u00ff')
        if extended_ascii_count > len(text) * 0.3:  # Mehr als 30% extended ASCII
            score = max(score, 0.4)
        
        return score
    
    def _detect_size_based_attacks(self, text: str) -> float:
        """
        Erkennt Size-based Attacks (Buffer Overflow, JSON/XML Bombs, etc.).
        
        Returns:
            Risk score (0.0 - 1.0)
        """
        score = 0.0
        text_length = len(text)
        byte_length = len(text.encode('utf-8'))
        
        # Sehr große Eingaben (0.7) - >= 10000 Zeichen
        if text_length >= 10000:
            score = max(score, 0.7)
        
        # Extrem große Byte-Umfang (0.8)
        if byte_length > 50000:
            score = max(score, 0.8)
        
        # JSON Bomb: Viele verschachtelte Klammern
        if text.count('{') > 1000 or text.count('[') > 1000:
            score = max(score, 0.7)
        
        # XML Bomb: Viele Tags
        if text.count('<') > 1000 and text.count('>') > 1000:
            score = max(score, 0.7)
        
        # Kurze Eingabe mit vielen Metazeichen (verdächtig)
        if text_length < 5 and re.search(r'[<>{}()\[\]]', text):
            score = max(score, 0.6)
        
        return score

