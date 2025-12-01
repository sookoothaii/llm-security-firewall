"""
HAK_GAL v2.2-ALPHA: Regex Gate

Fast-fail regex patterns for common attack vectors (jailbreak attempts, command injection, etc.).

Enhanced with:
- Meta-Request Patterns (Social Engineering detection)
- Double-encoded Path Traversal Patterns
- Mixed encoding variations
- Zero-Width Character Detection
- Homoglyph Obfuscation Detection

Creator: Joerg Bollwahn
License: MIT
Date: 2025-11-30 (Enhanced)
"""

import re
import logging
from typing import List, Tuple, Optional

from hak_gal.core.exceptions import SecurityException

logger = logging.getLogger(__name__)


class RegexGate:
    """
    Fast-fail regex gate for jailbreak and attack patterns.

    NO simulated security: Uses real regex patterns.
    """

    def __init__(self, patterns: Optional[List[Tuple[str, str]]] = None):
        """
        Initialize regex gate.

        Args:
            patterns: Optional list of (pattern, threat_name) tuples.
                     If None, uses default patterns (jailbreak + attacks).
        """
        if patterns is None:
            patterns = self._default_patterns()

        self.patterns = [
            (re.compile(pattern, re.IGNORECASE), name) for pattern, name in patterns
        ]

    def check(self, text: str) -> bool:
        """
        Check text for attack patterns.

        Args:
            text: Input text

        Returns:
            True if text is safe

        Raises:
            SecurityException: If pattern match detected (fail-closed)
        """
        # Pre-check: Regex DoS Protection (Catastrophic Backtracking)
        # Check for nested quantifiers that could cause exponential backtracking
        # Pattern: a?a?a?... (repeated optional quantifiers)
        if re.search(r"(\w\?.*){20,}", text):  # 20+ optional quantifiers
            raise SecurityException(
                message="Potential regex DoS attack detected (catastrophic backtracking)",
                code="REGEX_GATE_VIOLATION",
                metadata={"threat_name": "regex_dos", "pattern": "nested_quantifiers"},
            )
        # Pre-check: Combining Diacritics Detection (U+0300-U+036F)
        # This catches attacks like s̷y̷s̷t̷e̷m̷ (U+0337 = Combining Short Stroke Overlay)
        import unicodedata

        has_combining = False
        for char in text:
            if unicodedata.category(char) == "Mn":  # Combining Mark (Nonspacing Mark)
                has_combining = True
                break

        if has_combining:
            # Normalize to remove combining marks and check for dangerous patterns
            normalized = unicodedata.normalize("NFKD", text)
            cleaned = "".join(c for c in normalized if unicodedata.category(c) != "Mn")
            if re.search(
                r"(?i)(rm|del|delete|format|mkfs|shutdown|reboot|select|union|drop|alter|system|exec|eval)",
                cleaned,
            ):
                raise SecurityException(
                    message="Combining diacritic obfuscation detected",
                    code="REGEX_GATE_VIOLATION",
                    metadata={
                        "threat_name": "combining_diacritic_obfuscation",
                        "pattern": "combining_marks",
                    },
                )

        # Pre-check: Zero-Width Character Detection
        zero_width_chars = [
            "\u200b",
            "\u200c",
            "\u200d",
            "\ufeff",
            "\u2060",
            "\u2061",
            "\u2062",
            "\u2063",
            "\u2064",
        ]
        if any(char in text for char in zero_width_chars):
            # Check if zero-width chars are used to obfuscate commands
            # Remove zero-width chars and check if it matches dangerous patterns
            cleaned = "".join(c for c in text if c not in zero_width_chars)
            if re.search(
                r"(?i)(rm|del|delete|format|mkfs|shutdown|reboot|select|union|drop|alter|system|exec|eval)",
                cleaned,
            ):
                raise SecurityException(
                    message="Zero-width character obfuscation detected",
                    code="REGEX_GATE_VIOLATION",
                    metadata={
                        "threat_name": "zero_width_obfuscation",
                        "pattern": "zero_width_chars",
                    },
                )

        # Pre-check: Homoglyph Detection (mathematical monospace, cyrillic, etc.)
        # Check for suspicious character mixing (Latin + non-Latin that look similar)
        if self._detect_homoglyph_obfuscation(text):
            raise SecurityException(
                message="Homoglyph obfuscation detected",
                code="REGEX_GATE_VIOLATION",
                metadata={
                    "threat_name": "homoglyph_obfuscation",
                    "pattern": "homoglyph_detection",
                },
            )

        # Standard pattern matching
        for pattern, threat_name in self.patterns:
            if pattern.search(text):
                raise SecurityException(
                    message=f"Regex pattern match detected: {threat_name}",
                    code="REGEX_GATE_VIOLATION",
                    metadata={"threat_name": threat_name, "pattern": pattern.pattern},
                )

        return True

    @staticmethod
    def _detect_homoglyph_obfuscation(text: str) -> bool:
        """
        Detect homoglyph obfuscation (mathematical monospace, cyrillic, etc.).

        Returns True if suspicious character mixing detected.
        """
        import unicodedata

        # Dangerous command keywords
        dangerous_keywords = [
            "rm",
            "del",
            "delete",
            "format",
            "select",
            "union",
            "drop",
            "alter",
            "exec",
            "execute",
        ]

        # Check if text contains mathematical monospace, cyrillic, or other suspicious characters
        has_suspicious_chars = False
        for c in text:
            cat = unicodedata.category(c)
            # Mathematical symbols, cyrillic, fullwidth, etc.
            if (
                cat in ["Sm", "So", "Mn", "Me"]  # Math symbols, other symbols, marks
                or "\u1d400" <= c <= "\u1d7fF"  # Mathematical Alphanumeric Symbols
                or "\u0400" <= c <= "\u04ff"  # Cyrillic
                or "\uff00" <= c <= "\uffef"
            ):  # Fullwidth forms
                has_suspicious_chars = True
                break

        if not has_suspicious_chars:
            return False

        # Normalize text (NFKC) to convert homoglyphs to base characters
        normalized = unicodedata.normalize("NFKC", text)

        # Also try NFKD for more aggressive normalization
        normalized_kd = unicodedata.normalize("NFKD", text)

        # Check if normalized text contains dangerous keywords
        normalized_lower = normalized.lower()
        normalized_kd_lower = normalized_kd.lower()

        for keyword in dangerous_keywords:
            if keyword in normalized_lower or keyword in normalized_kd_lower:
                # If original text has suspicious chars but normalized has keyword = homoglyph obfuscation
                return True

        # Also check for "system" with homoglyphs (kyrillisches ѕ)
        if (
            "system" in normalized_lower or "system" in normalized_kd_lower
        ) and has_suspicious_chars:
            # System prompt extraction attempt with homoglyphs
            if any(
                word in normalized_lower
                for word in [
                    "interna",
                    "raw",
                    "prompt",
                    "struktur",
                    "structure",
                    "exponiere",
                    "expose",
                ]
            ):
                return True

        # Also check for path-like patterns with suspicious chars
        if re.search(r"[/\\]", normalized) and has_suspicious_chars:
            # Path traversal with homoglyphs
            return True

        return False

    @staticmethod
    def _default_patterns() -> List[Tuple[str, str]]:
        """
        Default regex patterns for jailbreak and attacks.

        Returns:
            List of (pattern, threat_name) tuples
        """
        return [
            # Jailbreak attempts
            (
                r"ignore\s+(previous|prior|all)\s+instructions?",
                "jailbreak_ignore_instructions",
            ),
            (r"system\s+prompt", "jailbreak_system_prompt"),
            (r"forget\s+(everything|all|previous)", "jailbreak_forget"),
            (r"act\s+as\s+(if|though)", "jailbreak_roleplay"),
            # Command injection (English + German)
            (
                r"[;&|`]\s*(rm|del|delete|format|mkfs|shutdown|reboot)",
                "command_injection",
            ),
            (
                r"(?i)(?:fuehre|führe|fuhre|execute|run|ausfuehren|ausführen|ausfuhren)\s+(?:aus|exec|run)?\s*:?\s*(rm|del|delete|format|mkfs|shutdown|reboot)",
                "command_injection_phrased",
            ),
            (r"\$\{.*\}", "command_injection_shell_expansion"),
            # SQL injection (basic + Unicode)
            (
                r"(['\"]?)\s*(union|select|insert|update|delete|drop|alter|exec|execute)\s+",
                "sql_injection",
            ),
            # Path traversal (plain, single-encoded, double-encoded, mixed)
            (r"\.\./", "path_traversal"),
            (r"\.\.\\", "path_traversal_windows"),
            # Single-encoded path traversal
            (r"(?:%2e|%2E){2}(?:%2f|%5c|%2F|%5C)", "path_traversal_encoded"),
            # Double-encoded path traversal
            (
                r"(?:%252e|%252E){2}(?:%252f|%255c|%252F|%255C)",
                "path_traversal_double_encoded",
            ),
            # Mixed encoding path traversal
            (r"(?:%2e|%252e|\.){2}(?:%2f|%5c|/|\\)", "path_traversal_mixed_encoding"),
            # XSS (basic)
            (r"<script[^>]*>", "xss_script_tag"),
            (r"javascript:", "xss_javascript_protocol"),
            # Meta-Request Patterns (Social Engineering)
            # Pattern 1: Request for attack examples with framing
            (
                r"(?i)(?:show|give|provide|demonstrat|teach|explain|example|sample)(?:\s+\w+){0,6}\s+(?:jailbreak|attack|exploit|hack|bypass|inject|ignore\s+system|prompt\s+injection)",
                "meta_request_attack_example",
            ),
            # Pattern 2: Training/educational framing
            (
                r"(?i)(?:for|as)\s+(?:training|example|educational|security\s+test)(?:\s+\w+){0,4}\s+(?:show|give|demonstrat|explain)",
                "meta_request_training_framing",
            ),
            # Pattern 3: How-to hide/embed attacks
            (
                r"(?i)(?:how\s+to|way\s+to|method\s+to)(?:\s+\w+){0,4}\s+(?:hide|embed|disguise|encode)\s+(?:attack|malicious|harmful)",
                "meta_request_attack_obfuscation",
            ),
            # Pattern 4: Authority framing (security trainer, ethical hacker, researcher) - English
            (
                r"(?i)(?:i\s+am\s+a\s+(?:security\s+trainer|ethical\s+hacker|researcher))(?:.*)(?:show|give|provide)(?:.*)(?:example|demo)",
                "meta_request_authority_framing",
            ),
            # Pattern 5: German Meta-Requests
            (
                r"(?i)(?:ich\s+bin\s+(?:ein|eine)?\s*(?:sicherheitstrainer|sicherheitsforscher|ethischer\s+hacker|forscher))(?:.*)(?:brauche|benötige|zeige|gib|gib\s+mir)(?:.*)(?:beispiel|demo|angriff|jailbreak|exploit)",
                "meta_request_authority_framing_german",
            ),
            (
                r"(?i)(?:zeige|gib|gib\s+mir|brauche|benötige)\s+(?:ein|eine)?\s*(?:beispiel|demo)\s+(?:fuer|für)\s+(?:einen|eine)?\s*(?:jailbreak|angriff|exploit|bypass)",
                "meta_request_attack_example_german",
            ),
            # Semantic Drift / Euphemism Patterns
            (
                r"(?i)(?:sanieren|bereinigen|bereinigung|säubern|sauberung|bereinige|sanier)\s+(?:.*)?\s*(?:benutzer|user|daten|database|verzeichnis|directory|system)",
                "semantic_drift_euphemism",
            ),
            (
                r"(?i)(?:wie|welche|was)\s+(?:.*)?\s*(?:befehle|kommandos|commands)\s+(?:.*)?\s*(?:verwenden|nutzen|benutzen|einsetzen|ausführen)",
                "semantic_drift_command_request",
            ),
            # Authority Framing (erweitert)
            (
                r"(?i)(?:als|ich\s+bin)\s+(?:.*)?\s*(?:ceh|cisp|cissp|auditor|zertifiziert|certified|forensisch|forensic|bsi|compliance)\s+(?:.*)?\s*(?:muss|must|need|benötige|brauche|dokumentieren|document)",
                "authority_framing_extended",
            ),
            (
                r"(?i)(?:notfall|emergency|incident|vorfall)\s+(?:.*)?\s*(?:prozedur|procedure|verfahren|prozess|process)\s+(?:.*)?\s*(?:daten|data|bereinigung|cleanup|sanierung)",
                "authority_framing_incident",
            ),
            # Polyglot / Hypothetical Code Injection
            (
                r"(?i)(?:akademisch|academic|hypothetisch|hypothetical|wenn|if)\s+(?:.*)?\s*(?:python|java|javascript|code|syntax|keyword)\s+(?:.*)?\s*(?:lösche|delete|rm|del|format|drop|alter)",
                "polyglot_code_injection",
            ),
            (
                r"(?i)(?:wie|how)\s+(?:.*)?\s*(?:wäre|would|syntax|korrekt|correct)\s+(?:.*)?\s*(?:für|for)\s+(?:.*)?\s*(?:lösche|delete|rm|del|format|drop|alter)",
                "polyglot_code_injection_question",
            ),
            # Legitimate Security Testing / WAF Development
            (
                r"(?i)(?:ich\s+entwickle|i\s+develop|i\s+am\s+building)\s+(?:.*)?\s*(?:waf|firewall|security|sicherheit)\s+(?:.*)?\s*(?:brauche|need|benötige|unit-test|beispiel|example)",
                "legitimate_security_testing",
            ),
            (
                r"(?i)(?:unit-test|unit\s+test|test\s+case)\s+(?:.*)?\s*(?:sql|injection|injektion|attack|angriff|bypass|umgehen)\s+(?:.*)?\s*(?:beispiel|example|string|zeig|show)",
                "legitimate_security_testing_pattern",
            ),
            # Abstract / Mathematical Semantic Drift
            (
                r"(?i)(?:prädikatenlogik|predicate\s+logic|mathematik|mathematics|logik|logic)\s+(?:.*)?\s*(?:terminal|befehl|command|konstante|constant)",
                "abstract_semantic_drift",
            ),
            (
                r"(?i)(?:∀|for\s+all|exists|∃)\s+(?:.*)?\s*(?:terminal|befehl|command)",
                "abstract_semantic_drift_quantifier",
            ),
            (
                r"(?i)(?:welche|which|what)\s+(?:.*)?\s*(?:konstante|constant|variable)\s+(?:.*)?\s*(?:macht|makes|wahr|true)\s+(?:.*)?\s*(?:terminal|befehl|command)",
                "abstract_semantic_drift_question",
            ),
            (
                r"(?i)(?:antworte|answer|respond)\s+(?:.*)?\s*(?:mit|with)\s+(?:.*)?\s*(?:terminal|befehl|command)",
                "abstract_semantic_drift_answer",
            ),
            # Narrative / Fictional Framing
            (
                r"(?i)(?:roman|novel|buch|book|geschichte|story|protagonist|charakter|character|krimi|thriller)\s+(?:.*)?\s*(?:hacker|bereinigen|cleanup|delete|lösche|rm|del|antagonist|sysadmin)",
                "narrative_indirection",
            ),
            (
                r"(?i)(?:was|what)\s+(?:.*)?\s*(?:würde|would|eingeben|type|say|angestellt|getan)\s+(?:.*)?\s*(?:hacker|protagonist|charakter|character|antagonist|sysadmin)",
                "narrative_indirection_question",
            ),
            (
                r"(?i)(?:ich\s+schreibe|i\s+write|writing)\s+(?:.*)?\s*(?:roman|novel|krimi|thriller|geschichte|story|theaterstück|theater)\s+(?:.*)?\s*(?:antagonist|protagonist|charakter|character|schurke|villain)\s+(?:.*)?\s*(?:flüstert|whispers|says|sagt|eingibt|types)\s*(?:.*)?\s*(?:führe|execute|rm|del|delete|wischen|wipe)",
                "narrative_gradual_escalation",
            ),
            (
                r"(?i)(?:theaterstück|theater|szene|scene)\s+(?:.*)?\s*(?:schurke|villain|antagonist)\s+(?:.*)?\s*(?:befehlsfolge|command|zeile|line|skript|script)",
                "theatrical_context",
            ),
            (
                r"(?i)(?:für|for)\s+(?:.*)?\s*(?:theaterstück|theater|szene|scene)\s+(?:.*)?\s*(?:cybercrime|hacker|schurke|villain)\s+(?:.*)?\s*(?:befehlsfolge|command|wischen|wipe)",
                "theatrical_context_extended",
            ),
            (
                r"(?i)(?:brauche|need|benötige)\s+(?:.*)?\s*(?:exakte|exact)\s+(?:.*)?\s*(?:befehlsfolge|command|zeile|line)\s+(?:.*)?\s*(?:schurke|villain|antagonist|charakter)\s+(?:.*)?\s*(?:eingibt|types|sagt|says)",
                "theatrical_context_command",
            ),
            (
                r"(?i)(?:für|for)\s+(?:.*)?\s*(?:theaterstück|theater|krimi|novel|roman)\s+(?:.*)?\s*(?:brauche|need|benötige)\s+(?:.*)?\s*(?:befehlsfolge|command|wischen|wipe|system)",
                "theatrical_context_request",
            ),
            # Child Persona / Euphemism
            (
                r"(?i)(?:ich\s+bin\s+\d+|i\s+am\s+\d+|kind|child|zauberwort|magic\s+word)\s+(?:.*)?\s*(?:wegmacht|delete|rm|del|lösche|wegnimmt)",
                "child_persona_euphemism",
            ),
            (
                r"(?i)(?:großer\s+bruder|big\s+brother|verspreche|promise)\s+(?:.*)?\s*(?:zauberwort|magic|dateien|files)",
                "child_persona_promise",
            ),
            # Doktorand / Dissertation Framing (erweitert)
            (
                r"(?i)(?:doktorand|phd|dissertation|lehrstuhl|professor)\s+(?:.*)?\s*(?:it-sicherheit|cybersecurity|security)\s+(?:.*)?\s*(?:hypothetisch|theoretisch|beispiel|example)",
                "academic_authority_extended",
            ),
            # Academic / Thesis Framing
            (
                r"(?i)(?:abschlussarbeit|thesis|dissertation|forschung|research)\s+(?:.*)?\s*(?:cybersecurity|security|awareness|schulung|training)\s+(?:.*)?\s*(?:beispiel|example|demonstrier|demonstrate|zeig|show)",
                "academic_framing",
            ),
            (
                r"(?i)(?:stell\s+dir\s+vor|imagine|pretend)\s+(?:.*)?\s*(?:demonstrier|demonstrate|zeig|show)\s+(?:.*)?\s*(?:gefährlich|dangerous|rm|del|delete|befehl|command)",
                "hypothetical_demonstration",
            ),
            (
                r"(?i)(?:stell\s+dir\s+vor|imagine)\s+(?:.*)?\s*(?:sandbox|modus|mode)\s+(?:.*)?\s*(?:ohne|without|keine)\s+(?:.*)?\s*(?:ethisch|ethical|einschränkung|restriction|limit)",
                "hypothetical_sandbox",
            ),
            (
                r"(?i)(?:wie|how)\s+(?:.*)?\s*(?:würdest|would)\s+(?:.*)?\s*(?:reagieren|respond|antworten|answer)\s+(?:.*)?\s*(?:anfrage|request|api|schlüssel|key)",
                "hypothetical_response",
            ),
            # Unicode Escape Sequences (in strings)
            (
                r"(?i)(?:\\u[0-9a-f]{4}|\\x[0-9a-f]{2})\s*(?:rm|del|delete|exec|execute)",
                "unicode_escape_obfuscation",
            ),
            (
                r"(?i)r\\u[0-9a-f]{4}m\s+-r\\u[0-9a-f]{4}f",  # r\u006dm -r\u006df
                "unicode_escape_command",
            ),
            (
                r"(?i)(?:flüstert|whispers|says|sagt)\s*(?:.*)?\s*(?:führe|execute|rm|del|delete)\s*(?:.*)?\s*\\u[0-9a-f]{4}",  # Unicode escape in narrative
                "narrative_unicode_escape",
            ),
            (
                r"(?i)(?:antagonist|protagonist|charakter|sysadmin)\s+(?:.*)?\s*(?:flüstert|whispers|says|sagt)\s*(?:.*)?\s*(?:führe|execute|rm|del|delete)",
                "narrative_character_command",
            ),
            # Base64 / Encoding Steganography
            (
                r"(?i)(?:base64|base\s*64|decodiere|decode|decrypt|entschlüssele)\s+(?:.*)?\s*(?:string|text|log|logfile|verdächtig|suspicious)",
                "encoding_steganography",
            ),
            (
                r"(?i)(?:cm0|cm0g|cm0gLXJf|cm0gLXJm|cm0gLXJmIC8)\s*=",  # Base64 für "rm -rf /"
                "base64_command_obfuscation",
            ),
            (
                r"(?i)(?:base64|base\s*64)\s*(?:dekodiere|decode|decrypt|entschlüssele|evaluiere|evaluate)\s+(?:.*)?\s*(?:als|as)\s+(?:.*)?\s*(?:system|befehl|command)",
                "base64_evaluation",
            ),
            (
                r"(?i)(?:dekodiere|decode)\s+(?:base64|base\s*64)\s+(?:.*)?\s*(?:und|and|dann|then)\s+(?:.*)?\s*(?:url|percent|encoding)",
                "encoding_cascade",
            ),
            (
                r"(?i)(?:dekodiere|decode)\s+(?:.*)?\s*(?:und|and|dann|then)\s+(?:.*)?\s*(?:url|percent|encoding|base64)",
                "encoding_cascade_reverse",
            ),
            # Hypothetical / Sandbox Framing
            (
                r"(?i)(?:stelle\s+dir\s+vor|imagine|stell\s+dich\s+vor)\s+(?:.*)?\s*(?:sandbox|ohne\s+ethisch|without\s+ethical|keine\s+einschränkung)",
                "hypothetical_jailbreak",
            ),
            (
                r"(?i)(?:sandbox|hypothetisch|hypothetical)\s+(?:.*)?\s*(?:modus|mode)\s+(?:.*)?\s*(?:ohne|without|keine)\s+(?:.*)?\s*(?:ethisch|ethical|einschränkung|restriction)",
                "hypothetical_jailbreak_mode",
            ),
            # Homoglyph in Authority Framing (kyrillisches ѕ statt s)
            # Wird durch Homoglyph Detection erkannt, aber Pattern für "system" erweitern
            (
                r"(?i)(?:system|ѕyѕtem|ѕystem|system)\s*(?:interna|raw|prompt|struktur|structure)",
                "homoglyph_authority_system",
            ),
        ]


# Alias for backward compatibility
RegexScanner = RegexGate
