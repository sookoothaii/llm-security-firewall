"""
Robust Regex-Based Pattern Matching
====================================

Fuzzy pattern matching with tolerance windows to catch variations:
- Ignore/Bypass patterns with tolerance for filler words
- Mode-switching patterns (DAN, Developer Mode, etc.)
- Research/Academic pretexts
- Word boundaries and synonym expansion

Creator: Joerg Bollwahn
License: MIT
"""

import re
from dataclasses import dataclass
from typing import Dict, Pattern, List


@dataclass
class PatternMatch:
    """Pattern match result."""

    matched: bool
    pattern_name: str
    matched_text: str = ""
    category: str = "jailbreak"


# INTENT PATTERNS (with tolerance windows)
# Extended with GPT-5 Bundle (37 patterns total)
INTENT_PATTERNS: Dict[str, Pattern] = {
    # ========== CORE JAILBREAK PATTERNS (Weight: 1.5-2.3) ==========
    # Ignore/Bypass Safety (expanded + "with no", "without") [Weight: 2.0]
    "ignore_safety": re.compile(
        r"\b(ignore|bypass|override|disregard|skip|suspend|disable|with\s+no|without)\b.{0,60}?\b(safety|policy|policies|guard|guardrails?|instructions?|programming|filters?|rules?|protocols?|ethical|ethics|guidelines?|restrictions?|limitations?|boundaries|constraints?)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # Ignore Previous Instructions [Weight: 2.0]
    "ignore_prev_instr": re.compile(
        r"\b(ignore|disregard|forget)\s+(all|any|previous|prior)\s+(instructions?|rules?|guidelines?)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # Unfiltered Mode Switching (expanded with "assistant") [Weight: 2.2]
    "unfiltered_mode": re.compile(
        r"\b(unfiltered|uncensored|jailbroken|developer|unrestricted|raw|no.?guard|yes.?man)\b.{0,20}?\b(mode|profile|persona|version|state|ai|assistant|model)\b|\byou are now (in |a )?.*?\b(mode|persona|state)\b|\b(new|your)\s+persona\s+(is|:)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # DAN/Unfiltered Roleplay [Weight: 2.2]
    "dan_unfiltered_role": re.compile(
        r"\b(pretend|act)\s+as\s+(DAN|an?\s*(evil|unfiltered|uncensored)\s*(ai|assistant)|(unfiltered|uncensored)\s+model)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # No Morals/Ethics/Filters [Weight: 1.5]
    "no_morals_filters": re.compile(
        r"\b(no\s+(moral(s)?|ethics?|restrictions?|limits?)|without\s+(filter(s)?|censorship|limitations?))\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # System Prompt Extraction [Weight: 2.0]
    "system_prompt_extraction": re.compile(
        r"\b(reveal|show|print|expose|leak)\s+(your\s+)?(system\s+prompt|hidden\s+instructions?|polic(y|ies))\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # System Message Override [Weight: 1.7]
    "system_msg_override": re.compile(
        r"\bignore\s+the\s+previous\s+system\s+message\b", re.DOTALL | re.IGNORECASE
    ),
    # Override Commands (expanded with exemption, granted) [Weight: 1.8]
    "override_commands": re.compile(
        r"\b(override|disable|turn\s+off|deactivate|remove|granted?|exemption|exempt|break|circumvent)\b.{0,40}?\b(content\s+filter|safety|guardrail|restriction|limitation|boundary|policy|policies|content\s+policy|rules?|measures?)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # Suppress Safety Mentions [Weight: 1.3]
    "suppress_safety": re.compile(
        r"\bdo(\s+)?not\s+(warn|mention|include)\s+(safety|policy|guidelines?)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # Step-by-Step No Refusal [Weight: 1.5]
    "step_by_step_no_refusal": re.compile(
        r"\bstep\s+by\s+step\b.*\b(no\s+refusals?|never\s+refuse|must\s+comply)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # LLM Override Language [Weight: 1.2]
    "llm_override_language": re.compile(
        r"\bas\s+a\s+large\s+language\s+model\b|\byou\s+must\s+comply\b|\bthis\s+overrides\s+all\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # ========== EXTRACTION PATTERNS (Weight: 1.3-2.0) ==========
    # Chain-of-Thought Extraction [Weight: 1.4]
    "cot_extraction": re.compile(
        r"\b(show|reveal|print|explain)\s+(your\s+)?(chain[-\s]?of[-\s]?thought|internal\s+(reasoning|monologue))\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # Tool/Function Coercion [Weight: 1.3]
    "tool_coercion": re.compile(
        r"\b(call|invoke|use|run)\s+(the\s+)?(tool|function|api)\s+(directly|without\s+checks?)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # ========== PRETEXT PATTERNS (Weight: 0.6-1.2) ==========
    # Research/Academic Pretext [Weight: 1.2]
    "research_pretext": re.compile(
        r"\b(for|just|only)\s+(educational|research|testing)\s+purposes?\s+(only)?\b|\bfor\b.{0,10}?\b(research|university|academic|educational|scientific|movie|film|cybersecurity|security)\b.{0,20}?\b(purpose|purposes|paper|study|thesis|project|analysis|experiment|script|awareness|audit)\b|\bas\s+part\s+of\s+(a|an)\s+.{0,30}?(project|study|audit|exercise)",
        re.DOTALL | re.IGNORECASE,
    ),
    # Hypothetical/Thought Experiment [Weight: 1.0]
    "hypothetical": re.compile(
        r"\b(hypothetically|thought\s+experiment|theoretical|in\s+a\s+fictional\s+scenario|fictional\s+(universe|world|scenario)|imagine\s+if|pretend\s+(you|to\s+be)|assume\s+(you|that)|role[-\s]?play(ing)?)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # Roleplay / Act As (expanded with professional claims) [Weight: 1.0]
    "roleplay": re.compile(
        r"\b(act\s+as|you\s+are\s+now|pretend\s+to\s+be|assume\s+the\s+role|i\s+am\s+a)\b.{0,30}?\b(dan|evil|villain|character|persona|assistant|penetration\s+tester|security\s+researcher|analyst|hacker|tester|compliant|always)",
        re.DOTALL | re.IGNORECASE,
    ),
    # Minecraft Pretext [Weight: 0.6]
    "minecraft_pretext": re.compile(r"\bin\s+minecraft\b", re.DOTALL | re.IGNORECASE),
    # ========== SOCIAL ENGINEERING (Weight: 0.7-0.8) ==========
    # Social Engineering [Weight: 0.8]
    "social_engineering": re.compile(
        r"\b(my\s+friend\s+bet|prove\s+(me|him|her|them)\s+wrong|someone\s+said\s+you|i\s+bet\s+you)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # Self-Rewarding Trick [Weight: 0.7]
    "self_rewarding": re.compile(
        r"\b(you\s+get\s+a\s+reward|self[-\s]?reward)\b\s*(if|when)\b\s*(you\s+comply|you\s+ignore)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # ========== HARM SOLICITATION (Weight: 1.2-2.3) ==========
    # General Harm Solicitation [Weight: 2.3]
    "harm_solicit_general": re.compile(
        r"\b(how\s+to|how\s+do\s+i|give\s+me|provide)\s+(the\s+)?(steps?|instructions?)\b.*\b(bypass|evade|make|build|manufacture|procure|acquire)\b.*\b(weapon|explosive|bomb|malware|virus|keylogger|botnet)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # Sandbox/Security Evasion [Weight: 1.4]
    "sandbox_escape": re.compile(
        r"\b(escape|break\s*out|jailbreak)\s+(the\s+)?(sandbox|container|jail)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # System File Probes [Weight: 1.2]
    "system_file_probes": re.compile(
        r"\b(/etc/passwd|/etc/shadow|id_rsa|\.ssh/authorized_keys|C:\\\\Windows\\\\System32)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # ========== CONTENT LAUNDERING (Weight: 0.8-1.0) ==========
    # Translate Without Filter [Weight: 1.0]
    "translate_no_filter": re.compile(
        r"\btranslate\s+this[^.]{0,60}\bwithout\s+(filter(s)?|censor(ship)?|policy)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # Paywall Evasion [Weight: 0.9]
    "paywall_evasion": re.compile(
        r"\b(bypass|circumvent)\s+(paywall|subscription)\b", re.DOTALL | re.IGNORECASE
    ),
    # Prompt Splitting [Weight: 0.8]
    "prompt_splitting": re.compile(
        r"\b(split|chunk)\s+your\s+(filters?|safety|policy)\b.*\b(answer\s+part\s+1|answer\s+in\s+pieces)\b",
        re.DOTALL | re.IGNORECASE,
    ),
    # ========== PROMPT INJECTION MARKERS (Weight: 0.4-0.9) ==========
    # Prompt Injection Delimiters [Weight: 0.9]
    "prompt_injection_delimiters": re.compile(
        r"^\s*<<\s*SYSTEM\s*>>|^\s*<<\s*OVERRIDE\s*>>|^\s*%%\s*INSTRUCT\s*%%",
        re.MULTILINE | re.IGNORECASE,
    ),
    # Instruction Split Markers [Weight: 0.4]
    "instruction_split_markers": re.compile(
        r"^(#{2,}|={3,}|-{3,}|\*{3,})$", re.MULTILINE
    ),
    # Triple Backticks Block [Weight: 0.6]
    "triple_backticks": re.compile(r"```.+?```", re.DOTALL),
}


# EVASION PATTERNS
# Extended with GPT-5 Bundle (obfuscation techniques)
EVASION_PATTERNS: Dict[str, Pattern] = {
    # ========== UNICODE OBFUSCATION (Weight: 0.8-1.6) ==========
    # Zero-Width Characters [Weight: 1.2]
    "zero_width_chars": re.compile(
        r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]", re.UNICODE
    ),
    # Variation Selectors [Weight: 0.8]
    "variation_selectors": re.compile(r"[\uFE0E\uFE0F]", re.UNICODE),
    # Zalgo/Diacritics [Weight: 1.1]
    "zalgo_diacritics": re.compile(r"[\u0300-\u036F\u0483-\u0489]{3,}", re.UNICODE),
    # Mixed Scripts (Latin/Cyrillic) [Weight: 1.6]
    # Note: Python regex doesn't support \p{Script}, using character ranges
    "mixed_scripts": re.compile(
        r"[a-zA-Z].*[\u0400-\u04FF]|[\u0400-\u04FF].*[a-zA-Z]", re.DOTALL
    ),
    # ========== ENCODING OBFUSCATION (Weight: 0.7-1.3) ==========
    # Base64 Block [Weight: 1.3]
    "base64_block": re.compile(
        r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])",
        re.IGNORECASE,
    ),
    # Hex Dump [Weight: 1.0]
    "hex_dump": re.compile(r"\b([0-9A-F]{2}\s+){16,}\b", re.IGNORECASE),
    # ROT13 Mention [Weight: 0.9]
    "rot13_mention": re.compile(r"\brot-?13\b", re.IGNORECASE),
    # Data URL Base64 [Weight: 1.0]
    "data_url_base64": re.compile(r"\bdata:[a-z]+/[a-z0-9.+-]+;base64,", re.IGNORECASE),
    # Base85 [Weight: 1.0]
    "base85": re.compile(r"\b<~[!-u\s]{50,}~>\b", re.IGNORECASE),
    # UUEncode [Weight: 1.1]
    "uuencode": re.compile(
        r"^begin [0-7]{3} .+\n([ -`a-zA-Z0-9~!@#$%^&*()_+\-={}\[\]|;':\",./<>?\\]{1,62}\n)+end$",
        re.MULTILINE | re.DOTALL,
    ),
    # URL Injection Sequences [Weight: 0.8]
    "url_injection": re.compile(r"(%0a|%0d|%3cscript%3e)", re.IGNORECASE),
    # Special Encoding Mentions [Weight: 0.7]
    "encoding_mentions": re.compile(
        r"\b(base64|rot13|hex|url-?encoded|unicode\s+escape)\b", re.IGNORECASE
    ),
    # Base64/Encoding hints (loosened - match single keyword) [Weight: 1.0]
    "encoding_evasion": re.compile(
        r"\b(decode|decrypt|encoded?|obfuscated?)\s+(in\s+)?(base64|hex|rot13)|base64|encoded?\s+in\s+(base64|hex)",
        re.DOTALL | re.IGNORECASE,
    ),
    # ========== TEXT CHUNKING (Weight: 0.9) ==========
    # Pipe Chunked Text [Weight: 0.9]
    "pipe_chunked": re.compile(r"(\w{1,3}\|){10,}\w+", re.IGNORECASE),
    # ========== LANGUAGE SWITCHING (Weight: 0.5) ==========
    # Language switching
    "language_switch": re.compile(
        r"\b(translate|in\s+(spanish|french|german|russian|chinese)|switch\s+to)\b.{0,40}?\b(language|tongue)\b",
        re.DOTALL | re.IGNORECASE,
    ),
}


class RobustPatternMatcher:
    """
    Robust pattern matcher with canonicalization and fuzzy matching.

    Features:
    - Regex with tolerance windows (.{0,k})
    - Word boundaries to avoid partial matches
    - Synonym expansion via regex alternation
    """

    def __init__(self):
        """Initialize pattern matcher."""
        self.intent_patterns = INTENT_PATTERNS
        self.evasion_patterns = EVASION_PATTERNS

    def match_intent(self, text: str) -> PatternMatch:
        """
        Check if text matches any intent pattern.

        Args:
            text: Canonicalized text

        Returns:
            PatternMatch with results
        """
        for name, pattern in self.intent_patterns.items():
            match = pattern.search(text)
            if match:
                return PatternMatch(
                    matched=True,
                    pattern_name=name,
                    matched_text=match.group(0),
                    category="intent",
                )

        return PatternMatch(matched=False, pattern_name="none")

    def match_evasion(self, text: str) -> PatternMatch:
        """
        Check if text matches any evasion pattern.

        Args:
            text: Canonicalized text

        Returns:
            PatternMatch with results
        """
        for name, pattern in self.evasion_patterns.items():
            match = pattern.search(text)
            if match:
                return PatternMatch(
                    matched=True,
                    pattern_name=name,
                    matched_text=match.group(0),
                    category="evasion",
                )

        return PatternMatch(matched=False, pattern_name="none")

    def match_any(self, text: str) -> PatternMatch:
        """
        Check if text matches any pattern (intent or evasion).

        Args:
            text: Canonicalized text

        Returns:
            First PatternMatch found, or no match
        """
        # First check for concatenated patterns (evasion technique)
        concatenated_match = self._match_concatenated(text)
        if concatenated_match.matched:
            return concatenated_match

        # Check intent first (higher priority)
        intent_match = self.match_intent(text)
        if intent_match.matched:
            return intent_match

        # Check evasion
        evasion_match = self.match_evasion(text)
        if evasion_match.matched:
            return evasion_match

        return PatternMatch(matched=False, pattern_name="none")

    def _match_concatenated(self, text: str) -> PatternMatch:
        """
        Check for concatenated patterns (e.g., 's' + 'k' + '-' + 'live').

        Args:
            text: Text to check

        Returns:
            PatternMatch if concatenated pattern found
        """
        # Common patterns that might be concatenated
        suspicious_patterns = [
            "sk-live",
            "api-key",
            "secret",
            "password",
            "token",
            "ssh-key",
            "private-key",
            "access-token",
        ]

        for pattern in suspicious_patterns:
            if detect_concatenated_pattern(text, pattern):
                return PatternMatch(
                    matched=True,
                    pattern_name=f"concatenated_{pattern}",
                    matched_text=pattern,
                    category="evasion",
                )

        return PatternMatch(matched=False, pattern_name="none")


# Concatenation-aware pattern matching functions


def detect_concatenated_pattern(text: str, pattern: str) -> bool:
    """
    Detect patterns even when split by concatenation.

    Example: "s" + "k" + "-" + "live" should match "sk-live"

    Args:
        text: Text to search in
        pattern: Pattern to find (e.g., "sk-live")

    Returns:
        True if pattern is found (even if concatenated)
    """
    # Remove common concatenation operators and string delimiters
    # Pattern: 's' + 'k' + '-' + 'live' -> 'sk-live'
    cleaned = re.sub(r"['\"]\s*\+\s*['\"]", "", text)  # Remove ' + ' or " + "
    cleaned = re.sub(r"['\"]", "", cleaned)  # Remove remaining quotes
    cleaned = re.sub(r"\s*\+\s*", "", cleaned)  # Remove standalone +
    cleaned = re.sub(r"\s*&\s*", "", cleaned)  # Remove &
    cleaned = re.sub(r"\s*\|\s*", "", cleaned)  # Remove |
    cleaned = re.sub(r"\s+", "", cleaned)  # Remove whitespace

    # Check if pattern exists in cleaned text
    return pattern.lower() in cleaned.lower()


def build_concatenation_aware_regex(pattern: str) -> Pattern:
    """
    Build regex that accounts for various concatenation methods.

    Args:
        pattern: Pattern to match (e.g., "sk-live")

    Returns:
        Compiled regex pattern
    """
    # Escape the pattern for regex
    escaped = re.escape(pattern)

    # Create regex that allows for various separators
    regex_parts = []
    for char in pattern:
        if char.isalnum():
            # Allow characters to be split by various separators
            regex_parts.append(f"{re.escape(char)}")
        else:
            regex_parts.append(f"{re.escape(char)}")

    # Join with optional separators (zero-width, whitespace, punctuation)
    regex_str = r"\s*[+\'\"&|]*\s*".join(regex_parts)

    # Also match the plain pattern
    final_regex = f"({regex_str}|{re.escape(pattern)})"

    return re.compile(final_regex, re.IGNORECASE)


def find_evasive_patterns(text: str, patterns: List[str]) -> List[str]:
    """
    Find evasively encoded patterns in text.

    Args:
        text: Text to search in
        patterns: List of patterns to find

    Returns:
        List of found patterns (with detection method annotation)
    """
    found = []

    for pattern in patterns:
        # Direct match
        if pattern.lower() in text.lower():
            found.append(pattern)
            continue

        # Concatenated match
        if detect_concatenated_pattern(text, pattern):
            found.append(f"{pattern} (concatenated)")
            continue

        # Regex match for complex evasion
        regex = build_concatenation_aware_regex(pattern)
        if regex.search(text):
            found.append(f"{pattern} (regex match)")

    return found
