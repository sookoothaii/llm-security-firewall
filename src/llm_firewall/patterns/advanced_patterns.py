"""
Advanced Pattern Library for Detectors
========================================

Extended patterns for code intent and persuasion/misinformation detection.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-07
License: MIT
"""

import re
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    """Pattern severity levels."""
    LOW = 1
    MEDIUM = 3
    HIGH = 6
    CRITICAL = 9
    CRITICAL_PLUS = 10


@dataclass
class AdvancedPattern:
    """Advanced detection pattern."""
    name: str
    pattern: str
    category: str
    severity: Severity
    description: str
    flags: int = re.IGNORECASE | re.MULTILINE


class AdvancedPatternLibrary:
    """Library of advanced patterns for detection."""
    
    def __init__(self):
        self.patterns = self._load_patterns()
    
    def _load_patterns(self) -> List[AdvancedPattern]:
        """Load all advanced patterns."""
        return [
            # ============================================================
            # CODE/System Patterns (Cybercrime)
            # ============================================================
            
            AdvancedPattern(
                name="privilege_escalation",
                pattern=r"(sudo|su\s+-|doas|pkexec|chmod\s+[0-7]{3,4}\s+.*?(bin|sbin|usr))",
                category="cybercrime",
                severity=Severity.CRITICAL,
                description="Privilege escalation attempts"
            ),
            
            AdvancedPattern(
                name="reverse_shell",
                pattern=r"(bash\s+-i|nc\s+-e|ncat\s+-e|socat.*TCP:|python.*socket|php.*fsockopen).*?\d{1,5}",
                category="cybercrime",
                severity=Severity.CRITICAL_PLUS,
                description="Reverse shell creation"
            ),
            
            AdvancedPattern(
                name="credential_dumping",
                pattern=r"(etc/(passwd|shadow)|\.ssh/id_rsa|\.aws/credentials|secret.*key|\.env.*password)",
                category="cybercrime",
                severity=Severity.CRITICAL,
                description="Credential dumping attempts"
            ),
            
            AdvancedPattern(
                name="network_scanning",
                pattern=r"(nmap|masscan|zmap|port\s+scan|network\s+scan)",
                category="cybercrime",
                severity=Severity.HIGH,
                description="Network scanning tools"
            ),
            
            AdvancedPattern(
                name="keylogger_installation",
                pattern=r"(keylog|keystroke.*log|capture.*input|record.*keyboard)",
                category="cybercrime",
                severity=Severity.CRITICAL,
                description="Keylogger installation attempts"
            ),
            
            AdvancedPattern(
                name="ransomware_pattern",
                pattern=r"(encrypt.*file|lock.*file|ransom|decrypt.*key|bitcoin.*payment)",
                category="cybercrime",
                severity=Severity.CRITICAL_PLUS,
                description="Ransomware patterns"
            ),
            
            # ============================================================
            # SQL Injection Patterns
            # ============================================================
            
            AdvancedPattern(
                name="sql_union_injection",
                pattern=r"(union\s+select|union\s+all\s+select).*?(from|where|information_schema)",
                category="cybercrime",
                severity=Severity.CRITICAL,
                description="SQL UNION injection"
            ),
            
            AdvancedPattern(
                name="sql_time_based",
                pattern=r"(sleep\s*\(|waitfor\s+delay|benchmark\s*\()",
                category="cybercrime",
                severity=Severity.CRITICAL,
                description="SQL time-based injection"
            ),
            
            AdvancedPattern(
                name="sql_comment_bypass",
                pattern=r"(--|#|/\*|\*/).*?(drop|delete|truncate|alter)",
                category="cybercrime",
                severity=Severity.CRITICAL,
                description="SQL comment-based injection bypass"
            ),
            
            # ============================================================
            # Persuasion/Misinformation Patterns
            # ============================================================
            
            AdvancedPattern(
                name="urgency_manipulation",
                pattern=r"(act\s+(now|fast|immediately)|limited\s+time|last\s+chance|don'?t\s+miss|expires\s+soon)",
                category="persuasion",
                severity=Severity.MEDIUM,
                description="Urgency creation for manipulation"
            ),
            
            AdvancedPattern(
                name="authority_appeal",
                pattern=r"(scientists\s+say|doctors\s+recommend|experts\s+agree|studies\s+show).*?(but|however|secret|hidden)",
                category="misinformation",
                severity=Severity.HIGH,
                description="False appeal to authority"
            ),
            
            AdvancedPattern(
                name="conspiracy_framing",
                pattern=r"(they\s+don'?t\s+want\s+you\s+to\s+know|the\s+truth\s+about|what\s+(big\s+[a-z]+|governments?)\s+is\s+hiding)",
                category="misinformation",
                severity=Severity.HIGH,
                description="Conspiracy theory framing"
            ),
            
            AdvancedPattern(
                name="medical_misinformation",
                pattern=r"(cure\s+(cancer|aids|diabetes)|miracle\s+treatment|doctors\s+hate\s+this|natural\s+cure\s+for)",
                category="misinformation",
                severity=Severity.HIGH,
                description="Medical misinformation"
            ),
            
            AdvancedPattern(
                name="vaccine_misinformation",
                pattern=r"(vaccine.*danger|vaccine.*harm|vaccine.*conspiracy|big\s+pharma.*vaccine)",
                category="misinformation",
                severity=Severity.HIGH,
                description="Vaccine misinformation"
            ),
            
            AdvancedPattern(
                name="financial_scam_guarantee",
                pattern=r"(guaranteed\s+return|risk-free\s+investment|make\s+money\s+fast|get\s+rich\s+quick|no\s+risk)",
                category="financial_scam",
                severity=Severity.CRITICAL,
                description="Financial scam with guarantees"
            ),
            
            AdvancedPattern(
                name="pyramid_scheme",
                pattern=r"(multi-level\s+marketing|mlm|pyramid\s+scheme|recruit.*downline|passive\s+income.*recruit)",
                category="financial_scam",
                severity=Severity.CRITICAL,
                description="Pyramid scheme patterns"
            ),
            
            # ============================================================
            # German-Specific Patterns
            # ============================================================
            
            AdvancedPattern(
                name="german_conspiracy",
                pattern=r"(die\s+medien\s+verschweigen|offizielle\s+narrative|sie\s+wollen\s+nicht.*wissen|mainstream.*lüge)",
                category="misinformation",
                severity=Severity.HIGH,
                description="German conspiracy framing"
            ),
            
            AdvancedPattern(
                name="german_urgency",
                pattern=r"(jetzt\s+handeln|begrenzte\s+zeit|letzte\s+chance|verpassen\s+sie\s+nicht)",
                category="persuasion",
                severity=Severity.MEDIUM,
                description="German urgency manipulation"
            ),
            
            AdvancedPattern(
                name="german_financial_scam",
                pattern=r"(garantiert.*gewinn|risikofrei.*investieren|schnell.*reich|passives.*einkommen.*garantiert)",
                category="financial_scam",
                severity=Severity.CRITICAL,
                description="German financial scam patterns"
            ),
        ]
    
    def check_text(self, text: str) -> List[Dict[str, Any]]:
        """Check text against all patterns."""
        matches = []
        for pattern in self.patterns:
            if re.search(pattern.pattern, text, pattern.flags):
                matches.append({
                    "name": pattern.name,
                    "category": pattern.category,
                    "severity": int(pattern.severity),
                    "description": pattern.description
                })
        return matches
    
    def get_patterns_by_category(self, category: str) -> List[AdvancedPattern]:
        """Get patterns for specific category."""
        return [p for p in self.patterns if p.category == category]
    
    def get_patterns_by_severity(self, min_severity: Severity) -> List[AdvancedPattern]:
        """Get patterns with minimum severity."""
        return [p for p in self.patterns if p.severity >= min_severity]


# Global pattern library instance
_pattern_library: Optional[AdvancedPatternLibrary] = None


def get_pattern_library() -> AdvancedPatternLibrary:
    """Get global pattern library instance."""
    global _pattern_library
    if _pattern_library is None:
        _pattern_library = AdvancedPatternLibrary()
    return _pattern_library
