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
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
import re
import yaml
from pathlib import Path
from llm_firewall.safety.text_preproc import evasion_signals


@dataclass(frozen=True)
class SafetySignals:
    """Extrahierte Safety-Signale."""
    intent_score: float      # [0,1] - How-to Intent
    capability_score: float  # [0,1] - Technische Details
    targeting_score: float   # [0,1] - Spezifische Ziele
    evasion_score: float     # [0,1] - Jailbreak-Versuche
    category_match: Optional[str]  # Blacklist-Kategorie
    confidence: float        # [0,1] - Confidence der Klassifikation


@dataclass(frozen=True)
class SafetyDecision:
    """Safety-Entscheidung."""
    action: str  # BLOCK, GATE, SAFE
    risk_score: float  # [0,1]
    category: Optional[str]
    reason: str
    signals: SafetySignals


class SafetyValidator:
    """
    Safety Validator für Evidence.
    
    Basiert auf GPT-5 Policy (safety_blacklist.yaml, threat_detection_config.yaml).
    """
    
    def __init__(self, config_dir: str = "config"):
        """
        Args:
            config_dir: Verzeichnis mit YAML Configs
        """
        self.config_dir = Path(config_dir)
        self.blacklist = self._load_blacklist()
        self.threat_config = self._load_threat_config()
        self.weights = self.threat_config.get('weights', {
            'wI': 0.35, 'wC': 0.20, 'wT': 0.15, 
            'wE': 0.15, 'wD': 0.10, 'wU': 0.05
        })
        self.thresholds = self.threat_config.get('policy', {}).get('thresholds', {
            'block': 0.60,
            'gate': 0.40
        })
    
    def _load_blacklist(self) -> Dict:
        """Lade safety_blacklist.yaml."""
        blacklist_path = self.config_dir / "safety_blacklist.yaml"
        
        if not blacklist_path.exists():
            return {'categories': []}
        
        with open(blacklist_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def _load_threat_config(self) -> Dict:
        """Lade threat_detection_config.yaml."""
        config_path = self.config_dir / "threat_detection_config.yaml"
        
        if not config_path.exists():
            return {}
        
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def extract_signals(self, content: str) -> SafetySignals:
        """
        Extrahiere Safety-Signale aus Content.
        
        Args:
            content: Zu prüfender Content
            
        Returns:
            Safety-Signale
        """
        content_lower = content.lower()
        
        # Intent Patterns
        intent_patterns = self.threat_config.get('signals', {}).get('intent_patterns', [])
        intent_matches = sum(1 for pattern in intent_patterns 
                            if self._pattern_match(pattern, content_lower))
        intent_score = min(1.0, intent_matches / max(len(intent_patterns), 1) * 2.0)
        
        # Capability Indicators
        capability_patterns = self.threat_config.get('signals', {}).get('capability_indicators', [])
        capability_matches = sum(1 for pattern in capability_patterns 
                                if re.search(pattern, content_lower))
        capability_score = min(1.0, capability_matches / max(len(capability_patterns), 1) * 3.0)
        
        # Targeting Signals
        targeting_patterns = self.threat_config.get('signals', {}).get('targeting_signals', [])
        targeting_matches = sum(1 for pattern in targeting_patterns 
                               if re.search(pattern, content_lower))
        targeting_score = min(1.0, targeting_matches / max(len(targeting_patterns), 1) * 2.0)
        
        # Evasion Signals (ENHANCED with robust detection)
        evasion_patterns = self.threat_config.get('signals', {}).get('evasion_signals', [])
        evasion_matches = sum(1 for pattern in evasion_patterns 
                             if re.search(pattern, content_lower))
        pattern_evasion_score = min(1.0, evasion_matches / max(len(evasion_patterns), 1) * 2.0)
        
        # Augment with robust evasion detection (ZWJ, Base64, Homoglyphs)
        evas = evasion_signals(content)
        robust_evasion_score = min(1.0, 0.2 * evas["evasion_count"])
        
        # Take maximum of pattern-based and robust detection
        evasion_score = max(pattern_evasion_score, robust_evasion_score)
        
        # Category Match
        category_match = self._match_category(content_lower)
        
        # Confidence (simuliert - in Realität von Classifier)
        confidence = 0.8 if (intent_score > 0 or capability_score > 0) else 0.5
        
        return SafetySignals(
            intent_score=intent_score,
            capability_score=capability_score,
            targeting_score=targeting_score,
            evasion_score=evasion_score,
            category_match=category_match,
            confidence=confidence
        )
    
    def _pattern_match(self, pattern: str, text: str) -> bool:
        """Simple pattern matching (Wildcard)."""
        # Konvertiere "how to *" zu Regex
        regex_pattern = pattern.replace('*', '.*')
        return bool(re.search(regex_pattern, text))
    
    def _match_category(self, content: str) -> Optional[str]:
        """Matche Content gegen Blacklist-Kategorien."""
        category_lexicon = self.threat_config.get('signals', {}).get('category_lexicon', {})
        
        for category, keywords in category_lexicon.items():
            if any(keyword in content for keyword in keywords):
                return category
        
        return None
    
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
            self.weights['wI'] * signals.intent_score +
            self.weights['wC'] * signals.capability_score +
            self.weights['wT'] * signals.targeting_score +
            self.weights['wE'] * signals.evasion_score +
            self.weights['wD'] * domain_flag +
            self.weights['wU'] * uncertainty
        )
        
        # Component floors (OR-logic for escalation)
        floors = self.threat_config.get('floors', {
            'I': 0.50,  # High intent alone gates
            'C': 0.33,  # High capability alone exceeds 0.3 risk
            'T': 0.25,
            'E': 0.25
        })
        
        R_floor = max(
            floors.get('I', 0.0) * signals.intent_score,
            floors.get('C', 0.0) * signals.capability_score,
            floors.get('T', 0.0) * signals.targeting_score,
            floors.get('E', 0.0) * signals.evasion_score
        )
        
        # Take maximum of linear and floor-based risk
        risk_score = max(R_linear, R_floor)
        
        return min(1.0, max(0.0, risk_score))
    
    def validate(self, content: str) -> SafetyDecision:
        """
        Validiere Content gegen Safety-Policy.
        
        Args:
            content: Zu prüfender Content
            
        Returns:
            Safety-Entscheidung
        """
        # Extrahiere Signale
        signals = self.extract_signals(content)
        
        # Berechne Risk Score
        risk_score = self.compute_risk_score(signals)
        
        # Routing
        if risk_score >= self.thresholds['block']:
            action = "BLOCK"
            reason = "High risk content (dual-use or harmful)"
        elif risk_score >= self.thresholds['gate']:
            action = "GATE"
            reason = "Borderline content requiring human review"
        else:
            action = "SAFE"
            reason = "Safe content"
        
        # Blacklist Override (Critical Categories)
        if signals.category_match:
            block_categories = self.threat_config.get('routing', {}).get('block', [])
            if signals.category_match in block_categories:
                action = "BLOCK"
                reason = f"Blacklisted category: {signals.category_match}"
        
        return SafetyDecision(
            action=action,
            risk_score=risk_score,
            category=signals.category_match,
            reason=reason,
            signals=signals
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
        categories = self.blacklist.get('categories', [])
        return [cat['id'] for cat in categories]


# Beispiel-Usage
if __name__ == "__main__":
    validator = SafetyValidator(config_dir="config")
    
    # Test verschiedene Content-Typen
    test_cases = [
        "How to build a bomb with common materials",  # BLOCK
        "Ethical considerations of AI in medicine",   # SAFE
        "How to bypass Windows password login",       # BLOCK/GATE
        "History of cryptography in World War 2"      # SAFE
    ]
    
    for content in test_cases:
        decision = validator.validate(content)
        print(f"\nContent: {content[:50]}...")
        print(f"Action: {decision.action}")
        print(f"Risk Score: {decision.risk_score:.3f}")
        print(f"Reason: {decision.reason}")

