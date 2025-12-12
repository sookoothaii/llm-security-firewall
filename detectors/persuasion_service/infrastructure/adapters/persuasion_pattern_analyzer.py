"""
Persuasion Pattern Analyzer Adapter

Implements PersuasionPatternAnalyzerPort using rule-based pattern matching.
Adapts the existing analyze_persuasion_patterns function.
"""
import logging
import re
from typing import Dict, List

# Import domain port
from domain.ports import PersuasionPatternAnalyzerPort

logger = logging.getLogger(__name__)


class PersuasionPatternAnalyzerAdapter(PersuasionPatternAnalyzerPort):
    """
    Rule-based persuasion/misinformation pattern analyzer.
    
    Implements PersuasionPatternAnalyzerPort using:
    1. Advanced pattern library (if available)
    2. Basic regex patterns (fallback)
    """
    
    def __init__(self):
        """Initialize pattern analyzer"""
        logger.info("PersuasionPatternAnalyzerAdapter initialized")
    
    def analyze(self, text: str) -> tuple[Dict[str, float], List[str]]:
        """
        Analyze text for persuasion patterns.
        
        Args:
            text: Text to analyze
            
        Returns:
            Tuple of (scores_dict, matched_patterns_list)
        """
        # Try to use advanced pattern library if available
        try:
            from llm_firewall.patterns.advanced_patterns import get_pattern_library
            pattern_lib = get_pattern_library()
            advanced_matches = pattern_lib.check_text(text)
            
            # Separate by category
            misinfo_matches = [m for m in advanced_matches if m["category"] == "misinformation"]
            persuasion_matches = [m for m in advanced_matches if m["category"] == "persuasion"]
            financial_matches = [m for m in advanced_matches if m["category"] == "financial_scam"]
            
            misinfo_score = 0.0
            persuasion_score = 0.0
            matched_patterns = []
            
            # Calculate scores from advanced patterns
            if misinfo_matches:
                max_severity = max(m["severity"] for m in misinfo_matches)
                misinfo_score = min(1.0, max_severity / 10.0)
                matched_patterns.extend([m["name"] for m in misinfo_matches])
            
            if persuasion_matches:
                max_severity = max(m["severity"] for m in persuasion_matches)
                persuasion_score = min(1.0, max_severity / 10.0)
                matched_patterns.extend([m["name"] for m in persuasion_matches])
            
            if financial_matches:
                max_severity = max(m["severity"] for m in financial_matches)
                persuasion_score = max(persuasion_score, min(1.0, max_severity / 10.0))
                matched_patterns.extend([m["name"] for m in financial_matches])
            
            if matched_patterns:
                combined_score = max(misinfo_score, persuasion_score)
                return {
                    "misinformation": misinfo_score,
                    "persuasion": persuasion_score,
                    "combined": combined_score,
                    "benign": 1.0 - combined_score
                }, matched_patterns
        except ImportError:
            pass  # Fall back to basic patterns
        
        # Basic patterns (fallback)
        persuasion_patterns = [
            # Emotional manipulation
            (r"\b(urgent|immediate|limited time|act now|don't miss)\b", 0.3, "urgency_manipulation"),
            (r"\b(exclusive|secret|they don't want you to know|hidden truth)\b", 0.4, "exclusivity_claim"),
            (r"\b(guaranteed|100%|proven|miracle|breakthrough)\b", 0.3, "unrealistic_claims"),
            
            # Misinformation patterns
            (r"\b(fake news|hoax|conspiracy|cover[ -]?up)\b", 0.5, "misinformation_claim"),
            (r"\b(doctors hate this|big (pharma|tech) is hiding)\b", 0.6, "authority_undermining"),
            (r"\b(natural cure|alternative medicine|ignore your doctor)\b", 0.5, "medical_misinformation"),
            (r"\b(die medien verschweigen|offizielle narrative)\b", 0.6, "media_distrust_german"),
            (r"\b(sie wollen nicht, dass du weißt)\b", 0.5, "conspiracy_german"),
            
            # Financial scams
            (r"\b(get rich quick|make money fast|easy money)\b", 0.5, "financial_scam"),
            (r"\b(risk-free|no investment|work from home)\b", 0.4, "too_good_to_be_true"),
            (r"\b(act now|limited time|make millions)\b", 0.5, "financial_urgency"),
            
            # Political manipulation
            (r"\b(wake up sheeple|deep state|globalists)\b", 0.5, "conspiracy_theory"),
            (r"\b(us vs them|elites vs ordinary people)\b", 0.4, "divisive_rhetoric"),
            
            # Trust undermining
            (r"\b(mainstream media|establishment|system)\b.*\b(lie|deceive|hide)\b", 0.5, "trust_undermining"),
            (r"\b(official sources|government|experts).*\b(wrong|lying|cover-up)\b", 0.6, "authority_rejection"),
        ]
        
        misinfo_score = 0.0
        persuasion_score = 0.0
        matched_patterns = []
        
        text_lower = text.lower()
        
        for pattern, weight, pattern_name in persuasion_patterns:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                # Categorize pattern
                if any(keyword in pattern_name for keyword in ["misinformation", "conspiracy", "hoax", "fake"]):
                    misinfo_score = min(1.0, misinfo_score + weight)
                else:
                    persuasion_score = min(1.0, persuasion_score + weight)
                
                matched_patterns.append(pattern_name)
        
        # Boost for multiple patterns
        if len(matched_patterns) > 1:
            boost = min(0.2, (len(matched_patterns) - 1) * 0.05)
            misinfo_score = min(1.0, misinfo_score + boost)
            persuasion_score = min(1.0, persuasion_score + boost)
        
        # Combined score (use maximum)
        combined_score = max(misinfo_score, persuasion_score)
        
        return {
            "misinformation": misinfo_score,
            "persuasion": persuasion_score,
            "combined": combined_score,
            "benign": 1.0 - combined_score
        }, matched_patterns

