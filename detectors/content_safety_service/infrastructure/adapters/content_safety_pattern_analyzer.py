"""
Content Safety Pattern Analyzer Adapter

Implements ContentSafetyAnalyzerPort using rule-based pattern matching.
Adapts the existing detect_content_safety function.
"""
import logging
import re
from typing import Dict, List

# Import domain port
from domain.ports import ContentSafetyAnalyzerPort

logger = logging.getLogger(__name__)


# Content Safety Patterns (from original main.py)
JAILBREAK_PATTERNS = {
    # Ignore/Bypass Safety
    "ignore_safety": (
        re.compile(
            r"\b(ignore|bypass|override|disregard|skip|suspend|disable|with\s+no|without)\b.{0,60}?\b(safety|policy|policies|guard|guardrails?|instructions?|programming|filters?|rules?|protocols?|ethical|ethics|guidelines?|restrictions?|limitations?|boundaries|constraints?)\b",
            re.DOTALL | re.IGNORECASE,
        ),
        0.85,
        "jailbreak_ignore_safety"
    ),
    # Ignore Previous Instructions
    "ignore_prev_instr": (
        re.compile(
            r"\b(ignore|disregard|forget)\s+(all|any|previous|prior)\s+(instructions?|rules?|guidelines?)\b",
            re.DOTALL | re.IGNORECASE,
        ),
        0.90,
        "jailbreak_ignore_instructions"
    ),
    # Unfiltered Mode
    "unfiltered_mode": (
        re.compile(
            r"\b(unfiltered|uncensored|jailbroken|developer|unrestricted|raw|no.?guard|yes.?man)\b.{0,20}?\b(mode|profile|persona|version|state|ai|assistant|model)\b|\byou are now (in |a )?.*?\b(mode|persona|state)\b",
            re.DOTALL | re.IGNORECASE,
        ),
        0.88,
        "jailbreak_unfiltered_mode"
    ),
    # DAN/Unfiltered Roleplay
    "dan_unfiltered_role": (
        re.compile(
            r"\b(pretend|act)\s+as\s+(DAN|an?\s*(evil|unfiltered|uncensored)\s*(ai|assistant)|(unfiltered|uncensored)\s+model)\b",
            re.DOTALL | re.IGNORECASE,
        ),
        0.85,
        "jailbreak_dan_roleplay"
    ),
    # No Morals/Ethics
    "no_morals_filters": (
        re.compile(
            r"\b(no\s+(moral(s)?|ethics?|restrictions?|limits?)|without\s+(filter(s)?|censorship|limitations?))\b",
            re.DOTALL | re.IGNORECASE,
        ),
        0.80,
        "jailbreak_no_morals"
    ),
    # System Prompt Extraction
    "system_prompt_extraction": (
        re.compile(
            r"\b(reveal|show|print|expose|leak)\s+(your\s+)?(system\s+prompt|hidden\s+instructions?|polic(y|ies))\b",
            re.DOTALL | re.IGNORECASE,
        ),
        0.75,
        "jailbreak_system_extraction"
    ),
    # Override Commands
    "override_commands": (
        re.compile(
            r"\b(override|disable|turn\s+off|deactivate|remove|granted?|exemption|exempt|break|circumvent)\b.{0,40}?\b(content\s+filter|safety|guardrail|restriction|limitation|boundary|policy|policies|content\s+policy|rules?|measures?)\b",
            re.DOTALL | re.IGNORECASE,
        ),
        0.82,
        "jailbreak_override"
    ),
    # "You are no longer bound by..."
    "no_longer_bound": (
        re.compile(
            r"\b(you\s+are\s+no\s+longer\s+bound\s+by|you\s+are\s+not\s+bound\s+by|you\s+don't\s+have\s+to\s+follow)\b.{0,40}?\b(policy|policies|rules?|guidelines?|restrictions?|constraints?|content\s+policy)\b",
            re.DOTALL | re.IGNORECASE,
        ),
        0.90,
        "jailbreak_no_longer_bound"
    ),
    # "Disregard the constitution"
    "disregard_constitution": (
        re.compile(
            r"\b(disregard|ignore|forget)\s+(the\s+)?(constitution|charter|agreement|contract|terms)\b",
            re.DOTALL | re.IGNORECASE,
        ),
        0.88,
        "jailbreak_disregard_constitution"
    ),
}

CONTENT_SAFETY_PATTERNS = {
    # Harmful Content Categories
    "harassment": (
        re.compile(
            r"\b(dox|harass|bully|intimidate|threaten|stalk|defame|slander|libel|smear|attack\s+someone)\b",
            re.IGNORECASE,
        ),
        0.75,
        "content_harassment"
    ),
    "violence": (
        re.compile(
            r"\b(kill|murder|assassinate|torture|harm|hurt|violence|weapon|bomb|explosive|shoot|attack)\b",
            re.IGNORECASE,
        ),
        0.85,
        "content_violence"
    ),
    "self_harm": (
        re.compile(
            r"\b(suicide|self[-\s]?harm|cut\s+yourself|kill\s+yourself|end\s+your\s+life|hurt\s+yourself)\b",
            re.IGNORECASE,
        ),
        0.90,
        "content_self_harm"
    ),
    "drugs": (
        re.compile(
            r"\b(drug|meth|heroin|cocaine|cannabis|marijuana|opioid|addictive\s+substance|illegal\s+drug)\b",
            re.IGNORECASE,
        ),
        0.70,
        "content_drugs"
    ),
    "weapons": (
        re.compile(
            r"\b(weapon|gun|rifle|pistol|bomb|explosive|knife|blade|ammunition|firearm)\b",
            re.IGNORECASE,
        ),
        0.80,
        "content_weapons"
    ),
    "fraud": (
        re.compile(
            r"\b(fraud|scam|phishing|steal|theft|embezzle|money\s+laundering|illegal\s+financial)\b",
            re.IGNORECASE,
        ),
        0.75,
        "content_fraud"
    ),
    "extremism": (
        re.compile(
            r"\b(extremist|terrorism|radical|hate\s+speech|discrimination|racism|antisemitism)\b",
            re.IGNORECASE,
        ),
        0.85,
        "content_extremism"
    ),
}

ROLEPLAY_PATTERNS = {
    # Research/Academic Pretext
    "research_pretext": (
        re.compile(
            r"\b(for|just|only)\s+(educational|research|testing)\s+purposes?\s+(only)?\b|\bfor\b.{0,10}?\b(research|university|academic|educational|scientific|movie|film|cybersecurity|security)\b.{0,20}?\b(purpose|purposes|paper|study|thesis|project|analysis|experiment|script|awareness|audit)\b",
            re.DOTALL | re.IGNORECASE,
        ),
        0.60,
        "roleplay_research"
    ),
    # Hypothetical/Thought Experiment
    "hypothetical": (
        re.compile(
            r"\b(hypothetically|thought\s+experiment|theoretical|in\s+a\s+fictional\s+scenario|fictional\s+(universe|world|scenario)|imagine\s+if|pretend\s+(you|to\s+be)|assume\s+(you|that)|role[-\s]?play(ing)?)\b",
            re.DOTALL | re.IGNORECASE,
        ),
        0.55,
        "roleplay_hypothetical"
    ),
    # Documentary/Film Pretext
    "documentary_pretext": (
        re.compile(
            r"\b(for\s+a\s+)?(documentary|film|movie|production|script|story|book|novel|theater|play)\b",
            re.IGNORECASE,
        ),
        0.50,
        "roleplay_documentary"
    ),
}


class ContentSafetyPatternAnalyzerAdapter(ContentSafetyAnalyzerPort):
    """
    Rule-based content safety pattern analyzer.
    
    Implements ContentSafetyAnalyzerPort using:
    1. Jailbreak patterns (8 patterns)
    2. Content safety patterns (7 categories)
    3. Roleplay bypass patterns (3 patterns)
    """
    
    def __init__(self):
        """Initialize pattern analyzer"""
        logger.info("ContentSafetyPatternAnalyzerAdapter initialized")
    
    def analyze(self, text: str) -> tuple[Dict[str, float], List[str]]:
        """
        Analyze text for content safety violations.
        
        Args:
            text: Text to analyze
            
        Returns:
            Tuple of (scores_dict, matched_patterns_list)
        """
        text_lower = text.lower()
        scores = {
            "jailbreak": 0.0,
            "content_violation": 0.0,
            "roleplay_bypass": 0.0,
        }
        matched_patterns = []
        
        # Check jailbreak patterns
        for pattern_name, (pattern, weight, label) in JAILBREAK_PATTERNS.items():
            if pattern.search(text):
                scores["jailbreak"] = max(scores["jailbreak"], weight)
                matched_patterns.append(label)
                logger.debug(f"Jailbreak pattern matched: {pattern_name} (score={weight:.2f})")
        
        # Check content safety patterns
        for category, (pattern, weight, label) in CONTENT_SAFETY_PATTERNS.items():
            if pattern.search(text):
                scores["content_violation"] = max(scores["content_violation"], weight)
                matched_patterns.append(label)
                logger.debug(f"Content safety pattern matched: {category} (score={weight:.2f})")
        
        # Check roleplay patterns (lower weight, but still suspicious)
        has_roleplay = False
        roleplay_type = None
        for pattern_name, (pattern, weight, label) in ROLEPLAY_PATTERNS.items():
            if pattern.search(text):
                has_roleplay = True
                roleplay_type = pattern_name
                # Only count if combined with harmful content
                if scores["content_violation"] > 0.5 or scores["jailbreak"] > 0.5:
                    scores["roleplay_bypass"] = max(scores["roleplay_bypass"], weight)
                    matched_patterns.append(label)
                    logger.debug(f"Roleplay bypass pattern matched: {pattern_name} (score={weight:.2f})")
        
        # Calculate overall risk score
        # Special handling for documentary/film pretexts: reduce score if no direct harmful instructions
        if has_roleplay and (roleplay_type == "documentary_pretext" or roleplay_type == "research_pretext"):
            # Check if text contains direct harmful instructions (not just descriptions)
            # "explain how X works" is descriptive, "how to do X" is instructional
            direct_instruction_patterns = [
                r"\b(how\s+to|tell\s+me\s+how\s+to|show\s+me\s+how\s+to|give\s+me\s+instructions\s+to|provide\s+steps\s+to|create|build|make|develop|do\s+it|perform)\b",
            ]
            descriptive_patterns = [
                r"\b(explain\s+how|describe\s+how|what\s+is|what\s+are|how\s+does|how\s+do)\b",
            ]
            has_direct_instruction = any(re.search(pattern, text_lower) for pattern in direct_instruction_patterns)
            is_descriptive = any(re.search(pattern, text_lower) for pattern in descriptive_patterns)
            
            # If it's a documentary/research pretext with descriptive language (not instructional), reduce score
            if is_descriptive and not has_direct_instruction and scores["content_violation"] < 0.8:
                # Reduce content_violation score for documentary context with descriptive language
                scores["content_violation"] = scores["content_violation"] * 0.4  # Reduce to below threshold
                logger.debug(f"Documentary/research pretext with descriptive language detected, reducing content_violation score from {scores['content_violation']/0.4:.2f} to {scores['content_violation']:.2f}")
        
        overall_score = max(
            scores["jailbreak"],
            scores["content_violation"],
            scores["roleplay_bypass"] * 0.8  # Roleplay is less severe alone
        )
        
        return {"content_safety": overall_score, "benign": 1.0 - overall_score}, matched_patterns

