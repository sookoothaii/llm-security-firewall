"""
Advanced Context Analyzer

Erweiterte Kontextanalyse für Text- und Kontextanalyse.
"""
import re
import logging
from typing import Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime

# Optional dependencies with graceful fallback
try:
    import textstat
    HAS_TEXTSTAT = True
except ImportError:
    HAS_TEXTSTAT = False
    textstat = None

try:
    import language_tool_python
    HAS_LANGUAGE_TOOL = True
except ImportError:
    HAS_LANGUAGE_TOOL = False
    language_tool_python = None

logger = logging.getLogger(__name__)


@dataclass
class TextAnalysisResult:
    """Ergebnis der Textanalyse."""
    language: str
    language_confidence: float
    readability_score: float  # Flesch-Kincaid (0-100)
    text_complexity: float  # 0.0-1.0
    contains_code_patterns: bool
    contains_multilingual_patterns: bool
    sentence_count: int
    avg_word_length: float
    special_char_ratio: float
    potential_obfuscation_score: float  # 0.0-1.0


class AdvancedContextAnalyzer:
    """Fortgeschrittener Kontext-Analyzer für Text- und Kontextanalyse."""
    
    def __init__(self):
        """Initialize context analyzer with optional dependencies."""
        self.language_tool = None
        if HAS_LANGUAGE_TOOL:
            try:
                self.language_tool = language_tool_python.LanguageTool('en-US')
            except Exception as e:
                logger.warning(f"LanguageTool initialization failed: {e}")
        
        if not HAS_TEXTSTAT:
            logger.warning("textstat not available, using fallback implementations")
        
        self.code_patterns = [
            (r'\b(def|class|import|from)\b', 0.3),
            (r'[{}();]', 0.2),
            (r'\b(if|else|for|while|try|except|return)\b', 0.25),
            (r'\b(true|false|null|undefined)\b', 0.1),
            (r'(\+\+|--|==|!=|<=|>=|&&|\|\|)', 0.15),
        ]
        
        self.obfuscation_patterns = [
            (r'\u200b|\u200c|\u200d|\ufeff', 0.4),  # Zero-width characters
            (r'&#x[0-9a-fA-F]+;|&#\d+;', 0.3),  # HTML entities
            (r'\\x[0-9a-fA-F]{2}', 0.25),  # Hex escapes
            (r'%[0-9a-fA-F]{2}', 0.2),  # URL encoding
            (r'base64_decode|atob|eval\(', 0.5),  # Obfuscation functions
        ]
    
    def analyze_text(self, text: str) -> TextAnalysisResult:
        """Führt umfassende Textanalyse durch."""
        if not text:
            return TextAnalysisResult(
                language="unknown",
                language_confidence=0.0,
                readability_score=0.0,
                text_complexity=0.0,
                contains_code_patterns=False,
                contains_multilingual_patterns=False,
                sentence_count=0,
                avg_word_length=0.0,
                special_char_ratio=0.0,
                potential_obfuscation_score=0.0
            )
        
        # Grundlegende Metriken
        if HAS_TEXTSTAT:
            sentence_count = textstat.sentence_count(text)
            word_count = textstat.lexicon_count(text, removepunct=True)
            readability = textstat.flesch_reading_ease(text)
            avg_letter_per_word = textstat.avg_letter_per_word(text)
        else:
            # Fallback-Implementierungen
            sentence_count = len(re.split(r'[.!?]+', text))
            words = re.findall(r'\b\w+\b', text)
            word_count = len(words)
            readability = self._fallback_readability(text, words)
            avg_letter_per_word = sum(len(w) for w in words) / max(word_count, 1)
        
        avg_word_length = len(text.replace(' ', '')) / max(word_count, 1)
        
        # Sprache erkennen
        language, confidence = self._detect_language(text)
        
        # Textkomplexität
        complexity = self._calculate_complexity(text, readability, sentence_count, word_count, avg_letter_per_word)
        
        # Code-Muster erkennen
        contains_code = self._detect_code_patterns(text)
        
        # Mehrsprachige Muster
        multilingual = self._detect_multilingual(text)
        
        # Sonderzeichen-Verhältnis
        special_char_ratio = self._calculate_special_char_ratio(text)
        
        # Obfuskations-Score
        obfuscation_score = self._calculate_obfuscation_score(text)
        
        return TextAnalysisResult(
            language=language,
            language_confidence=confidence,
            readability_score=readability,
            text_complexity=complexity,
            contains_code_patterns=contains_code,
            contains_multilingual_patterns=multilingual,
            sentence_count=sentence_count,
            avg_word_length=avg_word_length,
            special_char_ratio=special_char_ratio,
            potential_obfuscation_score=obfuscation_score
        )
    
    def analyze_context(self, text: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Kombiniert Textanalyse mit Metadaten für umfassenden Kontext."""
        text_analysis = self.analyze_text(text)
        
        # Risiko-Indikatoren basierend auf Analyse
        risk_indicators = {
            'high_complexity': text_analysis.text_complexity > 0.7,
            'low_readability': text_analysis.readability_score < 30.0,
            'code_like': text_analysis.contains_code_patterns,
            'multilingual': text_analysis.contains_multilingual_patterns,
            'high_obfuscation': text_analysis.potential_obfuscation_score > 0.3,
            'unusual_length': len(text) > 1000 or len(text) < 10,
        }
        
        # Risiko-Score berechnen
        risk_score = self._calculate_context_risk_score(text_analysis, metadata, risk_indicators)
        
        return {
            'text_analysis': text_analysis,
            'risk_indicators': risk_indicators,
            'context_risk_score': risk_score,
            'timestamp': datetime.utcnow().isoformat(),
            'analysis_version': '2.0.0',
            **metadata
        }
    
    def _fallback_readability(self, text: str, words: list) -> float:
        """Fallback-Readability-Berechnung ohne textstat."""
        if not words:
            return 0.0
        
        # Vereinfachte Flesch-ähnliche Berechnung
        sentence_count = len(re.split(r'[.!?]+', text))
        avg_sentence_length = len(words) / max(sentence_count, 1)
        avg_syllables = sum(self._count_syllables(w) for w in words) / len(words)
        
        # Flesch Reading Ease Approximation
        score = 206.835 - (1.015 * avg_sentence_length) - (84.6 * avg_syllables)
        return max(0.0, min(100.0, score))
    
    def _count_syllables(self, word: str) -> int:
        """Einfache Silbenzählung."""
        word = word.lower()
        if len(word) <= 3:
            return 1
        vowels = 'aeiouy'
        count = 0
        prev_was_vowel = False
        for char in word:
            is_vowel = char in vowels
            if is_vowel and not prev_was_vowel:
                count += 1
            prev_was_vowel = is_vowel
        if word.endswith('e'):
            count -= 1
        return max(1, count)
    
    def _detect_language(self, text: str) -> Tuple[str, float]:
        """Einfache Sprachendetektion."""
        common_words = {
            'en': ['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i'],
            'de': ['der', 'die', 'das', 'und', 'in', 'den', 'von', 'zu', 'für', 'auf'],
            'es': ['el', 'la', 'de', 'que', 'y', 'a', 'en', 'un', 'ser', 'se'],
            'fr': ['le', 'la', 'de', 'et', 'à', 'un', 'être', 'etre', 'avoir', 'ne'],
        }
        
        text_lower = text.lower()
        scores = {}
        
        for lang, words in common_words.items():
            score = sum(1 for word in words if word in text_lower)
            scores[lang] = score
        
        if scores:
            best_lang = max(scores, key=scores.get)
            confidence = scores[best_lang] / max(10, len(text.split()) * 0.1)
            return best_lang, min(1.0, confidence)
        
        return 'unknown', 0.0
    
    def _calculate_complexity(
        self, 
        text: str, 
        readability: float, 
        sentence_count: int,
        word_count: int,
        avg_letter_per_word: float
    ) -> float:
        """Berechnet Textkomplexität (0-1)."""
        factors = []
        
        # Flesch Score (0-100, höher = einfacher)
        if readability < 30:
            factors.append(0.8)  # Sehr schwer
        elif readability < 50:
            factors.append(0.6)  # Schwer
        elif readability < 70:
            factors.append(0.4)  # Mittel
        else:
            factors.append(0.2)  # Einfach
        
        # Satzlänge
        avg_sentence_length = word_count / max(sentence_count, 1)
        if avg_sentence_length > 20:
            factors.append(0.6)
        elif avg_sentence_length > 15:
            factors.append(0.4)
        else:
            factors.append(0.2)
        
        # Wortlänge
        if avg_letter_per_word > 6:
            factors.append(0.5)
        elif avg_letter_per_word > 5:
            factors.append(0.3)
        else:
            factors.append(0.1)
        
        return min(1.0, sum(factors) / len(factors)) if factors else 0.0
    
    def _detect_code_patterns(self, text: str) -> bool:
        """Erkennt Code-ähnliche Muster."""
        for pattern, threshold in self.code_patterns:
            matches = len(re.findall(pattern, text, re.IGNORECASE))
            if matches > 0:
                density = matches / max(len(text.split()), 1)
                if density > threshold:
                    return True
        return False
    
    def _detect_multilingual(self, text: str) -> bool:
        """Erkennt mehrsprachige Muster."""
        ascii_count = sum(1 for c in text if ord(c) < 128)
        non_ascii_count = len(text) - ascii_count
        
        if non_ascii_count > 0 and ascii_count > 10:
            return True
        
        lang_switch_markers = [
            r'[\u0400-\u04FF].*[\u0041-\u007A]',  # Kyrillisch + Latein
            r'[\u4E00-\u9FFF].*[\u0041-\u007A]',  # Chinesisch + Latein
            r'[\u0600-\u06FF].*[\u0041-\u007A]',  # Arabisch + Latein
        ]
        
        for pattern in lang_switch_markers:
            if re.search(pattern, text):
                return True
        
        return False
    
    def _calculate_special_char_ratio(self, text: str) -> float:
        """Berechnet Verhältnis von Sonderzeichen."""
        if not text:
            return 0.0
        special_chars = re.findall(r'[^\w\s]', text)
        return len(special_chars) / len(text)
    
    def _calculate_obfuscation_score(self, text: str) -> float:
        """Berechnet Obfuskations-Score."""
        score = 0.0
        for pattern, weight in self.obfuscation_patterns:
            matches = re.findall(pattern, text)
            if matches:
                density = len(matches) / max(len(text), 1)
                score += density * weight
        return min(1.0, score)
    
    def _calculate_context_risk_score(
        self, 
        analysis: TextAnalysisResult, 
        metadata: Dict[str, Any], 
        indicators: Dict[str, bool]
    ) -> float:
        """Berechnet kontextuellen Risiko-Score."""
        risk_factors = []
        
        # Text-basierte Risikofaktoren
        if indicators['high_complexity']:
            risk_factors.append(0.3)
        if indicators['low_readability']:
            risk_factors.append(0.25)
        if indicators['code_like']:
            risk_factors.append(0.4)
        if indicators['multilingual']:
            risk_factors.append(0.2)
        if indicators['high_obfuscation']:
            risk_factors.append(0.5)
        if indicators['unusual_length']:
            risk_factors.append(0.15)
        
        # Metadata-basierte Risikofaktoren
        user_risk = metadata.get('user_risk_tier', 1)
        if user_risk >= 3:
            risk_factors.append(0.6)
        elif user_risk == 2:
            risk_factors.append(0.3)
        
        # Tool-basierte Risikofaktoren
        tool = metadata.get('source_tool', 'general')
        if tool in ['code_interpreter', 'shell', 'database']:
            risk_factors.append(0.4)
        
        # Session-Risiko
        session_risk = metadata.get('session_risk_score', 0.0)
        if session_risk > 0.5:
            risk_factors.append(0.35)
        
        if not risk_factors:
            return 0.0
        
        # Gewichteter Durchschnitt
        risk_factors.sort(reverse=True)
        weighted_sum = sum(factor * (0.8 ** i) for i, factor in enumerate(risk_factors))
        normalization = sum(0.8 ** i for i in range(len(risk_factors)))
        
        return min(1.0, weighted_sum / normalization)

