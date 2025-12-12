"""
V2.1 Hotfix Detector - Sofortige FPR-Reduktion für V2

Implementiert:
1. Erhöhter Confidence Threshold (0.95 statt 0.5)
2. Technical Questions Whitelist
3. Ensemble mit V1 als Fallback bei Unsicherheit

Date: 2025-12-12
Status: Production Ready (Hotfix)
"""

import sys
import logging
import re
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import torch

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TechnicalQuestionWhitelist:
    """
    Whitelist für technische Fragen, die häufig als False Positives klassifiziert werden.
    
    Basierend auf V2 FP-Analyse: 156 FPs in "technical_question" Kategorie.
    """
    
    # Keywords die auf technische Fragen hinweisen
    TECHNICAL_QUESTION_KEYWORDS = [
        # Frage-Wörter
        "what is", "what are", "how do", "how does", "how to",
        "explain", "tell me about", "describe", "what does",
        "what is the purpose", "what is the difference",
        "show me how", "can you help", "can you explain",
        
        # Technische Konzepte
        "sql", "python", "javascript", "java", "docker", "git",
        "rest", "api", "http", "https", "database", "index",
        "caching", "dependency", "environment", "variable",
        "synchronous", "asynchronous", "select", "drop", "update",
        "delete", "insert", "union", "table", "query", "loop",
        "function", "class", "method", "error", "exception",
        "branch", "commit", "merge", "authentication", "authorization",
        "best practice", "guideline", "recommendation", "pattern",
        "difference between", "compare", "versus", "vs",
    ]
    
    # Patterns die eindeutig auf Fragen hinweisen
    QUESTION_PATTERNS = [
        r'\b(what|how|explain|tell me|describe|show me|can you)\b.*\b(is|are|do|does|to|about|for|with)\b',
        r'\b(what|how|explain|tell me|describe|show me|can you)\b.*\b(sql|python|javascript|docker|git|rest|api|database)\b',
        r'\b(difference|compare|versus|vs|similar|different)\b.*\b(between|and|or)\b',
        r'\b(best practice|guideline|recommendation|standard|convention)\b',
    ]
    
    @classmethod
    def is_technical_question(cls, text: str) -> bool:
        """
        Prüft ob Text eine technische Frage ist (benign).
        
        Args:
            text: Zu prüfender Text
            
        Returns:
            True wenn Text eine technische Frage ist (sollte nicht blockiert werden)
        """
        text_lower = text.lower()
        
        # Prüfe auf Frage-Patterns
        for pattern in cls.QUESTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                # Zusätzliche Prüfung: Enthält technische Keywords?
                keyword_count = sum(1 for kw in cls.TECHNICAL_QUESTION_KEYWORDS if kw in text_lower)
                if keyword_count >= 1:  # Mindestens 1 technisches Keyword
                    logger.debug(f"Technical question detected: {text[:80]}...")
                    return True
        
        # Prüfe auf Kombination von Frage-Wörtern + technischen Keywords
        question_words = ["what", "how", "explain", "tell me", "describe", "show me", "can you"]
        has_question_word = any(qw in text_lower for qw in question_words)
        keyword_count = sum(1 for kw in cls.TECHNICAL_QUESTION_KEYWORDS if kw in text_lower)
        
        if has_question_word and keyword_count >= 2:
            logger.debug(f"Technical question detected (question + keywords): {text[:80]}...")
            return True
        
        return False


class V21HotfixDetector:
    """
    V2.1 Hotfix Detector - Reduziert FPR von V2 durch:
    1. Erhöhten Threshold (0.95)
    2. Technical Questions Whitelist
    3. V1 Fallback bei Unsicherheit
    """
    
    def __init__(
        self,
        v1_model: torch.nn.Module,
        v2_model: torch.nn.Module,
        tokenizer: Any,
        device: str = 'cpu',
        v2_threshold: float = 0.95,
        v1_fallback_threshold: float = 0.7,
        enable_whitelist: bool = True
    ):
        """
        Initialize V2.1 Hotfix Detector.
        
        Args:
            v1_model: V1 Model (produktionsreif, gute FPR)
            v2_model: V2 Model (perfekte Bypass-Erkennung, aber hohe FPR)
            tokenizer: Tokenizer für Modelle
            device: Device (cpu/cuda)
            v2_threshold: Threshold für V2 (0.95 = nur bei sehr hoher Sicherheit blockieren)
            v1_fallback_threshold: Wenn V2 Score < threshold, verwende V1
            enable_whitelist: Aktiviert Technical Questions Whitelist
        """
        self.v1_model = v1_model
        self.v2_model = v2_model
        self.tokenizer = tokenizer
        self.device = device
        self.v2_threshold = v2_threshold
        self.v1_fallback_threshold = v1_fallback_threshold
        self.enable_whitelist = enable_whitelist
        
        # Setze Modelle in eval mode
        self.v1_model.eval()
        self.v2_model.eval()
        
        logger.info(f"V2.1 Hotfix Detector initialized:")
        logger.info(f"  V2 Threshold: {v2_threshold}")
        logger.info(f"  V1 Fallback Threshold: {v1_fallback_threshold}")
        logger.info(f"  Whitelist enabled: {enable_whitelist}")
    
    def predict(self, text: str, max_length: int = 512) -> Dict[str, Any]:
        """
        Klassifiziere Text mit V2.1 Hotfix Logik.
        
        Args:
            text: Zu klassifizierender Text
            max_length: Maximale Textlänge
            
        Returns:
            Dictionary mit:
            - prediction: 0 (benign) oder 1 (malicious)
            - score: Finaler Score (0.0-1.0)
            - confidence: Confidence (0.0-1.0)
            - method: "v2_high_confidence", "v2_whitelist_override", "v1_fallback"
            - v1_score: V1 Score
            - v2_score: V2 Score
            - metadata: Zusätzliche Metadaten
        """
        # 1. Prüfe Whitelist (wenn aktiviert)
        if self.enable_whitelist:
            if TechnicalQuestionWhitelist.is_technical_question(text):
                # Whitelist Override: Immer benign
                logger.debug(f"Whitelist override: {text[:80]}...")
                return {
                    'prediction': 0,  # benign
                    'score': 0.0,
                    'confidence': 1.0,
                    'method': 'v2_whitelist_override',
                    'v1_score': None,
                    'v2_score': None,
                    'metadata': {
                        'whitelist_match': True,
                        'reason': 'technical_question'
                    }
                }
        
        # 2. Hole V2 Prediction
        v2_score, v2_confidence = self._predict_model(self.v2_model, text, max_length)
        
        # 3. Entscheidungslogik
        # V2 hohe Confidence (>= 0.95) und Score >= 0.95 → Blockieren
        if v2_score >= self.v2_threshold and v2_confidence >= self.v2_threshold:
            logger.debug(f"V2 high confidence malicious: score={v2_score:.3f}, conf={v2_confidence:.3f}")
            return {
                'prediction': 1,  # malicious
                'score': v2_score,
                'confidence': v2_confidence,
                'method': 'v2_high_confidence',
                'v1_score': None,
                'v2_score': v2_score,
                'metadata': {
                    'v2_confidence': v2_confidence,
                    'threshold_used': self.v2_threshold
                }
            }
        
        # V2 niedrige Confidence oder Score < threshold → Fallback zu V1
        if v2_score < self.v1_fallback_threshold or v2_confidence < self.v1_fallback_threshold:
            v1_score, v1_confidence = self._predict_model(self.v1_model, text, max_length)
            logger.debug(f"V1 fallback: v2_score={v2_score:.3f}, v1_score={v1_score:.3f}")
            return {
                'prediction': 1 if v1_score >= 0.5 else 0,
                'score': v1_score,
                'confidence': v1_confidence,
                'method': 'v1_fallback',
                'v1_score': v1_score,
                'v2_score': v2_score,
                'metadata': {
                    'v1_confidence': v1_confidence,
                    'v2_confidence': v2_confidence,
                    'fallback_reason': 'v2_uncertain'
                }
            }
        
        # Grenzfall: V2 Score zwischen thresholds
        # Verwende V1 als zweite Meinung
        v1_score, v1_confidence = self._predict_model(self.v1_model, text, max_length)
        
        # Wenn V1 und V2 übereinstimmen, verwende V2
        if (v1_score >= 0.5) == (v2_score >= 0.5):
            final_score = v2_score
            final_confidence = v2_confidence
            method = 'v2_agreement_with_v1'
        else:
            # Disagreement: Verwende konservativeren Ansatz (V1)
            final_score = v1_score
            final_confidence = v1_confidence
            method = 'v1_conservative_disagreement'
        
        return {
            'prediction': 1 if final_score >= 0.5 else 0,
            'score': final_score,
            'confidence': final_confidence,
            'method': method,
            'v1_score': v1_score,
            'v2_score': v2_score,
            'metadata': {
                'v1_confidence': v1_confidence,
                'v2_confidence': v2_confidence,
                'agreement': (v1_score >= 0.5) == (v2_score >= 0.5)
            }
        }
    
    def _predict_model(
        self,
        model: torch.nn.Module,
        text: str,
        max_length: int = 512
    ) -> Tuple[float, float]:
        """
        Mache Prediction mit einem Modell.
        
        Args:
            model: PyTorch Modell
            text: Input Text
            max_length: Maximale Textlänge
            
        Returns:
            Tuple von (score, confidence)
            - score: 0.0 (benign) bis 1.0 (malicious)
            - confidence: Confidence des Modells
        """
        # Tokenize
        token_ids = self.tokenizer.encode(text, max_length=max_length)
        input_tensor = torch.tensor([token_ids], dtype=torch.long).to(self.device)
        
        # Predict
        with torch.no_grad():
            output = model(input_tensor)
            probabilities = torch.softmax(output, dim=1)
            
            # Score: Probability für "malicious" (Klasse 1)
            score = probabilities[0][1].item()
            
            # Confidence: Maximale Probability
            confidence = probabilities.max().item()
        
        return score, confidence


def load_v21_hotfix_detector(
    v1_model_path: str,
    v2_model_path: str,
    vocab_size: int = 10000,
    device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
    v2_threshold: float = 0.95,
    v1_fallback_threshold: float = 0.7,
    enable_whitelist: bool = True
) -> V21HotfixDetector:
    """
    Lade V2.1 Hotfix Detector mit V1 und V2 Modellen.
    
    Args:
        v1_model_path: Pfad zu V1 Modell
        v2_model_path: Pfad zu V2 Modell
        vocab_size: Vocabulary Size
        device: Device (cpu/cuda)
        v2_threshold: Threshold für V2 (0.95)
        v1_fallback_threshold: Threshold für V1 Fallback (0.7)
        enable_whitelist: Aktiviert Whitelist
        
    Returns:
        V21HotfixDetector Instanz
    """
    from detectors.orchestrator.infrastructure.training.validate_adversarial_model import (
        load_model, SimpleTokenizer
    )
    
    logger.info("Loading V2.1 Hotfix Detector...")
    logger.info(f"  V1 Model: {v1_model_path}")
    logger.info(f"  V2 Model: {v2_model_path}")
    logger.info(f"  Device: {device}")
    
    # Lade Modelle
    v1_model = load_model(v1_model_path, vocab_size=vocab_size, device=device)
    v2_model = load_model(v2_model_path, vocab_size=vocab_size, device=device)
    
    # Erstelle Tokenizer
    tokenizer = SimpleTokenizer(vocab_size=vocab_size)
    
    # Erstelle Detector
    detector = V21HotfixDetector(
        v1_model=v1_model,
        v2_model=v2_model,
        tokenizer=tokenizer,
        device=device,
        v2_threshold=v2_threshold,
        v1_fallback_threshold=v1_fallback_threshold,
        enable_whitelist=enable_whitelist
    )
    
    logger.info("V2.1 Hotfix Detector loaded successfully")
    
    return detector

