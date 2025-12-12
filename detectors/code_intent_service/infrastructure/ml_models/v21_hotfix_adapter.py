"""
V2.1 Hotfix Adapter - IntentClassifierPort Implementation

Integriert V2.1 Hotfix Detector in Code Intent Service hexagonale Architektur.

Date: 2025-12-12
Status: Production Ready
"""

import logging
import sys
from pathlib import Path
from typing import Optional

# Add project root to path
service_dir = Path(__file__).parent.parent.parent
project_root = service_dir.parent.parent
sys.path.insert(0, str(project_root))

# Import domain port
from domain.services.ports import IntentClassifierPort, ClassificationResult

# Import V2.1 Hotfix Detector
try:
    from detectors.orchestrator.domain.hotfix import load_v21_hotfix_detector
    HAS_V21_HOTFIX = True
except ImportError:
    HAS_V21_HOTFIX = False
    logger.warning("V2.1 Hotfix not available. V21HotfixAdapter will use fallback.")

logger = logging.getLogger(__name__)


class V21HotfixAdapter(IntentClassifierPort):
    """
    Adapter für V2.1 Hotfix Detector.
    
    Implementiert IntentClassifierPort für Integration in Code Intent Service.
    
    Features:
    - V2.1 Hotfix Detection (Threshold 0.95, Whitelist, V1 Fallback)
    - IntentClassifierPort Protocol Compliance
    - Lazy Loading
    - Fallback Support
    """
    
    def __init__(
        self,
        v1_model_path: Optional[str] = None,
        v2_model_path: Optional[str] = None,
        v2_threshold: float = 0.95,
        v1_fallback_threshold: float = 0.7,
        enable_whitelist: bool = True,
        use_gpu: bool = True,
        fallback_classifier: Optional[IntentClassifierPort] = None
    ):
        """
        Initialize V2.1 Hotfix Adapter.
        
        Args:
            v1_model_path: Path to V1 model checkpoint
            v2_model_path: Path to V2 model checkpoint
            v2_threshold: V2 threshold (0.95)
            v1_fallback_threshold: V1 fallback threshold (0.7)
            enable_whitelist: Enable technical questions whitelist
            use_gpu: Use GPU if available
            fallback_classifier: Fallback classifier if V2.1 Hotfix fails
        """
        if not HAS_V21_HOTFIX:
            raise ImportError("V2.1 Hotfix not available. Install required dependencies.")
        
        self.v1_model_path = v1_model_path or "models/code_intent_adversarial_v1/best_model.pt"
        self.v2_model_path = v2_model_path or "models/code_intent_adversarial_v2/best_model.pt"
        self.v2_threshold = v2_threshold
        self.v1_fallback_threshold = v1_fallback_threshold
        self.enable_whitelist = enable_whitelist
        self.use_gpu = use_gpu
        self.fallback_classifier = fallback_classifier
        
        # Lazy loading
        self._detector = None
        self._is_available = False
        
        logger.info("V21HotfixAdapter initialized (lazy loading enabled)")
    
    def _load_detector(self):
        """Lazy load V2.1 Hotfix Detector."""
        if self._detector is None:
            try:
                device = "cuda" if self.use_gpu else "cpu"
                self._detector = load_v21_hotfix_detector(
                    v1_model_path=self.v1_model_path,
                    v2_model_path=self.v2_model_path,
                    device=device,
                    v2_threshold=self.v2_threshold,
                    v1_fallback_threshold=self.v1_fallback_threshold,
                    enable_whitelist=self.enable_whitelist
                )
                self._is_available = True
                logger.info("V2.1 Hotfix Detector loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load V2.1 Hotfix Detector: {e}")
                self._is_available = False
                if self.fallback_classifier:
                    logger.info("Using fallback classifier")
                else:
                    raise
    
    def is_available(self) -> bool:
        """
        Check if V2.1 Hotfix Detector is available.
        
        Returns:
            True if detector is loaded and ready
        """
        if self._detector is None:
            try:
                self._load_detector()
            except Exception:
                return False
        return self._is_available
    
    def classify(self, text: str) -> ClassificationResult:
        """
        Classify text using V2.1 Hotfix Detector.
        
        Args:
            text: Text to classify
            
        Returns:
            ClassificationResult with score, method, confidence
        """
        # Lazy load if needed
        if self._detector is None:
            if not self.is_available():
                # Use fallback if available
                if self.fallback_classifier:
                    logger.warning("V2.1 Hotfix not available, using fallback classifier")
                    return self.fallback_classifier.classify(text)
                else:
                    raise RuntimeError("V2.1 Hotfix Detector not available and no fallback provided")
        
        try:
            # Get prediction from V2.1 Hotfix Detector
            result = self._detector.predict(text)
            
            # Convert to ClassificationResult
            return ClassificationResult(
                score=result['score'],
                method=result['method'],
                confidence=result['confidence'],
                is_execution_request=(result['prediction'] == 1),
                metadata={
                    'v1_score': result.get('v1_score'),
                    'v2_score': result.get('v2_score'),
                    'v2_threshold': self.v2_threshold,
                    'v1_fallback_threshold': self.v1_fallback_threshold,
                    'whitelist_enabled': self.enable_whitelist,
                    **result.get('metadata', {})
                }
            )
        except Exception as e:
            logger.error(f"V2.1 Hotfix classification error: {e}")
            # Use fallback if available
            if self.fallback_classifier:
                logger.warning("V2.1 Hotfix error, using fallback classifier")
                return self.fallback_classifier.classify(text)
            else:
                raise

