"""
V2.1 Enhanced - Mit Whitelist-Modul

Kombiniert V2.1 Hotfix mit Whitelist-Modul für weitere FPR-Reduktion.

Architecture:
- V2.1 Hotfix als Haupt-Detector
- Whitelist-Modul als Override für False Positives
- Safety-first: Nur bei hoher Confidence wird überschrieben
"""

import logging
from pathlib import Path
from typing import Tuple, Dict, Any, Optional
import torch

logger = logging.getLogger(__name__)


class V21Enhanced:
    """
    Enhanced V2.1 Hotfix mit Whitelist-Modul.
    
    Strategie:
    1. V2.1 Hotfix macht Hauptentscheidung
    2. Wenn V2.1 blockiert, prüfe Whitelist-Modul
    3. Wenn Whitelist-Modul sehr sicher (score > 0.9), override zu benign
    4. Sonst V2.1 Entscheidung beibehalten
    """
    
    def __init__(
        self,
        v1_model_path: Path,
        v2_model_path: Path,
        whitelist_model_path: Optional[Path] = None,
        device: str = 'cpu',
        v2_threshold: float = 0.95,
        v1_fallback_threshold: float = 0.7,
        whitelist_threshold: float = 0.9,
        whitelist_enabled: bool = True
    ):
        """
        Initialize V2.1 Enhanced.
        
        Args:
            v1_model_path: Path to V1 model
            v2_model_path: Path to V2 model
            whitelist_model_path: Path to Whitelist Classifier model
            device: Device for inference
            v2_threshold: V2 confidence threshold
            v1_fallback_threshold: V1 fallback threshold
            whitelist_threshold: Whitelist confidence threshold for override
            whitelist_enabled: Enable whitelist override
        """
        # Load V2.1 Hotfix
        from detectors.orchestrator.domain.hotfix.v2_1_hotfix_detector import load_v21_hotfix_detector
        
        self.v2_1 = load_v21_hotfix_detector(
            v1_model_path=v1_model_path,
            v2_model_path=v2_model_path,
            device=device,
            v2_threshold=v2_threshold,
            v1_fallback_threshold=v1_fallback_threshold,
            enable_whitelist=True  # V2.1's own whitelist
        )
        
        # Load Whitelist Module (optional)
        self.whitelist_classifier = None
        self.whitelist_enabled = whitelist_enabled
        self.whitelist_threshold = whitelist_threshold
        
        if whitelist_enabled and whitelist_model_path and whitelist_model_path.exists():
            try:
                from detectors.orchestrator.infrastructure.training.models.whitelist_classifier import (
                    create_whitelist_classifier
                )
                
                self.whitelist_classifier = create_whitelist_classifier(
                    base_model_name="distilbert-base-uncased",
                    dropout=0.1,
                    freeze_encoder=True,
                    device=device
                )
                
                # Load trained weights
                checkpoint = torch.load(whitelist_model_path, map_location=device, weights_only=False)
                self.whitelist_classifier.load_state_dict(checkpoint['model_state_dict'])
                self.whitelist_classifier.eval()
                
                logger.info(f"✓ Whitelist Classifier loaded from: {whitelist_model_path}")
            except Exception as e:
                logger.warning(f"Could not load Whitelist Classifier: {e}")
                logger.warning("Continuing without Whitelist Module")
                self.whitelist_enabled = False
        else:
            if whitelist_enabled:
                logger.warning("Whitelist Module not available, continuing without it")
            self.whitelist_enabled = False
        
        logger.info("V2.1 Enhanced initialized:")
        logger.info(f"  V2.1 Hotfix: ✓")
        logger.info(f"  Whitelist Module: {'✓' if self.whitelist_enabled else '✗'}")
        logger.info(f"  Whitelist Threshold: {self.whitelist_threshold}")
    
    def predict(self, text: str) -> Tuple[float, float, Dict[str, Any]]:
        """
        Predict with V2.1 Enhanced.
        
        Args:
            text: Text to analyze
            
        Returns:
            Tuple of (score, confidence, metadata)
        """
        # Step 1: V2.1 Hotfix Entscheidung
        v2_1_result = self.v2_1.predict(text)
        
        # Handle dict return from V2.1
        if isinstance(v2_1_result, dict):
            v2_1_score = v2_1_result.get('score', 0.0)
            v2_1_conf = v2_1_result.get('confidence', 0.0)
            v2_1_metadata = v2_1_result
            is_malicious_v2_1 = v2_1_result.get('prediction', 0) == 1
        else:
            # Tuple return (shouldn't happen, but handle it)
            v2_1_score, v2_1_conf, v2_1_metadata = v2_1_result
            is_malicious_v2_1 = v2_1_score >= 0.5
        
        # Step 2: Wenn V2.1 blockiert, prüfe Whitelist-Modul
        if is_malicious_v2_1 and self.whitelist_enabled and self.whitelist_classifier:
            try:
                whitelist_pred = self.whitelist_classifier.predict(
                    [text],
                    threshold=self.whitelist_threshold
                )[0]
                
                whitelist_score = whitelist_pred['whitelist_probability']
                is_whitelist = whitelist_pred['is_whitelist']
                
                # Step 3: Whitelist-Override (nur bei hoher Confidence)
                if is_whitelist and whitelist_score >= self.whitelist_threshold:
                    # Override zu benign
                    return (
                        0.0,  # Benign score
                        whitelist_score,  # Whitelist confidence
                        {
                            'method': 'v2_1_enhanced_whitelist_override',
                            'is_malicious': False,
                            'v2_1_score': v2_1_score,
                            'v2_1_method': v2_1_metadata.get('method', 'unknown'),
                            'whitelist_score': whitelist_score,
                            'whitelist_override': True,
                            'original_decision': 'malicious',
                            'override_reason': 'high_whitelist_confidence'
                        }
                    )
                else:
                    # Whitelist-Modul ist unsicher → V2.1 Entscheidung beibehalten
                    return (
                        v2_1_score,
                        v2_1_conf,
                        {
                            **v2_1_metadata,
                            'whitelist_checked': True,
                            'whitelist_score': whitelist_score,
                            'whitelist_override': False,
                            'whitelist_reason': 'low_confidence' if not is_whitelist else 'below_threshold'
                        }
                    )
            except Exception as e:
                logger.warning(f"Whitelist Module error: {e}, using V2.1 decision")
                return (v2_1_score, v2_1_conf, {**v2_1_metadata, 'whitelist_error': str(e)})
        
        # Step 4: V2.1 Entscheidung (wenn nicht blockiert oder Whitelist-Modul nicht aktiv)
        return (
            v2_1_score,
            v2_1_conf,
            {
                **v2_1_metadata,
                'whitelist_checked': self.whitelist_enabled and is_malicious_v2_1,
                'whitelist_override': False
            }
        )


def load_v21_enhanced(
    v1_model_path: str,
    v2_model_path: str,
    whitelist_model_path: Optional[str] = None,
    device: str = 'cpu',
    v2_threshold: float = 0.95,
    v1_fallback_threshold: float = 0.7,
    whitelist_threshold: float = 0.9,
    whitelist_enabled: bool = True
) -> V21Enhanced:
    """
    Factory function to load V2.1 Enhanced.
    
    Args:
        v1_model_path: Path to V1 model
        v2_model_path: Path to V2 model
        whitelist_model_path: Path to Whitelist Classifier (optional)
        device: Device for inference
        v2_threshold: V2 confidence threshold
        v1_fallback_threshold: V1 fallback threshold
        whitelist_threshold: Whitelist confidence threshold
        whitelist_enabled: Enable whitelist override
        
    Returns:
        V21Enhanced instance
    """
    return V21Enhanced(
        v1_model_path=Path(v1_model_path),
        v2_model_path=Path(v2_model_path),
        whitelist_model_path=Path(whitelist_model_path) if whitelist_model_path else None,
        device=device,
        v2_threshold=v2_threshold,
        v1_fallback_threshold=v1_fallback_threshold,
        whitelist_threshold=whitelist_threshold,
        whitelist_enabled=whitelist_enabled
    )

