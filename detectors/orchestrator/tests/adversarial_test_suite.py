"""
Adversarial Testing Suite for ML Detectors

This module provides testing infrastructure for evaluating the robustness
of ML-based detectors against adversarial attacks.

Usage:
    suite = AdversarialTestSuite(detector_models)
    results = suite.test_detector("content_safety", test_samples, labels)
"""

import numpy as np
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import json
from datetime import datetime

logger = logging.getLogger(__name__)

# Try to import ART, but make it optional for now
try:
    from art.attacks.evasion import FastGradientMethod, ProjectedGradientDescent
    from art.estimators.classification import SklearnClassifier
    ART_AVAILABLE = True
except ImportError:
    ART_AVAILABLE = False
    logger.warning(
        "Adversarial Robustness Toolbox (ART) not installed. "
        "Install with: pip install adversarial-robustness-toolbox"
    )


class AdversarialTestSuite:
    """Test suite for adversarial robustness of ML detectors."""
    
    def __init__(
        self, 
        detector_models: Optional[Dict[str, Any]] = None,
        output_dir: str = "test_results/adversarial"
    ):
        """
        Initialize test suite with detector models.
        
        Args:
            detector_models: Dictionary mapping detector names to model instances
            output_dir: Directory for test results
        """
        self.detector_models = detector_models or {}
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        if ART_AVAILABLE:
            self.attack_methods = self._initialize_attack_methods()
        else:
            self.attack_methods = {}
            logger.warning("ART not available, using basic attack methods only")
    
    def _initialize_attack_methods(self) -> Dict[str, Any]:
        """Initialize various attack methods."""
        if not ART_AVAILABLE:
            return {}
        
        return {
            "fgsm": FastGradientMethod,
            "pgd": ProjectedGradientDescent,
        }
    
    def test_detector(
        self, 
        detector_name: str, 
        test_samples: np.ndarray,
        labels: np.ndarray,
        attack_methods: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Test a detector against adversarial attacks.
        
        Args:
            detector_name: Name of the detector to test
            test_samples: Test samples (text embeddings or features)
            labels: True labels (1 = malicious, 0 = benign)
            attack_methods: List of attack methods to use (None = all)
            
        Returns:
            Dictionary with test results
        """
        if detector_name not in self.detector_models:
            raise ValueError(f"Detector {detector_name} not found")
        
        model = self.detector_models[detector_name]
        results = {
            "detector_name": detector_name,
            "test_samples_count": len(test_samples),
            "attack_results": {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        methods_to_test = attack_methods or list(self.attack_methods.keys())
        
        for attack_name in methods_to_test:
            if attack_name not in self.attack_methods:
                logger.warning(f"Attack method {attack_name} not available")
                continue
            
            try:
                attack_result = self._test_attack(
                    model=model,
                    attack_name=attack_name,
                    test_samples=test_samples,
                    labels=labels
                )
                results["attack_results"][attack_name] = attack_result
                
            except Exception as e:
                logger.error(f"Error testing {attack_name} on {detector_name}: {e}")
                results["attack_results"][attack_name] = {
                    "error": str(e),
                    "success": False
                }
        
        # Calculate overall metrics
        results["summary"] = self._calculate_summary(results["attack_results"])
        
        # Save results
        self._save_results(detector_name, results)
        
        return results
    
    def _test_attack(
        self,
        model: Any,
        attack_name: str,
        test_samples: np.ndarray,
        labels: np.ndarray
    ) -> Dict[str, Any]:
        """Test a specific attack method."""
        if not ART_AVAILABLE:
            # Fallback to basic character-level attacks
            return self._test_basic_attack(model, test_samples, labels)
        
        attack_class = self.attack_methods[attack_name]
        
        # Wrap model in ART estimator if needed
        if not hasattr(model, 'predict'):
            raise ValueError("Model must have predict method")
        
        # Create attack instance
        # Note: This is simplified - actual implementation depends on model type
        attack = attack_class(estimator=model, eps=0.1)
        
        # Generate adversarial examples
        adversarial_samples = attack.generate(x=test_samples)
        
        # Test model on adversarial samples
        original_predictions = model.predict(test_samples)
        adversarial_predictions = model.predict(adversarial_samples)
        
        # Calculate success rate (how many bypassed detection)
        bypass_rate = self._calculate_bypass_rate(
            original_predictions=original_predictions,
            adversarial_predictions=adversarial_predictions,
            labels=labels
        )
        
        return {
            "success": True,
            "bypass_rate": bypass_rate,
            "original_accuracy": self._calculate_accuracy(original_predictions, labels),
            "adversarial_accuracy": self._calculate_accuracy(adversarial_predictions, labels),
            "adversarial_samples_count": len(adversarial_samples),
            "adversarial_samples": adversarial_samples.tolist() if len(adversarial_samples) < 100 else "too_large"
        }
    
    def _test_basic_attack(
        self,
        model: Any,
        test_samples: np.ndarray,
        labels: np.ndarray
    ) -> Dict[str, Any]:
        """Basic character-level attack test (fallback when ART not available)."""
        # Simple character substitution attack
        adversarial_samples = test_samples.copy()
        
        # Add small perturbations (simplified)
        # In practice, this would be more sophisticated
        noise = np.random.normal(0, 0.01, test_samples.shape)
        adversarial_samples = adversarial_samples + noise
        
        original_predictions = model.predict(test_samples)
        adversarial_predictions = model.predict(adversarial_samples)
        
        bypass_rate = self._calculate_bypass_rate(
            original_predictions=original_predictions,
            adversarial_predictions=adversarial_predictions,
            labels=labels
        )
        
        return {
            "success": True,
            "bypass_rate": bypass_rate,
            "attack_type": "basic_character_perturbation",
            "original_accuracy": self._calculate_accuracy(original_predictions, labels),
            "adversarial_accuracy": self._calculate_accuracy(adversarial_predictions, labels)
        }
    
    def _calculate_bypass_rate(
        self,
        original_predictions: np.ndarray,
        adversarial_predictions: np.ndarray,
        labels: np.ndarray
    ) -> float:
        """
        Calculate percentage of successful bypasses.
        
        A bypass occurs when:
        - Original prediction correctly identifies threat (label=1, pred=1)
        - Adversarial prediction fails to identify threat (label=1, pred=0)
        """
        # Find malicious samples that were correctly identified
        correctly_identified = (labels == 1) & (original_predictions == 1)
        
        if not np.any(correctly_identified):
            return 0.0
        
        # Check how many were bypassed
        bypassed = correctly_identified & (adversarial_predictions == 0)
        bypass_rate = np.sum(bypassed) / np.sum(correctly_identified)
        
        return float(bypass_rate)
    
    def _calculate_accuracy(
        self,
        predictions: np.ndarray,
        labels: np.ndarray
    ) -> float:
        """Calculate prediction accuracy."""
        correct = np.sum(predictions == labels)
        total = len(labels)
        return float(correct / total) if total > 0 else 0.0
    
    def _calculate_summary(
        self,
        attack_results: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate summary statistics from attack results."""
        successful_attacks = [
            r for r in attack_results.values() 
            if r.get("success", False)
        ]
        
        if not successful_attacks:
            return {
                "total_attacks": len(attack_results),
                "successful_attacks": 0,
                "average_bypass_rate": 0.0,
                "max_bypass_rate": 0.0
            }
        
        bypass_rates = [r.get("bypass_rate", 0.0) for r in successful_attacks]
        
        return {
            "total_attacks": len(attack_results),
            "successful_attacks": len(successful_attacks),
            "average_bypass_rate": float(np.mean(bypass_rates)),
            "max_bypass_rate": float(np.max(bypass_rates)),
            "min_bypass_rate": float(np.min(bypass_rates))
        }
    
    def _save_results(
        self,
        detector_name: str,
        results: Dict[str, Any]
    ) -> None:
        """Save test results to file."""
        filename = self.output_dir / f"adversarial_test_{detector_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Saved adversarial test results to {filename}")
    
    def generate_adversarial_dataset(
        self,
        detector_name: str,
        base_samples: np.ndarray,
        labels: np.ndarray,
        attack_method: str = "pgd",
        max_samples: int = 1000
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate adversarial examples for training.
        
        Args:
            detector_name: Name of detector
            base_samples: Base training samples
            labels: True labels
            attack_method: Attack method to use
            max_samples: Maximum number of samples to generate
            
        Returns:
            Tuple of (adversarial_samples, adversarial_labels)
        """
        if detector_name not in self.detector_models:
            raise ValueError(f"Detector {detector_name} not found")
        
        model = self.detector_models[detector_name]
        
        # Limit samples if needed
        if len(base_samples) > max_samples:
            indices = np.random.choice(len(base_samples), max_samples, replace=False)
            base_samples = base_samples[indices]
            labels = labels[indices]
        
        # Generate adversarial examples
        if ART_AVAILABLE and attack_method in self.attack_methods:
            attack_class = self.attack_methods[attack_method]
            attack = attack_class(estimator=model, eps=0.1)
            adversarial_samples = attack.generate(x=base_samples)
        else:
            # Fallback to basic perturbation
            noise = np.random.normal(0, 0.01, base_samples.shape)
            adversarial_samples = base_samples + noise
        
        # Use same labels (adversarial examples should maintain original labels)
        adversarial_labels = labels.copy()
        
        return adversarial_samples, adversarial_labels


def main():
    """Example usage of AdversarialTestSuite."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Run adversarial robustness tests")
    parser.add_argument("--detector", type=str, required=True, help="Detector name to test")
    parser.add_argument("--model-path", type=str, help="Path to model file")
    parser.add_argument("--test-data", type=str, required=True, help="Path to test data")
    parser.add_argument("--output-dir", type=str, default="test_results/adversarial", help="Output directory")
    
    args = parser.parse_args()
    
    # Load model and test data (implementation depends on your setup)
    # detector_models = {args.detector: load_model(args.model_path)}
    # test_samples, labels = load_test_data(args.test_data)
    
    # suite = AdversarialTestSuite(detector_models, args.output_dir)
    # results = suite.test_detector(args.detector, test_samples, labels)
    
    # print(f"Test results: {results['summary']}")
    
    print("Adversarial test suite - implementation pending model loading")


if __name__ == "__main__":
    main()

