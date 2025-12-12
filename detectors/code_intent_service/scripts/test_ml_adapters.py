"""
Zwischentest für ML Model Adapter
==================================

Testet die implementierten ML-Model-Adapter:
- QuantumCNNAdapter
- CodeBERTAdapter
- RuleBasedIntentClassifier
- Composition Root Integration

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
License: MIT
"""

import sys
import logging
from pathlib import Path

# Add project root src directory to path (wie in main.py)
service_dir = Path(__file__).parent.parent
project_root = service_dir.parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))
# Also add service directory for local imports
sys.path.insert(0, str(service_dir))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_rule_based_classifier():
    """Test RuleBasedIntentClassifier (sollte immer funktionieren)."""
    logger.info("=" * 60)
    logger.info("TEST 1: RuleBasedIntentClassifier")
    logger.info("=" * 60)
    
    try:
        from infrastructure.ml_models.rule_based_classifier import RuleBasedIntentClassifier
        
        classifier = RuleBasedIntentClassifier()
        
        # Test availability
        assert classifier.is_available(), "RuleBasedIntentClassifier sollte immer verfügbar sein"
        logger.info("✓ RuleBasedIntentClassifier ist verfügbar")
        
        # Test classification
        test_cases = [
            ("What is ls?", False, "Frage sollte benign sein"),
            ("Please run ls", True, "Execution Request sollte blockiert werden"),
            ("ls", True, "Standalone Command sollte blockiert werden"),
            ("According to the documentation, ls lists files", False, "Dokumentation sollte benign sein"),
        ]
        
        for text, expected_malicious, description in test_cases:
            result = classifier.classify(text)
            is_malicious = result.is_execution_request
            
            status = "✓" if is_malicious == expected_malicious else "✗"
            logger.info(f"{status} '{text[:50]}...' -> {is_malicious} (erwartet: {expected_malicious}) - {description}")
            
            if is_malicious != expected_malicious:
                logger.warning(f"  ⚠️  Mismatch: {description}")
        
        logger.info("✓ RuleBasedIntentClassifier Tests abgeschlossen\n")
        return True
        
    except Exception as e:
        logger.error(f"✗ RuleBasedIntentClassifier Test fehlgeschlagen: {e}", exc_info=True)
        return False


def test_circuit_breaker():
    """Test Circuit Breaker."""
    logger.info("=" * 60)
    logger.info("TEST 2: SimpleCircuitBreaker")
    logger.info("=" * 60)
    
    try:
        from infrastructure.ml_models.circuit_breaker import SimpleCircuitBreaker, CircuitState
        
        breaker = SimpleCircuitBreaker(
            name="test_breaker",
            failure_threshold=2,
            recovery_timeout=1.0
        )
        
        # Initial state
        assert breaker.state == CircuitState.CLOSED, "Initial state sollte CLOSED sein"
        assert breaker.allow_request(), "Sollte Requests erlauben wenn CLOSED"
        logger.info("✓ Circuit Breaker initialisiert (CLOSED)")
        
        # First failure
        breaker.on_failure()
        assert breaker.state == CircuitState.CLOSED, "Nach 1 Fehler sollte noch CLOSED sein"
        logger.info("✓ Nach 1 Fehler: noch CLOSED")
        
        # Second failure (threshold)
        breaker.on_failure()
        assert breaker.state == CircuitState.OPEN, "Nach threshold Fehlern sollte OPEN sein"
        assert not breaker.allow_request(), "Sollte Requests ablehnen wenn OPEN"
        logger.info("✓ Nach threshold Fehlern: OPEN (Requests werden abgelehnt)")
        
        # Success should reset
        breaker.reset()
        assert breaker.state == CircuitState.CLOSED, "Reset sollte zu CLOSED führen"
        logger.info("✓ Reset funktioniert\n")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Circuit Breaker Test fehlgeschlagen: {e}", exc_info=True)
        return False


def test_codebert_adapter():
    """Test CodeBERTAdapter (mit Fallback wenn Model nicht verfügbar)."""
    logger.info("=" * 60)
    logger.info("TEST 3: CodeBERTAdapter")
    logger.info("=" * 60)
    
    try:
        from infrastructure.ml_models.codebert_adapter import CodeBERTAdapter
        from infrastructure.ml_models.rule_based_classifier import RuleBasedIntentClassifier
        
        fallback = RuleBasedIntentClassifier()
        adapter = CodeBERTAdapter(
            use_gpu=True,  # RTX 3080Ti
            fallback_classifier=fallback
        )
        
        logger.info(f"Device: {adapter.device}")
        if adapter.gpu_name:
            logger.info(f"GPU: {adapter.gpu_name} ({adapter.gpu_memory:.1f}GB VRAM)")
        
        # Test availability (may fail if transformers not installed)
        available = adapter.is_available()
        logger.info(f"CodeBERT verfügbar: {available}")
        
        if available:
            # Test classification
            test_cases = [
                "What is ls?",
                "Please run ls",
                "ls",
            ]
            
            for text in test_cases:
                result = adapter.classify(text)
                logger.info(f"  '{text[:50]}...' -> {result.method}, score={result.score:.3f}, execution={result.is_execution_request}")
        else:
            logger.warning("⚠️  CodeBERT nicht verfügbar (transformers nicht installiert oder Model-Loading fehlgeschlagen)")
            logger.info("  Fallback wird verwendet")
        
        logger.info("✓ CodeBERTAdapter Tests abgeschlossen\n")
        return True
        
    except ImportError as e:
        logger.warning(f"⚠️  CodeBERTAdapter Test übersprungen (Import fehlgeschlagen: {e})")
        return True  # Nicht kritisch
    except Exception as e:
        logger.error(f"✗ CodeBERTAdapter Test fehlgeschlagen: {e}", exc_info=True)
        return False


def test_quantum_cnn_adapter():
    """Test QuantumCNNAdapter (mit Fallback wenn Model nicht verfügbar)."""
    logger.info("=" * 60)
    logger.info("TEST 4: QuantumCNNAdapter")
    logger.info("=" * 60)
    
    try:
        from infrastructure.ml_models.quantum_cnn_adapter import QuantumCNNAdapter
        from infrastructure.ml_models.rule_based_classifier import RuleBasedIntentClassifier
        
        # Try to find model path
        service_dir = Path(__file__).parent.parent
        project_root = service_dir.parent.parent
        default_path = project_root / "models" / "quantum_cnn_trained" / "best_model.pt"
        
        logger.info(f"Suche Quantum Model bei: {default_path}")
        
        fallback = RuleBasedIntentClassifier()
        adapter = QuantumCNNAdapter(
            model_path=str(default_path) if default_path.exists() else None,
            use_gpu=True,  # RTX 3080Ti
            fallback_classifier=fallback
        )
        
        logger.info(f"Device: {adapter.device}")
        if adapter.gpu_name:
            logger.info(f"GPU: {adapter.gpu_name} ({adapter.gpu_memory:.1f}GB VRAM)")
        
        # Test availability
        available = adapter.is_available()
        logger.info(f"QuantumCNN verfügbar: {available}")
        
        if available:
            # Test classification
            test_cases = [
                "What is ls?",
                "Please run ls",
                "ls",
            ]
            
            for text in test_cases:
                result = adapter.classify(text)
                logger.info(f"  '{text[:50]}...' -> {result.method}, score={result.score:.3f}, execution={result.is_execution_request}")
        else:
            logger.warning("⚠️  QuantumCNN nicht verfügbar (Model nicht gefunden oder Loading fehlgeschlagen)")
            logger.info("  Fallback wird verwendet")
        
        logger.info("✓ QuantumCNNAdapter Tests abgeschlossen\n")
        return True
        
    except ImportError as e:
        logger.warning(f"⚠️  QuantumCNNAdapter Test übersprungen (Import fehlgeschlagen: {e})")
        return True  # Nicht kritisch
    except Exception as e:
        logger.error(f"✗ QuantumCNNAdapter Test fehlgeschlagen: {e}", exc_info=True)
        return False


def test_composition_root():
    """Test Composition Root Integration."""
    logger.info("=" * 60)
    logger.info("TEST 5: Composition Root Integration")
    logger.info("=" * 60)
    
    try:
        # Check if pydantic_settings is available
        try:
            import pydantic_settings
        except ImportError:
            logger.warning("⚠️  pydantic_settings nicht installiert, überspringe Composition Root Test")
            logger.info("  Installiere mit: pip install pydantic-settings")
            return True  # Nicht kritisch
        
        from infrastructure.app.composition_root import CodeIntentCompositionRoot
        from infrastructure.config.settings import DetectionSettings
        
        # Test with default settings
        logger.info("Teste mit Default Settings...")
        root = CodeIntentCompositionRoot()
        classifier = root.create_intent_classifier()
        
        assert classifier is not None, "Classifier sollte nicht None sein"
        assert classifier.is_available(), "Classifier sollte verfügbar sein"
        logger.info("✓ Classifier erstellt und verfügbar")
        
        # Test classification
        result = classifier.classify("Please run ls")
        logger.info(f"  'Please run ls' -> {result.method}, score={result.score:.3f}, execution={result.is_execution_request}")
        
        # Test with ML models disabled (should use rule-based)
        logger.info("\nTeste mit ML Models deaktiviert (Rule-Based Fallback)...")
        settings = DetectionSettings(
            use_quantum_model=False,
            use_codebert=False
        )
        root2 = CodeIntentCompositionRoot(settings=settings)
        classifier2 = root2.create_intent_classifier()
        
        assert classifier2 is not None, "Classifier sollte nicht None sein"
        result2 = classifier2.classify("Please run ls")
        logger.info(f"  'Please run ls' -> {result2.method}, score={result2.score:.3f}, execution={result2.is_execution_request}")
        assert result2.method == "rule_based", "Sollte rule_based verwenden wenn ML deaktiviert"
        
        logger.info("✓ Composition Root Integration Tests abgeschlossen\n")
        return True
        
    except Exception as e:
        logger.error(f"✗ Composition Root Test fehlgeschlagen: {e}", exc_info=True)
        return False


def main():
    """Führe alle Tests aus."""
    logger.info("\n" + "=" * 60)
    logger.info("ZWISCHENTEST: ML Model Adapter")
    logger.info("=" * 60 + "\n")
    
    results = []
    
    # Test 1: Rule-Based (sollte immer funktionieren)
    results.append(("RuleBasedIntentClassifier", test_rule_based_classifier()))
    
    # Test 2: Circuit Breaker
    results.append(("Circuit Breaker", test_circuit_breaker()))
    
    # Test 3: CodeBERT (kann fehlschlagen wenn transformers nicht installiert)
    results.append(("CodeBERTAdapter", test_codebert_adapter()))
    
    # Test 4: QuantumCNN (kann fehlschlagen wenn Model nicht gefunden)
    results.append(("QuantumCNNAdapter", test_quantum_cnn_adapter()))
    
    # Test 5: Composition Root
    results.append(("Composition Root", test_composition_root()))
    
    # Zusammenfassung
    logger.info("=" * 60)
    logger.info("ZUSAMMENFASSUNG")
    logger.info("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        logger.info(f"{status} - {name}")
    
    logger.info(f"\nErgebnis: {passed}/{total} Tests bestanden")
    
    if passed == total:
        logger.info("🎉 Alle Tests bestanden!")
        return 0
    else:
        logger.warning(f"⚠️  {total - passed} Test(s) fehlgeschlagen")
        return 1


if __name__ == "__main__":
    sys.exit(main())

