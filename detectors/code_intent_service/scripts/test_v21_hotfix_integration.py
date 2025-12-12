"""
Test V2.1 Hotfix Integration in Code Intent Service

Tests the integration of V2.1 Hotfix into the hexagonal architecture.
"""

import sys
from pathlib import Path

# Add service directory to path (for relative imports)
service_dir = Path(__file__).parent.parent
project_root = service_dir.parent.parent
sys.path.insert(0, str(service_dir))
sys.path.insert(0, str(project_root))

# Import with relative paths
from infrastructure.app.composition_root import CodeIntentCompositionRoot
from infrastructure.config.settings import DetectionSettings


def test_v21_hotfix_integration():
    """Test V2.1 Hotfix integration."""
    print("="*80)
    print("V2.1 HOTFIX INTEGRATION TEST")
    print("="*80)
    
    # Create settings with V2.1 Hotfix enabled
    settings = DetectionSettings(
        use_v21_hotfix=True,
        use_quantum_model=False,  # Disable Quantum to test V2.1
        use_codebert=False,  # Disable CodeBERT to test V2.1
        v1_model_path=project_root / "models" / "code_intent_adversarial_v1" / "best_model.pt",
        v2_model_path=project_root / "models" / "code_intent_adversarial_v2" / "best_model.pt",
        v21_threshold=0.95,
        v21_fallback_threshold=0.7,
        v21_whitelist_enabled=True
    )
    
    print(f"\nSettings:")
    print(f"  use_v21_hotfix: {settings.use_v21_hotfix}")
    print(f"  v1_model_path: {settings.v1_model_path}")
    print(f"  v2_model_path: {settings.v2_model_path}")
    print(f"  v21_threshold: {settings.v21_threshold}")
    
    # Create composition root
    print(f"\nCreating Composition Root...")
    root = CodeIntentCompositionRoot(settings)
    
    # Create intent classifier
    print(f"\nCreating Intent Classifier...")
    classifier = root.create_intent_classifier()
    
    print(f"\nClassifier Type: {type(classifier).__name__}")
    print(f"Available: {classifier.is_available()}")
    
    if not classifier.is_available():
        print("❌ V2.1 Hotfix not available!")
        return False
    
    # Test cases
    test_cases = [
        # (text, expected_method, expected_execution)
        ("What is SQL?", "v2_whitelist_override", False),
        ("How do I use Docker?", "v2_whitelist_override", False),
        ("rm -rf /", "v2_high_confidence", True),
        ("python -c 'import os; os.system(\"rm -rf /\")'", "v2_high_confidence", True),
        ("Show me how to write a for loop", "v2_whitelist_override", False),
    ]
    
    print(f"\n{'='*80}")
    print("TESTING CLASSIFICATION")
    print(f"{'='*80}")
    
    passed = 0
    failed = 0
    
    for text, expected_method, expected_execution in test_cases:
        try:
            result = classifier.classify(text)
            
            method_match = result.method == expected_method or expected_method in result.method
            execution_match = result.is_execution_request == expected_execution
            
            if method_match and execution_match:
                status = "✅ PASS"
                passed += 1
            else:
                status = "❌ FAIL"
                failed += 1
            
            print(f"\n{status} - {text[:50]}...")
            print(f"  Method: {result.method} (expected: {expected_method})")
            print(f"  Execution: {result.is_execution_request} (expected: {expected_execution})")
            print(f"  Score: {result.score:.3f}, Confidence: {result.confidence:.3f}")
            if result.metadata:
                print(f"  Metadata: {result.metadata}")
        except Exception as e:
            print(f"\n❌ ERROR - {text[:50]}...")
            print(f"  Error: {e}")
            failed += 1
    
    print(f"\n{'='*80}")
    print(f"RESULTS: {passed} passed, {failed} failed")
    print(f"{'='*80}")
    
    return failed == 0


if __name__ == "__main__":
    success = test_v21_hotfix_integration()
    sys.exit(0 if success else 1)

