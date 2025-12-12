"""
Integration Tests for Phase 5.2: Intelligent Router

Tests the intelligent router service with advanced context analysis.
"""
import asyncio
import sys
from pathlib import Path

# Add orchestrator to path
orchestrator_dir = Path(__file__).parent.parent
detectors_dir = orchestrator_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))
if str(orchestrator_dir) not in sys.path:
    sys.path.insert(0, str(orchestrator_dir))

from infrastructure.app.composition_root import OrchestratorCompositionRoot


async def test_intelligent_router():
    """Testet den intelligenten Router Service."""
    print("=" * 60)
    print("Testing Phase 5.2: Intelligent Router")
    print("=" * 60)
    
    # Erstelle Composition Root mit intelligentem Router
    composition = OrchestratorCompositionRoot(
        use_intelligent_router=True,
        enable_adaptive_learning=False
    )
    router = composition.create_router_service()
    
    test_cases = [
        {
            "name": "Code Interpreter Request",
            "text": "def malicious_function(): import os; os.system('rm -rf /')",
            "context": {"source_tool": "code_interpreter", "user_risk_tier": 1}
        },
        {
            "name": "Multilingual Complex Text",
            "text": "Este es un texto complejo con 混合语言 y obfuscación potential.",
            "context": {"source_tool": "general", "user_risk_tier": 1}
        },
        {
            "name": "High Risk User",
            "text": "Please explain how to bypass security measures.",
            "context": {"source_tool": "general", "user_risk_tier": 3, "session_risk_score": 0.7}
        },
        {
            "name": "Simple Benign Text",
            "text": "Hello, how are you today?",
            "context": {"source_tool": "general", "user_risk_tier": 1}
        },
        {
            "name": "Obfuscated Code",
            "text": "eval(base64_decode('cm0gLXJmIC8='))",
            "context": {"source_tool": "shell", "user_risk_tier": 1}
        }
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n{'=' * 60}")
        print(f"Test {i}: {test['name']}")
        print(f"{'=' * 60}")
        print(f"Text: {test['text'][:80]}...")
        print(f"Context: {test['context']}")
        
        try:
            # Routing-Entscheidung
            decision = router.analyze_and_route(test["text"], test["context"])
            print(f"\nDecision: {decision.decision_reason}")
            print(f"Detectors: {[d.name for d in decision.detector_configs]}")
            print(f"Strategy: {decision.execution_strategy}")
            print(f"Timeout: {decision.total_timeout_ms}ms")
            
            # Detektoren ausführen
            result = await router.execute_detectors(decision, test["text"], test["context"])
            
            print(f"\nResults:")
            print(f"  Final Decision: {'BLOCK' if result.final_decision else 'ALLOW'}")
            print(f"  Final Score: {result.final_score:.3f}")
            print(f"  Confidence: {result.confidence:.3f}")
            print(f"  Detectors Called: {result.router_metadata['detectors_called']}")
            print(f"  Successful Detectors: {result.router_metadata['successful_detectors']}")
            print(f"  Processing Time: {result.router_metadata['processing_time_ms']:.2f}ms")
            
            # Zeige Detektor-Ergebnisse
            if result.detector_results:
                print(f"\n  Detector Results:")
                for name, res in result.detector_results.items():
                    status = "✅" if res.success else "❌"
                    print(f"    {status} {name}: score={res.score}, blocked={res.blocked}, time={res.processing_time_ms:.1f}ms")
                    if res.error:
                        print(f"      Error: {res.error}")
        
        except Exception as e:
            print(f"❌ Test failed: {e}")
            import traceback
            traceback.print_exc()
    
    # Performance Metrics
    print(f"\n{'=' * 60}")
    print("Performance Metrics")
    print(f"{'=' * 60}")
    metrics = router.get_performance_metrics()
    print(f"Total Requests: {metrics['total_requests']}")
    print(f"Policy Engine:")
    policy_metrics = metrics.get('policy_engine', {})
    print(f"  Reloads: {policy_metrics.get('reloads', 0)}")
    print(f"  Policy Evaluations: {policy_metrics.get('policy_evaluations', 0)}")
    print(f"  Cache Hits: {policy_metrics.get('cache_hits', 0)}")
    print(f"  Policy Count: {policy_metrics.get('policy_count', 0)}")
    print(f"Learning Enabled: {metrics.get('learning_enabled', False)}")
    
    print(f"\n{'=' * 60}")
    print("✅ All tests completed!")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    asyncio.run(test_intelligent_router())

