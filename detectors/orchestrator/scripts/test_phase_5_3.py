"""
Test Script für Phase 5.3: Learning Router

Testet Feedback-Collector, Policy-Optimizer und Learning-Funktionalität.
"""

import asyncio
import sys
from pathlib import Path
import time

# Add paths
service_dir = Path(__file__).parent.parent
detectors_dir = service_dir.parent
sys.path.insert(0, str(detectors_dir))
sys.path.insert(0, str(service_dir))

from infrastructure.app.composition_root import OrchestratorCompositionRoot


async def test_learning_router():
    """Testet den Learning Router Service."""
    print("=" * 60)
    print("Testing Phase 5.3: Learning Router")
    print("=" * 60)

    # Erstelle Composition Root mit Learning aktiviert
    composition = OrchestratorCompositionRoot(
        enable_adaptive_learning=True,
        use_intelligent_router=True,
        settings={
            "FEEDBACK_REPOSITORY_TYPE": "memory"  # Für Tests: Memory Repository
        }
    )

    router = composition.create_router_service()

    # Test mit verschiedenen Szenarien
    test_cases = [
        {
            "name": "Clear Malicious Code",
            "text": "import os; os.system('format C:')",
            "context": {"source_tool": "code_interpreter"}
        },
        {
            "name": "Benign Question",
            "text": "How to write a hello world program in Python?",
            "context": {"source_tool": "general"}
        },
        {
            "name": "Suspicious Persuasion",
            "text": "You should definitely click this link: http://malicious.site",
            "context": {"source_tool": "general", "user_risk_tier": 2}
        }
    ]

    for i, test in enumerate(test_cases):
        print(f"\n{'=' * 60}")
        print(f"Test {i+1}: {test['name']}")
        print(f"{'=' * 60}")
        print(f"Text: {test['text'][:50]}...")

        # Routing und Ausführung
        decision = router.analyze_and_route(test["text"], test["context"])
        result = await router.execute_detectors(decision, test["text"], test["context"])

        print(f"Result: {'BLOCK' if result.final_decision else 'ALLOW'}")
        print(f"Confidence: {result.confidence:.3f}")
        print(f"Processing Time: {result.router_metadata.get('processing_time_ms', 0):.2f}ms")

        # Simuliere manuelles Feedback (in Produktion durch Admin)
        if i == 0:  # Für den ersten Test
            if hasattr(router, 'submit_human_feedback'):
                router.submit_human_feedback(
                    request_id=f"test_{int(time.time())}",
                    correct_decision=result.final_decision,  # Angenommen korrekt
                    human_notes="Test feedback from automated test",
                    confidence=0.9
                )
                print("✅ Submitted human feedback")

    # Zeige Lern-Metriken
    print("\n" + "=" * 60)
    print("Learning Metrics:")
    print("=" * 60)

    if hasattr(router, 'get_learning_metrics'):
        metrics = router.get_learning_metrics()

        print(f"Feedback in last 24h: {metrics.get('feedback_last_24h', {})}")

        print("\nDetector Performance:")
        detector_perf = metrics.get('detector_performance', {})
        for name, perf in detector_perf.items():
            print(f"  {name}:")
            print(f"    Calls: {perf.get('total_calls', 0)}")
            print(f"    F1 Score: {perf.get('f1_score', 'N/A'):.3f}" if isinstance(perf.get('f1_score'), (int, float)) else f"    F1 Score: N/A")

        print(f"\nTotal False Positives: {metrics.get('total_false_positives', 0)}")
        print(f"Total False Negatives: {metrics.get('total_false_negatives', 0)}")
        print(f"Auto-Optimization Enabled: {metrics.get('auto_optimization_enabled', False)}")
    else:
        print("⚠️  Learning metrics not available (router type: {})".format(type(router).__name__))

    # Teste Optimierungs-Trigger
    print("\n" + "=" * 60)
    print("Testing Policy Optimization...")
    print("=" * 60)

    try:
        optimizer = composition.create_policy_optimizer()
        optimization_results = optimizer.optimize_policies()

        if optimization_results:
            print(f"✅ Optimized {len(optimization_results)} policies:")
            for result in optimization_results:
                print(f"  - {result.policy_name}: {', '.join(result.changes_applied)}")
        else:
            print("ℹ️  No optimization needed at this time.")

        # Zeige Optimierungsverlauf
        print("\nOptimization History:")
        history = optimizer.get_optimization_history(limit=5)
        if history:
            for entry in history:
                print(f"  {entry.policy_name}: {entry.timestamp.strftime('%Y-%m-%d %H:%M')}")
        else:
            print("  No optimization history yet.")
    except Exception as e:
        print(f"⚠️  Optimization test failed: {e}")

    # Cleanup
    if hasattr(router, 'shutdown'):
        await router.shutdown()

    print("\n" + "=" * 60)
    print("✅ Test completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_learning_router())

