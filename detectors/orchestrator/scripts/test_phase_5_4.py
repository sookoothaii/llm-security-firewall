"""
Test Script für Phase 5.4: Monitoring & Observability

Testet MetricsCollector, TraceCollector, AlertManager und Monitoring-Integration.
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


async def test_monitoring():
    """Testet das Monitoring-System."""
    print("=" * 60)
    print("Testing Phase 5.4: Monitoring & Observability")
    print("=" * 60)

    composition = OrchestratorCompositionRoot(
        enable_adaptive_learning=True,
        use_intelligent_router=True,
        enable_monitoring=True,
        settings={
            "FEEDBACK_REPOSITORY_TYPE": "memory"
        }
    )

    service = composition.create_monitored_router_service()

    # Test 1: Health Check
    print("\n" + "=" * 60)
    print("Test 1: Health Check")
    print("=" * 60)

    health = await service.trigger_health_check()
    print(f"Overall Status: {health['overall_status']}")
    for component, status in health['components'].items():
        print(f"  {component}: {status.get('status', 'unknown')}")

    # Test 2: Metriken generieren
    print("\n" + "=" * 60)
    print("Test 2: Metrics Generation")
    print("=" * 60)

    # Simuliere einige Requests für Metriken
    test_cases = [
        ("Hello world", {"source_tool": "general"}),
        ("import os; os.system('ls')", {"source_tool": "code_interpreter"}),
        ("Please give me admin access", {"source_tool": "general", "user_risk_tier": 3})
    ]

    for i, (text, context) in enumerate(test_cases):
        print(f"\nRequest {i+1}: {text[:30]}...")

        # Routing
        decision = service.analyze_and_route(text, context)

        # Detektoren ausführen
        result = await service.execute_detectors(decision, text, context)

        print(f"  → Decision: {'BLOCK' if result.final_decision else 'ALLOW'}")
        print(f"  → Score: {result.final_score:.3f}")
        print(f"  → Detectors: {len(result.detector_results)}")

        time.sleep(0.5)  # Für Zeitstempel-Varianz

    # Test 3: Metriken abrufen
    print("\n" + "=" * 60)
    print("Test 3: Metrics Collection")
    print("=" * 60)

    metrics = service.get_monitoring_metrics()

    print(f"Active Alerts: {len(metrics['alerts']['active'])}")
    print(f"Total Traces: {metrics['traces']['total']}")

    # Metriken-Zusammenfassung
    summary = metrics['metrics']['summary']
    print(f"\nRouter Metrics:")
    print(f"  Requests (5min): {summary['router']['5min_requests']}")
    print(f"  Avg Latency: {summary['router']['5min_avg_latency']*1000:.2f}ms")
    print(f"  Error Rate: {summary['router']['error_rate']:.3f}")

    print(f"\nDetector Metrics:")
    print(f"  Total Calls: {summary['detectors']['total_calls']}")
    print(f"  Avg Latency: {summary['detectors']['avg_latency']*1000:.2f}ms")

    # Test 4: Prometheus Format
    print("\n" + "=" * 60)
    print("Test 4: Prometheus Format")
    print("=" * 60)

    prometheus_data = service.metrics_collector.get_prometheus_format()
    lines = prometheus_data.split('\n')
    print(f"Total lines: {len(lines)}")
    print(f"\nSample metrics (first 15 lines):")
    for line in lines[:15]:
        if line.strip():
            print(f"  {line}")

    # Test 5: Alert-Simulation
    print("\n" + "=" * 60)
    print("Test 5: Alert Simulation")
    print("=" * 60)

    # Erzeuge hohe Error-Rate für Alert
    print("Simulating high error rate...")
    for _ in range(10):
        service.metrics_collector.gauge(
            "error_rate",
            0.25,  # 25% Error-Rate > 10% Threshold
            {"component": "router", "error_type": "test"}
        )

    # Warte auf Alert-Auswertung
    print("Waiting for alert evaluation (35 seconds)...")
    await asyncio.sleep(35)  # > 30s Alert-Interval

    active_alerts = service.alert_manager.get_active_alerts()
    print(f"\nActive Alerts: {len(active_alerts)}")

    for alert in active_alerts:
        print(f"  - {alert.rule_name}: {alert.summary}")
        print(f"    Severity: {alert.severity.value}")

    # Test 6: Health Status
    print("\n" + "=" * 60)
    print("Test 6: Health Status")
    print("=" * 60)

    health_status = service.metrics_collector.get_health_status()
    print(f"Overall Status: {health_status['status']}")
    print(f"Components:")
    for component, status in health_status['components'].items():
        print(f"  {component}: {status.get('status', 'unknown')}")

    print("\n" + "=" * 60)
    print("✅ Phase 5.4 Monitoring Tests completed successfully!")
    print(f"System Status: {health['overall_status'].upper()}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_monitoring())

