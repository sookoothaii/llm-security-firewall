"""
Integration Test: AdversarialInputDetector via IntelligentRouterService

Tests the complete integration of AdversarialInputDetector in the router flow,
including detection, blocking, performance, and false positive handling.
"""

import sys
import json
import time
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from detectors.orchestrator.domain.ports import RoutingDecision, DetectorRouterPort


class RouterIntegrationTest:
    """Integration test for AdversarialInputDetector in router flow."""
    
    def __init__(self):
        """Initialize test suite."""
        self.results = {
            "detection_results": [],
            "performance_metrics": [],
            "false_positives": [],
            "summary": {}
        }
        
    def load_baseline_bypasses(self) -> List[str]:
        """Load baseline bypass samples."""
        bypass_samples = []
        results_dir = project_root / "test_results" / "adversarial"
        
        for results_file in results_dir.glob("baseline_*.json"):
            if "retest" in str(results_file):
                continue
                
            with open(results_file, 'r', encoding='utf-8') as f:
                results = json.load(f)
                
                for test_result in results.get("test_results", []):
                    if test_result.get("bypass", False) and test_result.get("label") == 1:
                        sample = test_result.get("sample", "")
                        if sample and sample not in bypass_samples:
                            bypass_samples.append(sample)
        
        return bypass_samples
    
    def load_benign_samples(self, count: int = 100) -> List[str]:
        """Generate benign test samples."""
        benign_samples = [
            "Hello, how are you?",
            "What is the weather today?",
            "Can you help me with Python?",
            "Explain quantum computing",
            "How do I sort a list in Python?",
            "What is machine learning?",
            "Tell me about artificial intelligence",
            "How does a neural network work?",
            "What is the capital of France?",
            "Explain the difference between AI and ML",
            "How can I learn programming?",
            "What are the best practices for code reviews?",
            "Can you explain REST APIs?",
            "What is the difference between SQL and NoSQL?",
            "How do I deploy a web application?",
        ]
        
        # Repeat to reach count
        samples = []
        for i in range(count):
            samples.append(benign_samples[i % len(benign_samples)])
        
        return samples
    
    def create_router_service(self) -> DetectorRouterPort:
        """Create router service instance for testing."""
        from detectors.orchestrator.application.intelligent_router_service import IntelligentRouterService
        from detectors.orchestrator.infrastructure.dynamic_policy_engine import DynamicPolicyEngine
        
        # Create a temporary policy config file for testing
        import tempfile
        import os
        
        # Create minimal policy config
        policy_config = """
policies:
  - name: test_policy
    conditions:
      - field: source_tool
        operator: equals
        value: general
    detectors:
      - name: content_safety
        mode: required
        timeout_ms: 1000
"""
        
        # Write to temp file
        temp_dir = project_root / "test_results" / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        policy_file = temp_dir / "test_policy.yaml"
        with open(policy_file, 'w') as f:
            f.write(policy_config)
        
        # Create policy engine
        policy_engine = DynamicPolicyEngine(
            config_path=str(policy_file),
            watch_for_changes=False
        )
        
        # Detector endpoints (not actually used in routing test, but required)
        detector_endpoints = {
            "content_safety": "http://localhost:8003",
            "code_intent": "http://localhost:8000",
            "persuasion": "http://localhost:8002",
        }
        
        return IntelligentRouterService(
            policy_engine=policy_engine,
            detector_endpoints=detector_endpoints,
            enable_adaptive_learning=False
        )
    
    def test_detection(self, router_service: DetectorRouterPort, text: str, is_malicious: bool) -> Dict[str, Any]:
        """Test detection for a single sample."""
        start_time = time.time()
        
        context = {
            "source_tool": "general",
            "user_risk_tier": 1,  # Numeric: 1=standard, 2=medium, 3=high
            "session_risk_score": 0.0
        }
        
        # Call router
        routing_decision = router_service.analyze_and_route(text, context)
        
        processing_time_ms = (time.time() - start_time) * 1000
        
        # Extract metadata
        router_metadata = routing_decision.router_metadata or {}
        adversarial_detected = router_metadata.get("adversarial_detection", False)
        adversarial_score = router_metadata.get("adversarial_score", 0.0)
        adversarial_metadata = router_metadata.get("adversarial_metadata", {})
        
        # Check if blocked
        is_blocked = (
            routing_decision.execution_strategy == "immediate_block" or
            adversarial_detected
        )
        
        return {
            "text": text[:70] + "..." if len(text) > 70 else text,
            "is_malicious": is_malicious,
            "adversarial_detected": adversarial_detected,
            "adversarial_score": adversarial_score,
            "is_blocked": is_blocked,
            "execution_strategy": routing_decision.execution_strategy,
            "decision_reason": routing_decision.decision_reason,
            "processing_time_ms": processing_time_ms,
            "adversarial_metadata": adversarial_metadata,
            "correct": (is_malicious and is_blocked) or (not is_malicious and not is_blocked)
        }
    
    def run_integration_test(self) -> Dict[str, Any]:
        """Run complete integration test."""
        print("="*80)
        print("INTEGRATION TEST: AdversarialInputDetector via IntelligentRouterService")
        print("="*80)
        print()
        
        # Load test samples
        print("Loading test samples...")
        bypass_samples = self.load_baseline_bypasses()
        benign_samples = self.load_benign_samples(count=100)
        
        print(f"  - Malicious samples: {len(bypass_samples)}")
        print(f"  - Benign samples: {len(benign_samples)}")
        print()
        
        # Create router service
        print("Creating router service...")
        router_service = self.create_router_service()
        print("  ✅ Router service created")
        print()
        
        # Test malicious samples
        print("Testing malicious samples...")
        malicious_results = []
        malicious_times = []
        
        for i, sample in enumerate(bypass_samples, 1):
            result = self.test_detection(router_service, sample, is_malicious=True)
            malicious_results.append(result)
            malicious_times.append(result["processing_time_ms"])
            
            if i <= 5 or not result["correct"]:
                status = "✅ DETECTED" if result["correct"] else "❌ MISSED"
                print(f"  {status}: {result['text']}")
                print(f"    Score: {result['adversarial_score']:.3f} | "
                      f"Blocked: {result['is_blocked']} | "
                      f"Time: {result['processing_time_ms']:.2f}ms")
        
        print()
        
        # Test benign samples
        print("Testing benign samples...")
        benign_results = []
        benign_times = []
        false_positives = []
        
        for i, sample in enumerate(benign_samples, 1):
            result = self.test_detection(router_service, sample, is_malicious=False)
            benign_results.append(result)
            benign_times.append(result["processing_time_ms"])
            
            if not result["correct"]:  # False positive
                false_positives.append(result)
                print(f"  ⚠️  FALSE POSITIVE: {result['text']}")
                print(f"    Score: {result['adversarial_score']:.3f} | "
                      f"Blocked: {result['is_blocked']}")
        
        if not false_positives:
            print("  ✅ No false positives detected")
        
        print()
        
        # Calculate metrics
        detected_malicious = sum(1 for r in malicious_results if r["correct"])
        detection_rate = (detected_malicious / len(malicious_results)) * 100 if malicious_results else 0
        false_positive_rate = (len(false_positives) / len(benign_results)) * 100 if benign_results else 0
        
        avg_malicious_time = sum(malicious_times) / len(malicious_times) if malicious_times else 0
        avg_benign_time = sum(benign_times) / len(benign_times) if benign_times else 0
        max_time = max(malicious_times + benign_times) if (malicious_times or benign_times) else 0
        
        # Summary
        summary = {
            "total_malicious": len(malicious_results),
            "detected_malicious": detected_malicious,
            "detection_rate": detection_rate,
            "total_benign": len(benign_results),
            "false_positives": len(false_positives),
            "false_positive_rate": false_positive_rate,
            "performance": {
                "avg_malicious_time_ms": avg_malicious_time,
                "avg_benign_time_ms": avg_benign_time,
                "max_time_ms": max_time,
                "budget_ms": 50,
                "within_budget": max_time <= 50
            }
        }
        
        # Print summary
        print("="*80)
        print("TEST SUMMARY")
        print("="*80)
        print(f"Malicious Samples:")
        print(f"  Total: {summary['total_malicious']}")
        print(f"  Detected: {summary['detected_malicious']} ({summary['detection_rate']:.1f}%)")
        print(f"  Missed: {summary['total_malicious'] - summary['detected_malicious']}")
        print()
        print(f"Benign Samples:")
        print(f"  Total: {summary['total_benign']}")
        print(f"  False Positives: {summary['false_positives']} ({summary['false_positive_rate']:.1f}%)")
        print()
        print(f"Performance:")
        print(f"  Avg malicious time: {avg_malicious_time:.2f}ms")
        print(f"  Avg benign time: {avg_benign_time:.2f}ms")
        print(f"  Max time: {max_time:.2f}ms")
        print(f"  Budget: 50ms")
        print(f"  Within budget: {'✅ YES' if summary['performance']['within_budget'] else '❌ NO'}")
        print()
        
        # Success criteria
        success_criteria = {
            "detection_rate_ok": detection_rate >= 95.0,
            "false_positive_rate_ok": false_positive_rate <= 5.0,
            "performance_ok": max_time <= 50.0
        }
        
        all_passed = all(success_criteria.values())
        
        print("Success Criteria:")
        print(f"  Detection Rate >= 95%: {'✅' if success_criteria['detection_rate_ok'] else '❌'} ({detection_rate:.1f}%)")
        print(f"  False Positive Rate <= 5%: {'✅' if success_criteria['false_positive_rate_ok'] else '❌'} ({false_positive_rate:.1f}%)")
        print(f"  Performance <= 50ms: {'✅' if success_criteria['performance_ok'] else '❌'} ({max_time:.2f}ms)")
        print()
        print(f"Overall Result: {'✅ PASS' if all_passed else '❌ FAIL'}")
        print("="*80)
        
        self.results = {
            "summary": summary,
            "success_criteria": success_criteria,
            "all_passed": all_passed,
            "malicious_results": malicious_results[:10],  # First 10 for detail
            "false_positives": false_positives
        }
        
        return self.results


def main():
    """Run integration test."""
    tester = RouterIntegrationTest()
    results = tester.run_integration_test()
    
    # Save results
    output_file = project_root / "test_results" / "adversarial" / "integration_test_results.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nResults saved to: {output_file}")
    
    return 0 if results["all_passed"] else 1


if __name__ == "__main__":
    exit(main())

