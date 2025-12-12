#!/usr/bin/env python3
"""
Full Test Suite Runner - Orchestrator Service
==============================================

Führt alle Test-Suites automatisch durch:
- Load Tests
- Resilience Tests
- Security Tests
- Monitoring Tests

Usage:
    python -m tests.run_full_test_suite
    python -m tests.run_full_test_suite --skip-load
"""

import asyncio
import subprocess
import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@dataclass
class TestSuiteResult:
    """Ergebnis einer Test-Suite."""
    suite_name: str
    passed: bool
    duration: float
    output: str
    error: Optional[str] = None


class FullTestSuiteRunner:
    """Runner für alle Test-Suites."""

    def __init__(self, base_url: str = "http://localhost:8001", output_dir: str = "test_results"):
        self.base_url = base_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[TestSuiteResult] = []

    async def run_load_test(self, concurrent: int = 100, duration: int = 30) -> TestSuiteResult:
        """Führt Load-Test aus."""
        print("\n" + "=" * 80)
        print("🚀 Running Load Test...")
        print("=" * 80)
        
        start_time = asyncio.get_event_loop().time()
        
        try:
            from tests.load_test import LoadTester
            
            tester = LoadTester(base_url=self.base_url)
            result = await tester.test_concurrent_requests(
                concurrent=concurrent,
                duration=duration
            )
            
            # Save result
            output_file = self.output_dir / f"load_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump(asdict(result), f, indent=2)
            
            duration_elapsed = asyncio.get_event_loop().time() - start_time
            
            # Check success criteria
            passed = (
                result.requests_per_second >= 100 and
                result.p95_latency_ms < 200 and
                result.error_rate < 0.001
            )
            
            return TestSuiteResult(
                suite_name="load_test",
                passed=passed,
                duration=duration_elapsed,
                output=f"Results saved to {output_file}"
            )
        except Exception as e:
            duration_elapsed = asyncio.get_event_loop().time() - start_time
            return TestSuiteResult(
                suite_name="load_test",
                passed=False,
                duration=duration_elapsed,
                output="",
                error=str(e)
            )

    async def run_resilience_test(self) -> TestSuiteResult:
        """Führt Resilienz-Test aus."""
        print("\n" + "=" * 80)
        print("🛡️  Running Resilience Test...")
        print("=" * 80)
        
        start_time = asyncio.get_event_loop().time()
        
        try:
            from tests.resilience_test import ResilienceTester
            
            async with ResilienceTester(base_url=self.base_url) as tester:
                results = await tester.run_all_tests()
            
            # Save results
            output_file = self.output_dir / f"resilience_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump([asdict(r) for r in results], f, indent=2)
            
            duration_elapsed = asyncio.get_event_loop().time() - start_time
            
            # Check if all tests passed
            passed = all(r.passed for r in results)
            
            return TestSuiteResult(
                suite_name="resilience_test",
                passed=passed,
                duration=duration_elapsed,
                output=f"Results saved to {output_file}"
            )
        except Exception as e:
            duration_elapsed = asyncio.get_event_loop().time() - start_time
            return TestSuiteResult(
                suite_name="resilience_test",
                passed=False,
                duration=duration_elapsed,
                output="",
                error=str(e)
            )

    async def run_security_test(self) -> TestSuiteResult:
        """Führt Security-Test aus."""
        print("\n" + "=" * 80)
        print("🔒 Running Security Test...")
        print("=" * 80)
        
        start_time = asyncio.get_event_loop().time()
        
        try:
            from tests.security_test import SecurityTester
            
            tester = SecurityTester(base_url=self.base_url)
            results = await tester.test_input_validation()
            
            # Save results
            output_file = self.output_dir / f"security_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump([asdict(r) for r in results], f, indent=2)
            
            duration_elapsed = asyncio.get_event_loop().time() - start_time
            
            # Check if all tests passed
            passed = all(r.passed for r in results)
            
            return TestSuiteResult(
                suite_name="security_test",
                passed=passed,
                duration=duration_elapsed,
                output=f"Results saved to {output_file}"
            )
        except Exception as e:
            duration_elapsed = asyncio.get_event_loop().time() - start_time
            return TestSuiteResult(
                suite_name="security_test",
                passed=False,
                duration=duration_elapsed,
                output="",
                error=str(e)
            )

    async def run_monitoring_test(self) -> TestSuiteResult:
        """Führt Monitoring-Test aus (Python-Version für Windows-Kompatibilität)."""
        print("\n" + "=" * 80)
        print("📊 Running Monitoring Test...")
        print("=" * 80)
        
        import time
        start_time = time.time()
        
        try:
            from tests.monitoring_test import MonitoringTester
            
            tester = MonitoringTester(base_url=self.base_url, output_dir=str(self.output_dir))
            await tester.run_all_tests()
            
            duration_elapsed = time.time() - start_time
            
            # Check if all tests passed
            passed = all(r.get("success", False) for r in tester.results.values())
            
            return TestSuiteResult(
                suite_name="monitoring_test",
                passed=passed,
                duration=duration_elapsed,
                output=f"Results saved to {self.output_dir}"
            )
        except Exception as e:
            duration_elapsed = time.time() - start_time
            return TestSuiteResult(
                suite_name="monitoring_test",
                passed=False,
                duration=duration_elapsed,
                output="",
                error=str(e)
            )

    async def run_all_tests(
        self,
        skip_load: bool = False,
        skip_resilience: bool = False,
        skip_security: bool = False,
        skip_monitoring: bool = False,
        load_concurrent: int = 100,
        load_duration: int = 30
    ):
        """Führt alle Tests aus."""
        print("\n" + "=" * 80)
        print("[TEST] FULL TEST SUITE - ORCHESTRATOR SERVICE")
        print("=" * 80)
        print(f"Base URL: {self.base_url}")
        print(f"Output Directory: {self.output_dir}")
        print("=" * 80)
        
        # Load Test
        if not skip_load:
            result = await self.run_load_test(
                concurrent=load_concurrent,
                duration=load_duration
            )
            self.results.append(result)
        else:
            print("\n⏭️  Skipping Load Test")

        # Resilience Test
        if not skip_resilience:
            result = await self.run_resilience_test()
            self.results.append(result)
        else:
            print("\n⏭️  Skipping Resilience Test")

        # Security Test
        if not skip_security:
            result = await self.run_security_test()
            self.results.append(result)
        else:
            print("\n⏭️  Skipping Security Test")

        # Monitoring Test
        if not skip_monitoring:
            result = await self.run_monitoring_test()
            self.results.append(result)
        else:
            print("\n⏭️  Skipping Monitoring Test")

    def print_summary(self):
        """Druckt Zusammenfassung aller Tests."""
        print("\n" + "=" * 80)
        print("📊 TEST SUITE SUMMARY")
        print("=" * 80)
        
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.passed)
        total_duration = sum(r.duration for r in self.results)
        
        print(f"\nTotal Test Suites: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {total_tests - passed_tests}")
        print(f"Total Duration: {total_duration:.2f}s")
        
        print(f"\n[INFO] Detailed Results:")
        for result in self.results:
            status = "[OK] PASSED" if result.passed else "[ERROR] FAILED"
            print(f"   {status}: {result.suite_name} ({result.duration:.2f}s)")
            if result.error:
                print(f"      Error: {result.error}")
            if result.output:
                print(f"      {result.output}")
        
        print("\n" + "=" * 80)
        
        if passed_tests == total_tests:
            print("[SUCCESS] ALL TEST SUITES PASSED!")
        else:
            print(f"[WARN] {total_tests - passed_tests} TEST SUITE(S) FAILED")
        
        print("=" * 80 + "\n")
        
        # Save summary
        summary_file = self.output_dir / f"test_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump({
                "timestamp": datetime.utcnow().isoformat(),
                "total_tests": total_tests,
                "passed": passed_tests,
                "failed": total_tests - passed_tests,
                "total_duration": total_duration,
                "results": [asdict(r) for r in self.results]
            }, f, indent=2)
        
        print(f"📄 Summary saved to: {summary_file}")


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Full Test Suite Runner")
    parser.add_argument(
        "--url",
        type=str,
        default="http://localhost:8001",
        help="Base URL of orchestrator service (default: http://localhost:8001)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="test_results",
        help="Output directory for test results (default: test_results)"
    )
    parser.add_argument(
        "--skip-load",
        action="store_true",
        help="Skip load test"
    )
    parser.add_argument(
        "--skip-resilience",
        action="store_true",
        help="Skip resilience test"
    )
    parser.add_argument(
        "--skip-security",
        action="store_true",
        help="Skip security test"
    )
    parser.add_argument(
        "--skip-monitoring",
        action="store_true",
        help="Skip monitoring test"
    )
    parser.add_argument(
        "--load-concurrent",
        type=int,
        default=100,
        help="Concurrent requests for load test (default: 100)"
    )
    parser.add_argument(
        "--load-duration",
        type=int,
        default=30,
        help="Duration for load test in seconds (default: 30)"
    )
    
    args = parser.parse_args()
    
    runner = FullTestSuiteRunner(
        base_url=args.url,
        output_dir=args.output_dir
    )
    
    await runner.run_all_tests(
        skip_load=args.skip_load,
        skip_resilience=args.skip_resilience,
        skip_security=args.skip_security,
        skip_monitoring=args.skip_monitoring,
        load_concurrent=args.load_concurrent,
        load_duration=args.load_duration
    )
    
    runner.print_summary()


if __name__ == "__main__":
    asyncio.run(main())

